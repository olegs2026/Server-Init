#!/usr/bin/env bash
#
# 01-init.sh — первичная подготовка сервера Ubuntu (запускать после 00-init.sh)
#   1) обновление системы
#   2) установка часто используемых инструментов администрирования
#   3) автоматические security-обновления (unattended-upgrades)
#   4) fail2ban: защита SSH, вечный бан, 3 промаха за сутки,
#      whitelist localhost + IP самого сервера (определяются автоматически)
#
# Скрипт идемпотентен: повторный запуск безопасен. Конфиги перегенерируются,
# git-репозиторий /etc и таймеры не дублируются, а твои доверенные IP в
# /etc/fail2ban/ignoreip.local при этом сохраняются.
#
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a            # не задавать вопросы про рестарт сервисов

### ---------- проверки ----------
if [[ $EUID -ne 0 ]]; then
  echo "Запусти от root:  sudo $0" >&2
  exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "Это не Debian/Ubuntu (нет apt-get). Прерываю." >&2
  exit 1
fi

LOG="/var/log/fresh-start-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
echo "==> Лог пишется в $LOG"

# --- ловушка ошибок: при любом необработанном сбое печатаем, где и что упало ---
on_error() {
  local rc=$? line=$1
  echo >&2
  echo "############################################################" >&2
  echo "!! ОШИБКА (код $rc) на строке $line" >&2
  echo "!! Команда: $BASH_COMMAND" >&2
  echo "!! Скрипт прерван. Подробности в логе: $LOG" >&2
  echo "!! Скрипт идемпотентен — после исправления можно запустить заново." >&2
  echo "############################################################" >&2
  exit "$rc"
}
trap 'on_error $LINENO' ERR

# --- защита от обрыва SSH-сессии: настоятельно советуем tmux/screen ---
# Если сессия отвалится (частое дело на мобильных клиентах вроде Termius),
# скрипт, запущенный напрямую, умрёт на полпути. Внутри tmux он переживёт обрыв.
if [[ -t 0 && -z "${TMUX:-}" && -z "${STY:-}" ]]; then
  echo
  echo "СОВЕТ: ты не внутри tmux/screen. Длинный прогон + обрыв SSH = скрипт прервётся."
  echo "Надёжнее так (tmux переживёт обрыв связи):"
  echo "    command -v tmux >/dev/null || apt-get install -y tmux"
  echo "    tmux new -s setup        # внутри:  sudo $0"
  echo "    # отвалилось? переподключись по SSH и:  tmux attach -t setup"
  echo
  read -r -p "Продолжить ПРЯМО СЕЙЧАС без tmux? (yes/no): " _ans
  [[ "$_ans" == "yes" ]] || { echo "Ок. Перезапусти под tmux."; exit 0; }
fi

### ---------- 1. обновление системы ----------
echo
echo "==> Обновляю систему (update + full-upgrade + autoremove)"
apt-get update -y
apt-get -y full-upgrade
apt-get -y --purge autoremove
apt-get -y autoclean

# Подавляем git-подсказку про имя ветки по умолчанию (чтобы etckeeper init
# не сыпал "hint: Using 'master'..."). Пишем системный gitconfig напрямую —
# это работает ещё до установки git и не зависит от порядка.
if ! grep -qs 'defaultBranch' /etc/gitconfig 2>/dev/null; then
  printf '[init]\n\tdefaultBranch = main\n' >> /etc/gitconfig
fi

### ---------- 2. установка инструментов ----------
# Базовый набор: то, что просил + то, что обычно нужно для администрирования.
PKGS=(
  # запрошенное
  iperf3 mc btop htop curl
  # сеть и диагностика
  iproute2 net-tools dnsutils mtr-tiny nmap tcpdump traceroute
  iftop nethogs whois socat wget
  # мониторинг / процессы / диск
  sysstat iotop ncdu lsof
  # работа с данными / файлами
  jq tree rsync unzip zip p7zip-full
  # сессии и редакторы
  tmux screen vim nano
  # система / репозитории / прочее
  git bash-completion ca-certificates gnupg
  software-properties-common apt-transport-https
  needrestart unattended-upgrades ufw fail2ban
  # бэкап конфигов и аудит безопасности
  etckeeper lynis debsums
)

# Необязательное (раскомментируй при необходимости):
#   smartmontools  # здоровье физических дисков (для bare-metal)
#   glances        # удобный, но тянет много python-зависимостей
#   auditd         # аудит системных вызовов

echo
echo "==> Устанавливаю инструменты"
install_pkgs() {                     # надёжная установка по одному пакету
  local p failed=()
  for p in "$@"; do
    if apt-get install -y "$p" >/dev/null 2>&1; then
      echo "    + $p"
    else
      echo "    ! не удалось установить: $p"
      failed+=("$p")
    fi
  done
  ((${#failed[@]})) && echo "    Пропущено: ${failed[*]}" || true
}

if ! apt-get install -y "${PKGS[@]}"; then
  echo "    Пакетный режим не прошёл — ставлю по одному..."
  install_pkgs "${PKGS[@]}"
fi
# ss входит в iproute2, htop/btop/curl уже в списке — отдельно не нужно

### ---------- 3. автоматические security-обновления ----------
echo
echo "==> Включаю автоматические обновления безопасности"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true

### ---------- 4. fail2ban ----------
echo
echo "==> Настраиваю fail2ban"

# --- определяем порт(ы) SSH ---
detect_ssh_port() {
  local p=""
  p=$(sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null \
        | awk '/^port / {print $2}' | paste -sd, -) || true
  if [[ -z "$p" ]]; then
    p=$(grep -rhiE '^[[:space:]]*Port[[:space:]]+' \
          /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null \
          | awk '{print $2}' | sort -un | paste -sd, -) || true
  fi
  [[ -z "$p" ]] && p=22
  echo "$p"
}
SSH_PORT=$(detect_ssh_port) || true
[[ -z "$SSH_PORT" ]] && SSH_PORT=22

# --- собственные IP сервера (для whitelist) ---
SERVER_IPS=$(ip -o addr show scope global 2>/dev/null \
              | awk '{print $4}' | cut -d/ -f1 | sort -u | tr '\n' ' ') || true

# --- какой фаервол в системе -> правильный banaction ---
# На разных бэкендах fail2ban должен блокировать по-разному, иначе бан
# "применится", но реально трафик не зарежет.
detect_banaction() {
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    FW="firewalld"
    BANACTION="firewallcmd-ipset"
    BANACTION_ALL="firewallcmd-ipset"
  elif command -v nft >/dev/null 2>&1; then
    BANACTION="nftables-multiport"
    BANACTION_ALL="nftables-allports"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
      FW="ufw (active) поверх nftables"
    else
      FW="nftables"
    fi
  elif command -v iptables >/dev/null 2>&1; then
    BANACTION="iptables-multiport"
    BANACTION_ALL="iptables-allports"
    FW="iptables"
  else
    FW="не определён"
    BANACTION="iptables-multiport"        # безопасный дефолт
    BANACTION_ALL="iptables-allports"
  fi
}
detect_banaction

# --- список доверенных IP, который скрипт НЕ перезатирает (идемпотентно) ---
# Сюда админ вписывает свои адреса; они подмешиваются в ignoreip при каждом прогоне.
if [[ ! -f /etc/fail2ban/ignoreip.local ]]; then
  cat > /etc/fail2ban/ignoreip.local <<'EOF'
# По одному IP или CIDR в строке. Это ТВОИ доверенные адреса
# (домашний/рабочий IP), чтобы fail2ban тебя не забанил.
# Файл не перезаписывается скриптом — правь смело.
# Пример:
# 203.0.113.45
# 198.51.100.0/24
EOF
fi
EXTRA_IPS=$(grep -vhE '^[[:space:]]*#|^[[:space:]]*$' /etc/fail2ban/ignoreip.local 2>/dev/null | tr '\n' ' ') || true

echo "    Порт SSH:        $SSH_PORT"
echo "    IP сервера:      ${SERVER_IPS:-<не найдены>}"
echo "    Фаервол:         $FW  ->  banaction=$BANACTION"
[[ -n "${EXTRA_IPS// }" ]] && echo "    Доверенные IP:   $EXTRA_IPS"

# --- jail.local: вечный бан, 3 промаха за сутки ---
cat > /etc/fail2ban/jail.local <<EOF
# Управляется fresh-start.sh — правь здесь, не в jail.conf.
# Свои доверенные IP добавляй в /etc/fail2ban/ignoreip.local (не тут).

[DEFAULT]
# Читаем журнал systemd (в Ubuntu 24.04 /var/log/auth.log по умолчанию нет)
backend  = systemd

# Бан навсегда
bantime  = -1
# Окно наблюдения — 1 сутки (86400 c)
findtime = 86400
# 3 неудачные попытки = бан
maxretry = 3

# Способ блокировки под текущий фаервол ($FW)
banaction          = ${BANACTION}
banaction_allports = ${BANACTION_ALL}

# Whitelist: localhost + IP сервера + доверенные адреса из ignoreip.local
ignoreip = 127.0.0.1/8 ::1 ${SERVER_IPS}${EXTRA_IPS:+ }${EXTRA_IPS}

[sshd]
enabled  = true
port     = ${SSH_PORT}
maxretry = 3
EOF

# --- fail2ban.local: чтобы вечные баны переживали перезапуск ---
# (иначе запись о бане вычистится из БД через dbpurgeage по умолчанию = 1 сутки)
cat > /etc/fail2ban/fail2ban.local <<'EOF'
[Definition]
# ~20 лет в секундах — фактически "не чистить" перманентные баны
dbpurgeage = 648000000
EOF

# --- проверка конфигурации и запуск ---
echo "    Проверяю конфиг fail2ban..."
if fail2ban-client -t; then
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban
  sleep 2
  echo
  echo "==> Статус fail2ban / sshd:"
  fail2ban-client status sshd || echo "    (jail sshd ещё инициализируется — проверь позже)"
else
  echo "    ОШИБКА в конфиге fail2ban! Сервис не перезапущен, проверь /etc/fail2ban/jail.local" >&2
fi

### ---------- 5. автобэкап конфигов ----------
echo
echo "==> Настраиваю автоматический бэкап конфигов"

# 5a. etckeeper — версионирование /etc через git, автокоммиты при apt
if command -v etckeeper >/dev/null 2>&1; then
  if [[ ! -d /etc/.git ]]; then
    etckeeper init >/dev/null 2>&1 || true
    etckeeper commit "fresh-start: initial /etc snapshot" >/dev/null 2>&1 || true
    echo "    etckeeper: /etc теперь под git, коммиты при каждом apt"
  else
    etckeeper commit "fresh-start: snapshot" >/dev/null 2>&1 || true
    echo "    etckeeper: уже инициализирован, сделан свежий коммит"
  fi
fi

# 5b. ежедневный архив /etc + список пакетов, с ротацией
install -d -m 750 /var/backups/config
cat > /usr/local/sbin/config-backup.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DEST=/var/backups/config
KEEP=14
ts=$(date +%Y%m%d-%H%M%S)
mkdir -p "$DEST"
# список установленных пакетов — для быстрого восстановления сервера
apt-mark showmanual      > "$DEST/manual-packages-$ts.txt"  2>/dev/null || true
dpkg --get-selections    > "$DEST/dpkg-selections-$ts.txt"  2>/dev/null || true
# архив /etc
tar czf "$DEST/etc-$ts.tar.gz" -C / etc 2>/dev/null || true
# ротация: хранить последние $KEEP копий каждого типа
for pat in 'etc-*.tar.gz' 'manual-packages-*.txt' 'dpkg-selections-*.txt'; do
  ls -1t "$DEST"/$pat 2>/dev/null | tail -n +$((KEEP+1)) | xargs -r rm -f || true
done
EOF
chmod 750 /usr/local/sbin/config-backup.sh

cat > /etc/systemd/system/config-backup.service <<'EOF'
[Unit]
Description=Backup /etc and installed-package list

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/config-backup.sh
EOF

cat > /etc/systemd/system/config-backup.timer <<'EOF'
[Unit]
Description=Daily /etc config backup

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=900

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now config-backup.timer >/dev/null 2>&1 || true
/usr/local/sbin/config-backup.sh || true
echo "    Ежедневный бэкап -> /var/backups/config (хранится 14 последних копий)"

### ---------- 6. аудит безопасности ----------
echo
echo "==> Запускаю аудит безопасности (lynis)"

LYNIS_BIN=$(command -v lynis || true)
if [[ -n "$LYNIS_BIN" ]]; then
  echo "    Идёт аудит (1-3 минуты). Вывод НЕ глушу специально — поток данных"
  echo "    не даёт SSH-сессии оборваться по таймауту. Не закрывай окно."
  echo "    --------------------------------------------------------------"
  # --quick: без пауз "нажмите ENTER"; timeout: страховка от зависания;
  # вывод идёт в терминал и в лог (через общий tee), что и держит сессию живой.
  timeout 900 "$LYNIS_BIN" audit system --no-colors --quick 2>&1 || true
  echo "    --------------------------------------------------------------"
  HINDEX=$(awk -F= '/^hardening_index=/{print $2}' /var/log/lynis-report.dat 2>/dev/null | tail -1) || true
  echo "    Отчёт: /var/log/lynis.log  и  /var/log/lynis-report.dat"
  [[ -n "${HINDEX:-}" ]] && echo "    Hardening index: $HINDEX / 100"
  echo "    Замечания и предложения:  grep -E '^(warning|suggestion)' /var/log/lynis-report.dat"

  # еженедельный автопрогон (под systemd tty нет — паузы и так не будет, но --quick для единообразия)
  cat > /etc/systemd/system/lynis-audit.service <<EOF
[Unit]
Description=Weekly Lynis security audit

[Service]
Type=oneshot
ExecStart=${LYNIS_BIN} audit system --quiet --no-colors --quick
EOF

  cat > /etc/systemd/system/lynis-audit.timer <<'EOF'
[Unit]
Description=Run Lynis audit weekly

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now lynis-audit.timer >/dev/null 2>&1 || true
  echo "    Включён еженедельный автоаудит (systemd timer)"
else
  echo "    lynis не установился — пропускаю аудит"
fi

# проверка целостности файлов установленных пакетов
if command -v debsums >/dev/null 2>&1; then
  echo "    Проверка целостности пакетов (debsums)..."
  CHANGED=$(debsums -s 2>&1 || true)
  if [[ -n "$CHANGED" ]]; then
    echo "    ВНИМАНИЕ, изменённые/повреждённые файлы пакетов:"
    echo "$CHANGED" | sed 's/^/      /'
  else
    echo "    debsums: расхождений не найдено"
  fi
fi

### ---------- 7. сетевые параметры: BBR + форвардинг ----------
echo
echo "==> Включаю TCP BBR и IP-форвардинг (sysctl)"

# BBR требует модуль tcp_bbr (на ядре 24.04 обычно уже доступен)
modprobe tcp_bbr 2>/dev/null || true
echo tcp_bbr > /etc/modules-load.d/bbr.conf   # автозагрузка после ребута

cat > /etc/sysctl.d/99-fresh-start.conf <<'EOF'
# Управляется fresh-start.sh

# --- TCP BBR: лучше throughput/латентность на загруженных и дальних каналах ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- IP forwarding: маршрутизация / VPN / NAT / контейнеры ---
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF

sysctl --system >/dev/null 2>&1 || true

# проверяем, что применилось
CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')
QD=$(sysctl -n net.core.default_qdisc        2>/dev/null || echo '?')
FWD=$(sysctl -n net.ipv4.ip_forward          2>/dev/null || echo '?')
echo "    tcp_congestion_control = $CC   (ожидается bbr)"
echo "    default_qdisc          = $QD   (ожидается fq)"
echo "    ip_forward             = $FWD   (ожидается 1)"
if [[ "$CC" != "bbr" ]]; then
  echo "    ВНИМАНИЕ: BBR не активировался. Проверь:  modprobe tcp_bbr && lsmod | grep bbr"
fi

### ---------- итог ----------
echo
echo "############################################################"
echo "==> Готово."
echo
echo "Установлено инструментов: см. список выше."
echo "fail2ban: вечный бан, 3 промаха за 24ч, защита SSH (порт $SSH_PORT), banaction=$BANACTION ($FW)."
echo "В whitelist уже: 127.0.0.1/8 ::1 ${SERVER_IPS}${EXTRA_IPS:+ }${EXTRA_IPS}"
echo
echo "Бэкап конфигов: etckeeper (git в /etc) + ежедневный архив в /var/backups/config."
echo "Аудит: lynis (разово сделан + еженедельно по таймеру), debsums проверил целостность."
echo "Сеть: TCP BBR + IP-форвардинг включены (/etc/sysctl.d/99-fresh-start.conf)."
echo "  Посмотреть таймеры:   systemctl list-timers"
echo "  Рекомендации lynis:   grep -E '^(warning|suggestion)' /var/log/lynis-report.dat"
echo "  История изменений /etc: cd /etc && git log"
echo
echo "ВАЖНО — добавь свой IP в whitelist, чтобы не заблокировать себя."
echo "Узнай свой внешний IP (с домашней машины):  curl ifconfig.me"
echo "Впиши его (постоянно и безопасно для повторных запусков скрипта):"
echo "    echo '<ТВОЙ_IP>' >> /etc/fail2ban/ignoreip.local"
echo "    systemctl reload fail2ban"
echo "Срочно (до перезагрузки fail2ban):"
echo "    fail2ban-client set sshd addignoreip <ТВОЙ_IP>"
echo
echo "Разбанить адрес при необходимости:"
echo "    fail2ban-client set sshd unbanip <IP>"
echo "Посмотреть забаненные:"
echo "    fail2ban-client status sshd"
echo "############################################################"
echo
echo "==> ПРОВЕРКА СОСТОЯНИЯ (скопируй и прогони, чтобы убедиться, что всё ок):"
echo
echo "  # fail2ban работает и jail sshd поднят:"
echo "  systemctl is-active fail2ban  &&  fail2ban-client status sshd"
echo
echo "  # действующие правила jail (порт, bantime, ignoreip, banaction):"
echo "  fail2ban-client get sshd banip ; fail2ban-client status"
echo
echo "  # автообновления и таймеры бэкапа/аудита включены:"
echo "  systemctl is-enabled unattended-upgrades config-backup.timer lynis-audit.timer"
echo "  systemctl list-timers --all | grep -E 'config-backup|lynis'"
echo
echo "  # BBR и форвардинг реально применились:"
echo "  sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc net.ipv4.ip_forward"
echo
echo "  # /etc под версионным контролем (должен быть git-лог):"
echo "  git -C /etc log --oneline -5"
echo
echo "  # последний архив конфигов на месте:"
echo "  ls -lt /var/backups/config | head"
echo
echo "  # индекс защищённости от lynis:"
echo "  grep -i hardening /var/log/lynis-report.dat   # индекс защищённости"
echo "############################################################"

if [[ -f /var/run/reboot-required ]]; then
  echo
  echo "ВНИМАНИЕ: системе требуется перезагрузка (обновилось ядро/библиотеки)."
  echo "Перезагрузи когда будет удобно:  reboot"
fi

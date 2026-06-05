#!/usr/bin/env bash
#
# 00-init.sh — базовый SSH hardening для Ubuntu (22.04/24.04).
#   1) root — только по ключу (PermitRootLogin prohibit-password)
#   2) порт SSH -> запрашивается интерактивно (Enter = 44422)
#   3) порт 22 убирается из конфигурации sshd (+ опционально из фаервола)
#   4) запрет логина root по паролю
#   5) резервная учётка с правами sudo — имя запрашивается (Enter = root777)
#   6) публичный ключ запрашивается интерактивно (Terminus -> Export public key)
#
# Скрипт НЕ рвёт текущую сессию и НЕ закрывает 22, пока ты сам не подтвердишь,
# что новое подключение на новом порту работает.
#
# Идемпотентность: повторный запуск безопасен. Уже существующий пользователь,
# уже прописанный ключ и уже заданный пароль не трогаются (можно пропустить),
# конфиг sshd перегенерируется, фаервол определяется автоматически.
#
set -Eeuo pipefail

# --- ловушка ошибок: при любом необработанном сбое печатаем, где и что упало ---
on_error() {
  local rc=$? line=$1
  echo >&2
  echo "############################################################" >&2
  echo "!! ОШИБКА (код $rc) на строке $line" >&2
  echo "!! Команда: $BASH_COMMAND" >&2
  echo "!! Скрипт прерван. Текущая SSH-сессия НЕ закрыта — не паникуй." >&2
  echo "!! Бэкап конфигов лежит в: ${BACKUP_DIR:-/root/ssh-hardening-backup-*}" >&2
  echo "############################################################" >&2
  exit "$rc"
}
trap 'on_error $LINENO' ERR

### ---------- параметры ----------
ADMIN_GROUP="sudo"                       # на Ubuntu админская группа = sudo
HARDENING_FILE="/etc/ssh/sshd_config.d/00-hardening.conf"
BACKUP_DIR="/root/ssh-hardening-backup-$(date +%Y%m%d-%H%M%S)"
DEFAULT_PORT=44422
DEFAULT_USER="root777"

### ---------- проверки ----------
if [[ $EUID -ne 0 ]]; then
  echo "Запусти от root:  sudo $0" >&2
  exit 1
fi

### ---------- интерактивный выбор порта и резервной учётки ----------
echo "==> Параметры (просто Enter — взять значение по умолчанию)"
read -r -p "    Новый порт SSH [${DEFAULT_PORT}]: " NEW_PORT || true
NEW_PORT="${NEW_PORT:-$DEFAULT_PORT}"
if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || (( NEW_PORT < 1 || NEW_PORT > 65535 )); then
  echo "    Некорректный порт: '$NEW_PORT'. Прерываю." >&2; exit 1
fi
if (( NEW_PORT == 22 )); then
  echo "    Порт 22 — это то, от чего уходим. Выбери другой." >&2; exit 1
fi

read -r -p "    Имя резервной sudo-учётки [${DEFAULT_USER}]: " BACKUP_USER || true
BACKUP_USER="${BACKUP_USER:-$DEFAULT_USER}"
if ! [[ "$BACKUP_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  echo "    Некорректное имя пользователя: '$BACKUP_USER'. Прерываю." >&2; exit 1
fi
echo "    -> порт: $NEW_PORT,  резервная учётка: $BACKUP_USER"

echo "==> Бэкап текущих конфигов в $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
cp -a /etc/ssh/sshd_config        "$BACKUP_DIR/"        2>/dev/null || true
cp -a /etc/ssh/sshd_config.d      "$BACKUP_DIR/"        2>/dev/null || true

### ---------- проверка порта (п.2) ----------
echo "==> Проверяю порт $NEW_PORT"
CURRENT_PORTS=$(grep -rhiE '^[[:space:]]*Port[[:space:]]+' \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null \
  | awk '{print $2}' | sort -u || true)

if [[ -n "$CURRENT_PORTS" ]] && echo "$CURRENT_PORTS" | grep -qvE '^22$'; then
  echo "    ВНИМАНИЕ: в конфиге уже задан нестандартный порт: $CURRENT_PORTS"
  read -r -p "    Всё равно выставить $NEW_PORT? (yes/no): " ans
  [[ "$ans" == "yes" ]] || { echo "Отмена."; exit 1; }
fi

if ss -tlnH "( sport = :$NEW_PORT )" 2>/dev/null | grep -q .; then
  echo "    ВНИМАНИЕ: порт $NEW_PORT уже кем-то слушается!"
  read -r -p "    Продолжить? (yes/no): " ans
  [[ "$ans" == "yes" ]] || { echo "Отмена."; exit 1; }
fi

### ---------- публичный ключ (п.6) ----------
echo
echo "==> Публичный SSH-ключ"
EXISTING_KEYS=no
if [[ -s /root/.ssh/authorized_keys ]] || { id "$BACKUP_USER" &>/dev/null && [[ -s "$(getent passwd "$BACKUP_USER" | cut -d: -f6)/.ssh/authorized_keys" ]]; }; then
  EXISTING_KEYS=yes
  echo "    Ключи уже прописаны. Нажми Enter, чтобы пропустить добавление,"
  echo "    либо вставь ещё один публичный ключ для добавления."
else
  echo "    Terminus: Keychain -> New Key (Ed25519) -> Generate -> Export public key."
  echo "    Вставь ПУБЛИЧНЫЙ ключ одной строкой (ssh-ed25519 ... или ssh-rsa ...):"
fi
read -r PUBKEY

if [[ -z "${PUBKEY// }" ]]; then
  if [[ "$EXISTING_KEYS" == "yes" ]]; then
    echo "    Пропускаю добавление ключа (уже есть)."
    PUBKEY=""
  else
    echo "Ключ не введён, а существующих нет — без ключа продолжать опасно. Прерываю." >&2
    exit 1
  fi
else
  TMPK=$(mktemp)
  printf '%s\n' "$PUBKEY" > "$TMPK"
  if ! ssh-keygen -l -f "$TMPK" >/dev/null 2>&1; then
    rm -f "$TMPK"
    echo "Это не похоже на валидный публичный ключ. Прерываю." >&2
    exit 1
  fi
  rm -f "$TMPK"
  echo "    Ключ валиден."
fi

install_key() {            # install_key <username>
  local user="$1" home
  [[ -z "${PUBKEY// }" ]] && return 0          # нечего добавлять — пропускаем
  home=$(getent passwd "$user" | cut -d: -f6)
  install -d -m 700 -o "$user" -g "$user" "$home/.ssh"
  touch "$home/.ssh/authorized_keys"
  grep -qxF "$PUBKEY" "$home/.ssh/authorized_keys" || printf '%s\n' "$PUBKEY" >> "$home/.ssh/authorized_keys"
  chmod 600 "$home/.ssh/authorized_keys"
  chown "$user:$user" "$home/.ssh/authorized_keys"
  echo "    Ключ прописан для пользователя $user"
}

### ---------- резервная учётка rootos (п.5) ----------
echo
echo "==> Резервная учётка $BACKUP_USER (группа $ADMIN_GROUP)"
if id "$BACKUP_USER" &>/dev/null; then
  echo "    Пользователь уже есть — создание пропускаю."
else
  adduser --gecos "" --disabled-password "$BACKUP_USER"
fi
usermod -aG "$ADMIN_GROUP" "$BACKUP_USER"

# пароль ставим только если он ещё не задан (идемпотентность)
PW_STATUS=$(passwd -S "$BACKUP_USER" 2>/dev/null | awk '{print $2}') || true
if [[ "$PW_STATUS" == "P" ]]; then
  echo "    Пароль уже задан — пропускаю. (Сменить: passwd $BACKUP_USER)"
else
  echo "    Задай пароль для $BACKUP_USER:"
  for _try in 1 2 3; do
    if passwd "$BACKUP_USER"; then
      break
    fi
    echo "    Не получилось (попытка $_try из 3), попробуй ещё раз."
    [[ "$_try" == 3 ]] && echo "    Пропускаю — задай позже вручную:  passwd $BACKUP_USER"
  done
fi

### ---------- раскладка ключей ----------
install_key root
install_key "$BACKUP_USER"

### ---------- нужен ли пароль по SSH для rootos ----------
echo
echo "    Если потеряешь ключ — без пароля по SSH в систему не зайти (только консоль провайдера)."
read -r -p "==> Разрешить вход по ПАРОЛЮ по SSH ТОЛЬКО для $BACKUP_USER (резервный доступ)? (yes/no): " PWBACKUP

### ---------- конфиг sshd (п.1,3,4) ----------
echo
echo "==> Пишу $HARDENING_FILE"
cat > "$HARDENING_FILE" <<EOF
# Создано ssh-hardening.sh $(date)
Port $NEW_PORT
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF

if [[ "$PWBACKUP" == "yes" ]]; then
cat >> "$HARDENING_FILE" <<EOF

# Резервный доступ по паролю только для $BACKUP_USER
Match User $BACKUP_USER
    PasswordAuthentication yes
EOF
fi
chmod 644 "$HARDENING_FILE"

# нейтрализуем конфликтующие директивы в основном конфиге и cloud-init,
# чтобы Port 22 / разрешения пароля оттуда не мешали (наш файл 00- читается первым).
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/50-cloud-init.conf; do
  [[ -f "$f" ]] || continue
  sed -ri 's/^[[:space:]]*(Port|PermitRootLogin|PasswordAuthentication)[[:space:]].*/# & # off by hardening/I' "$f"
done

### ---------- проверка синтаксиса перед перезапуском ----------
echo "==> Проверка синтаксиса sshd -t"
if ! sshd -t; then
  echo "ОШИБКА в конфиге! Откатываю изменения." >&2
  rm -f "$HARDENING_FILE"
  cp -a "$BACKUP_DIR/sshd_config"   /etc/ssh/sshd_config   2>/dev/null || true
  rm -rf /etc/ssh/sshd_config.d
  cp -a "$BACKUP_DIR/sshd_config.d" /etc/ssh/sshd_config.d 2>/dev/null || true
  exit 1
fi

### ---------- socket-активация (важно для Ubuntu 24.04!) ----------
# В 24.04 ssh по умолчанию слушает через ssh.socket, и тогда Port из конфига игнорируется.
# Переводим на обычный сервис, чтобы Port применялся.
echo "==> Перевожу SSH с socket-активации на обычный сервис"
if systemctl list-unit-files | grep -q '^ssh.socket'; then
  systemctl disable --now ssh.socket || true
fi
systemctl enable ssh.service >/dev/null 2>&1 || systemctl enable ssh >/dev/null 2>&1 || true
systemctl restart ssh

sleep 1
if ss -tlnH | grep -qE "[:.]$NEW_PORT[[:space:]]"; then
  echo "    OK: sshd слушает порт $NEW_PORT"
else
  echo "    ВНИМАНИЕ: не вижу слушателя на $NEW_PORT. Проверь:  ss -tlnp | grep ssh"
fi

### ---------- фаервол: что используется и установлено ----------
detect_firewall() {
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    FW="firewalld"
  elif command -v ufw >/dev/null 2>&1; then
    FW="ufw"
  elif command -v nft >/dev/null 2>&1; then
    FW="nftables"
  elif command -v iptables >/dev/null 2>&1; then
    FW="iptables"
  else
    FW="none"
  fi
}
detect_firewall

fw_status() {
  case "$FW" in
    firewalld) echo "firewalld (активен)";;
    ufw)       echo "ufw ($(ufw status 2>/dev/null | awk '/^Status:/{print $2}'))";;
    nftables)  echo "nftables (без ufw/firewalld)";;
    iptables)  echo "iptables (без ufw/firewalld)";;
    none)      echo "не установлен";;
  esac
}
echo
echo "==> Фаервол в системе: $(fw_status)"

# Открываем новый порт ДО теста — иначе при уже активном фаерволе
# новая сессия на $NEW_PORT не пройдёт и ты не сможешь подтвердить доступ.
case "$FW" in
  firewalld)
    firewall-cmd --permanent --add-port="${NEW_PORT}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo "    firewalld: открыт $NEW_PORT/tcp" ;;
  ufw)
    ufw allow "${NEW_PORT}/tcp" >/dev/null 2>&1 || true
    echo "    ufw: разрешён $NEW_PORT/tcp" ;;
  nftables|iptables|none)
    echo "    ($FW: если фаервол что-то режет — открой $NEW_PORT/tcp вручную перед тестом)" ;;
esac

### ---------- ТЕСТ перед закрытием 22 ----------
echo
echo "############################################################"
echo "#  НЕ ЗАКРЫВАЙ ЭТУ СЕССИЮ!"
echo "#  Открой НОВОЕ подключение в Terminus:"
echo "#     host = <твой_сервер>"
echo "#     port = $NEW_PORT"
echo "#     auth = SSH key (тот, что ты вставил)"
echo "#     user = root  (по ключу)  или  $BACKUP_USER"
echo "#  Убедись, что вход реально работает."
echo "############################################################"
read -r -p "Новая сессия на $NEW_PORT работает? Закрыть порт 22? (yes/no): " CLOSE22

if [[ "$CLOSE22" == "yes" ]]; then
  case "$FW" in
    firewalld)
      firewall-cmd --permanent --remove-port=22/tcp  >/dev/null 2>&1 || true
      firewall-cmd --permanent --remove-service=ssh   >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
      echo "    firewalld: убраны 22/tcp и сервис ssh"
      firewall-cmd --list-all || true ;;
    ufw)
      echo "    ВНИМАНИЕ: если ufw выключен, его включение закроет ВСЕ входящие,"
      echo "    кроме разрешённых. Есть web/иные сервисы — добавь их порты потом."
      read -r -p "    Продолжить с ufw? (yes/no): " a
      if [[ "$a" == "yes" ]]; then
        ufw allow "${NEW_PORT}/tcp" >/dev/null 2>&1 || true
        ufw delete allow 22/tcp  2>/dev/null || true
        ufw delete allow 22      2>/dev/null || true
        ufw delete allow OpenSSH 2>/dev/null || true
        ufw deny 22/tcp >/dev/null 2>&1 || true
        yes | ufw enable >/dev/null 2>&1 || true
        ufw status verbose
      fi ;;
    nftables|iptables|none)
      echo "    Активного ufw/firewalld нет (текущий: $FW)."
      echo "    sshd уже не слушает порт 22 — на уровне приложения он закрыт."
      read -r -p "    Поставить ufw и закрыть 22 через него? (yes/no): " a
      if [[ "$a" == "yes" ]]; then
        command -v ufw >/dev/null 2>&1 || { apt-get update -y && apt-get install -y ufw; }
        FW="ufw"
        ufw allow "${NEW_PORT}/tcp" >/dev/null 2>&1 || true
        ufw deny 22/tcp >/dev/null 2>&1 || true
        yes | ufw enable >/dev/null 2>&1 || true
        ufw status verbose
      else
        echo "    Ок — при необходимости правь $FW вручную."
      fi ;;
  esac
else
  echo "Фаервол не трогаю. На уровне sshd порт 22 уже не слушается (что и требовалось)."
fi

echo
PW_NOTE="нет (вход по ключу)"
[[ "$PWBACKUP" == "yes" ]] && PW_NOTE="да (резервный вход по SSH)"
SRV_IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1) || true
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                  00-init: SSH HARDENING — ГОТОВО             ║"
echo "╚════════════════════════════════════════════════════════════╝"
printf "  %-24s %s\n" "Новый порт SSH:"      "$NEW_PORT"
printf "  %-24s %s\n" "Вход root:"           "только по ключу, пароль запрещён"
printf "  %-24s %s\n" "Резервная учётка:"    "$BACKUP_USER (группа $ADMIN_GROUP)"
printf "  %-24s %s\n" "Пароль у $BACKUP_USER:"  "$PW_NOTE"
printf "  %-24s %s\n" "Фаервол:"             "$(fw_status)"
printf "  %-24s %s\n" "Бэкап конфигов:"      "$BACKUP_DIR"
echo "  ────────────────────────────────────────────────────────────"
echo "  Подключение в Terminus:"
printf "    host=%s  port=%s  user=root|%s  auth=SSH key\n" "${SRV_IP:-<ip_сервера>}" "$NEW_PORT" "$BACKUP_USER"
echo "  Проверь НОВУЮ сессию на порту $NEW_PORT, НЕ закрывая текущую!"
echo "╚════════════════════════════════════════════════════════════╝"

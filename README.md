#!/usr/bin/env bash
#
# 02-init.sh — доп. SSH-хардинг по рекомендациям lynis (SSH-7408). Запускать после 00/01.
#   Применяет: MaxAuthTries=3, MaxSessions=2, X11Forwarding=no, Compression=no,
#              LogLevel=VERBOSE, TCPKeepAlive=no, ClientAliveInterval/CountMax.
#   НЕ трогает: AllowTcpForwarding / AllowAgentForwarding — твой проброс портов
#              в Terminus продолжит работать (по твоему выбору).
#
# Идемпотентно. Конфиг проверяется через sshd -t, ssh перезагружается через
# reload (НЕ restart) — текущая сессия не рвётся.
#
set -Eeuo pipefail

on_error() {
  local rc=$? line=$1
  echo >&2
  echo "############################################################" >&2
  echo "!! ОШИБКА (код $rc) на строке $line" >&2
  echo "!! Команда: $BASH_COMMAND" >&2
  echo "!! Текущая SSH-сессия НЕ закрыта. Бэкап: ${BACKUP_DIR:-?}" >&2
  echo "############################################################" >&2
  exit "$rc"
}
trap 'on_error $LINENO' ERR

if [[ $EUID -ne 0 ]]; then
  echo "Запусти от root:  sudo $0" >&2
  exit 1
fi

# Имя файла специально сортируется РАНЬШE 00-hardening.conf:
# его Match-блок (User rootos) не должен "перехватывать" наши глобальные настройки.
EXTRA_FILE="/etc/ssh/sshd_config.d/00-extra.conf"
BACKUP_DIR="/root/ssh-hardening-backup-$(date +%Y%m%d-%H%M%S)"

echo "==> Бэкап конфигов SSH в $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
cp -a /etc/ssh/sshd_config   "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/ssh/sshd_config.d "$BACKUP_DIR/" 2>/dev/null || true

echo "==> Пишу $EXTRA_FILE"
cat > "$EXTRA_FILE" <<'EOF'
# Доп. хардинг SSH по рекомендациям lynis (SSH-7408).
# Туннели/проброс портов НЕ трогаем: AllowTcpForwarding и AllowAgentForwarding
# намеренно НЕ заданы здесь (остаются как есть).
# Файл назван так, чтобы читаться раньше 00-hardening.conf (до его Match-блока).

MaxAuthTries 3
MaxSessions 2
X11Forwarding no
Compression no
LogLevel VERBOSE
TCPKeepAlive no
ClientAliveInterval 120
ClientAliveCountMax 2

# (по желанию) ограничить КТО заходит по SSH — снижает риск перебора,
# но при опечатке можно заблокировать себе вход. Раскомментируй ОСОЗНАННО,
# вписав всех нужных пользователей:
# AllowUsers root rootos
EOF
chmod 644 "$EXTRA_FILE"

echo "==> Проверка синтаксиса sshd -t"
if ! sshd -t; then
  echo "ОШИБКА в конфиге — откатываю $EXTRA_FILE" >&2
  rm -f "$EXTRA_FILE"
  sshd -t && echo "Откат успешен, конфиг снова валиден." >&2
  exit 1
fi

echo "==> Перечитываю конфиг SSH (reload — текущая сессия не рвётся)"
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl restart ssh

echo
echo "############################################################"
echo "==> Готово. Применён SSH-хардинг:"
echo "    MaxAuthTries=3, MaxSessions=2, X11Forwarding=no, Compression=no,"
echo "    LogLevel=VERBOSE, TCPKeepAlive=no, ClientAliveInterval=120, CountMax=2"
echo "    Туннели (TCP/Agent forwarding) НЕ тронуты."
echo
echo "Проверка, что новые значения подхватились:"
echo "    sshd -T | grep -Ei 'maxauthtries|maxsessions|x11forwarding|loglevel|clientalive|compression|tcpkeepalive'"
echo
echo "Пересними оценку безопасности (часть SSH-замечаний уйдёт):"
echo "    lynis audit system --quick   # смотри 'Hardening index' в конце"
echo
echo "ВАЖНО: проверь новый вход ДО закрытия текущей сессии — открой ещё одно"
echo "подключение в Terminus и убедись, что заходит. (Конфиг валиден, но привычка.)"
echo "############################################################"

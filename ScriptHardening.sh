#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 022
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C

readonly VERSION="2.0.1"
readonly STATE_DIR="/var/lib/ubuntu-hardening"
readonly LOG_DIR="/var/log/ubuntu-hardening"
readonly LOCK_FILE="/run/ubuntu-hardening.lock"
TS="$(date +%Y%m%d-%H%M%S)"; readonly TS
SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"; readonly SELF

# -------------- PASSO 1 - ESTADO GLOBAL -----
SUBCMD="apply"
DRY_RUN=0; ASSUME_YES=0; FORCE=0
ADMIN_USERS=(); SSH_PORT=""; SSH_PORT_SET=0
RESTRICT_SSH_USERS=0; ALLOW_PASSWORD_AUTH=0; ROOT_KEYS_ONLY=0
ALLOW_TCP_FWD=0; ALLOW_AGENT_FWD=0; SKIP_SSH_CRYPTO=0
EXTRA_PORTS=(); SSH_ALLOW_FROM=(); SSH_NO_RATELIMIT=0; UFW_RESET=0
F2B_IGNORE=(); F2B_IGNORE_CURRENT=0
FULL_UPGRADE=0; REMOVE_LEGACY=0
SYSCTL_EXT=0; SYSCTL_NOFWD=0; SYSCTL_NORA=0; SYSCTL_STRICT_RPF=0
NO_DEFAULT_MODULES=0; BLOCK_MODULES=(); BLOCK_USB=0; BLOCK_TB=0
SUDO_IO_LOG=0; TMOUT_SECS=0; CRON_ALLOW=0; HARDEN_SHM=0
DISABLE_SERVICES=(); MASK_SERVICES=0
AUDIT_TUNE=0; AUDIT_IMMUTABLE=0
AA_ENFORCE=(); AA_COMPLAIN=()
WITH_AIDE=0; WITH_RKH=0; RKH_UPDATE=0; WITH_LYNIS=0; COLLECT_REPORTS=0
ROLLBACK_MINUTES=15; NO_AUTO_ROLLBACK=0; RB_BACKUP_DIR=""
declare -A SKIP=()
declare -A TRACKED=()
BACKUP_DIR=""; WORK_DIR=""; LOG_FILE="/dev/null"
APPLIED=(); SKIPPED=(); WARNINGS=(); FAILURES=(); PORTS_OPENED=(); SERVICES_CHANGED=()
REBOOT_NEEDED=0; SUMMARY_READY=0; FILE_CHANGED=0
TARGET_SSH_PORT=""; CURRENT_SSH_PORTS=(); SSH_MAJOR=0; SSH_MINOR=0; PKGS=(); ROLES=()
AUDIT_EXISTING=""
readonly VALID_STEPS="ssh ufw fail2ban sysctl modules auth autoupdates files services auditd apparmor logging time banners"

if [[ -t 1 ]]; then
  C_G=$'\e[32m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_C=$'\e[36m'; C_N=$'\e[0m'
else
  C_G=""; C_Y=""; C_R=""; C_C=""; C_N=""
fi

# -------------- PASSO 2 - LOGGING -----
_log() { local lvl="$1" col="$2"; shift 2
  local line; line="$(date '+%F %T') [$lvl] $*"
  printf '%s\n' "$line" >>"$LOG_FILE"
  printf '%s%s%s\n' "$col" "$line" "$C_N"
}
log()       { _log OK "$C_G" "$@"; }
info()      { _log INFO "$C_C" "$@"; }
warn()      { WARNINGS+=("$*"); _log AVISO "$C_Y" "$@"; }
err()       { _log ERRO "$C_R" "$@" >&2; }
fail_soft() { FAILURES+=("$*"); _log FALHA "$C_R" "$@"; }
skipped()   { SKIPPED+=("$*"); info "Ignorado: $*"; }
applied()   { APPLIED+=("$*"); log "$*"; }
die()       { err "$*"; exit 1; }
usage_err() { printf 'Erro: %s\n\nUse --help para ver as opções.\n' "$*" >&2; exit 2; }

on_err() {
  local rc=$? line="${1:-?}" fn="${2:-main}"
  trap - ERR
  err "Falha inesperada (código $rc) na linha $line, função '$fn'. O texto do comando é omitido de propósito (evita vazar dados sensíveis)."
  err "Log: $LOG_FILE"
  if [[ -f "$STATE_DIR/pending" ]]; then
    err "Há rollback agendado. Para reverter agora: sudo $SELF rollback"
  fi
  exit "$rc"
}
trap 'on_err "$LINENO" "${FUNCNAME[0]:-main}"' ERR
trap 'die "Interrompido por sinal. Se SSH/UFW já foram alterados, o rollback agendado continua ativo."' INT TERM

finish() {
  local rc=$?
  trap - EXIT ERR INT TERM
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then rm -rf -- "$WORK_DIR"; fi
  if [[ $rc -eq 0 && ${#FAILURES[@]} -gt 0 ]]; then rc=3; fi
  if [[ "$SUBCMD" == apply && $SUMMARY_READY -eq 1 ]]; then print_summary "$rc"; fi
  exit "$rc"
}
trap finish EXIT

# -------------- PASSO 3 - FUNCOES AUXILIARES -----
have() { command -v "$1" >/dev/null 2>&1; }
join_by() { local IFS="$1"; shift; printf '%s' "$*"; }
step_enabled() { [[ -z "${SKIP[$1]:-}" ]]; }

need_cmds() {
  local missing=() c
  for c in "$@"; do if ! have "$c"; then missing+=("$c"); fi; done
  if ((${#missing[@]})); then die "Dependências ausentes: ${missing[*]}"; fi
}

run() {
  if ((DRY_RUN)); then info "[dry-run] $(printf '%q ' "$@")"; return 0; fi
  "$@"
}

confirm() {
  local msg="$1" ans
  if ((DRY_RUN)); then info "[dry-run] seria pedida confirmação: $msg"; return 0; fi
  if ((ASSUME_YES)); then info "Confirmado via --yes: $msg"; return 0; fi
  if [[ ! -t 0 ]]; then warn "Confirmação necessária e stdin não é interativo (use --yes): $msg"; return 1; fi
  read -r -p "[?] $msg Digite 'sim' para continuar: " ans
  if [[ "$ans" == "sim" || "$ans" == "yes" ]]; then return 0; fi
  return 1
}

pkg_installed() { [[ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null)" == "installed" ]]; }

# -------------- PASSO 4 - VALIDADORES -----
valid_user()      { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }
valid_port()      { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( $1 <= 65535 )); }
valid_portproto() { [[ "$1" == */* ]] && valid_port "${1%%/*}" && [[ "${1##*/}" == tcp || "${1##*/}" == udp ]]; }
valid_name()      { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9@._:+-]{0,127}$ ]]; }
valid_cidr() {
  [[ "$1" =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]] || return 1
  python3 -c 'import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False)' "$1" 2>/dev/null
}
valid_ip() {
  [[ "$1" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
  python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$1" 2>/dev/null
}
ip_in_cidrs() {
  python3 - "$@" <<'PY'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
sys.exit(0 if any(ip in ipaddress.ip_network(c, strict=False) for c in sys.argv[2:]) else 1)
PY
}

current_client_ip() {
  local ip=""
  if [[ -n "${SSH_CONNECTION:-}" ]]; then ip="${SSH_CONNECTION%% *}"; fi
  if [[ -z "$ip" ]]; then
    ip="$(who -m 2>/dev/null | awk '{print $NF}' | tr -d '()')" || ip=""
  fi
  if [[ -n "$ip" ]] && valid_ip "$ip"; then printf '%s' "$ip"; fi
  return 0
}

# -------------- PASSO 5 - USO -----
usage() {
  cat <<'EOF'
ubuntu-hardening.sh v2.0.0 — hardening controlado de Ubuntu Server

SUBCOMANDOS
  apply (padrão)          Aplica o hardening
  confirm [--force]       Confirma sucesso e CANCELA o rollback automático
  rollback [--backup-dir D]  Reverte manualmente (usa o rollback pendente)

GERAIS
  --admin-user USER       Obrigatório. Repetível (1º = principal). Precisa ter chave SSH válida.
  --dry-run               Mostra diffs/comandos sem aplicar nada
  --yes, -y               Responde "sim" às confirmações (automação; leia os avisos!)
  --skip STEP             Pula etapa. STEPs: ssh ufw fail2ban sysctl modules auth
                          autoupdates files services auditd apparmor logging time banners
  --rollback-minutes N    Janela do rollback automático (2-120, padrão 15)
  --no-auto-rollback      NÃO agenda rollback (risco de lockout; só p/ automação externa)

SSH
  --ssh-port PORT         Altera a porta (padrão: preserva a atual)
  --restrict-ssh-users    Escreve AllowUsers com os --admin-user (OUTROS usuários perdem SSH)
  --allow-password-auth   Mantém PasswordAuthentication yes (RISCO). Necessário se faltar chave
  --root-ssh-keys-only    PermitRootLogin prohibit-password (padrão: no)
  --allow-tcp-forward     AllowTcpForwarding yes (bastion/túneis)
  --allow-agent-forward   AllowAgentForwarding yes
  --skip-ssh-crypto       Não define Ciphers/MACs/KexAlgorithms

FIREWALL / FAIL2BAN
  --allow-port P/proto    Libera porta no UFW (ex.: 443/tcp). Repetível
  --allow-ssh-from CIDR   Restringe SSH a IP/CIDR. Repetível
  --ssh-no-ratelimit      Usa "allow" em vez de "limit" no SSH
  --ufw-reset             Apaga regras UFW existentes (pede confirmação)
  --fail2ban-ignoreip C   IP/CIDR ignorado pelo fail2ban. Repetível
  --fail2ban-ignore-current-ip  Ignora o IP da sessão atual (opt-in)

PACOTES
  --full-upgrade          apt-get upgrade geral (confirmação)
  --remove-legacy-pkgs    Remove telnet/rsh/nis/talk/xinetd instalados (inventário+confirmação)

KERNEL / MÓDULOS
  --sysctl-extended       Conjunto estendido (perf_event, kexec, sysrq, userfaultfd...)
  --disable-ip-forward    ip_forward=0 (recusa se detectar Docker/K8s/VPN/bridge)
  --disable-ipv6-ra       accept_ra=0 (quebra SLAAC)
  --strict-rpfilter       rp_filter=1 (quebra roteamento assimétrico)
  --block-module NAME     Bloqueia módulo adicional. Repetível
  --no-default-modules    Não usa a lista padrão (cramfs freevxfs jffs2 hfs hfsplus dccp rds tipc)
  --block-usb             Bloqueia usb-storage (confirmação)
  --block-thunderbolt     Bloqueia thunderbolt (confirmação)

CONTAS / ARQUIVOS / SERVIÇOS
  --sudo-io-log           sudo log_input/log_output (PODE GRAVAR SENHAS; confirmação)
  --tmout SEC             TMOUT em shells interativos (padrão: desativado)
  --cron-allow            Cria /etc/cron.allow (root, admins e donos de crontabs atuais)
  --harden-shm            /dev/shm nodev,nosuid,noexec
  --disable-service NAME  Desabilita (disable --now) serviço. Repetível; mostra dependentes
  --mask-services         Também mascara os serviços acima (confirmação)

AUDITORIA / MAC / INTEGRIDADE
  --audit-tune-logs       auditd max_log_file=50, num_logs=10
  --audit-immutable       Adiciona "-e 2" (regras só mudam após reboot) (confirmação)
  --apparmor-enforce P    aa-enforce no programa/perfil P (ex.: /usr/sbin/cupsd). Repetível
  --apparmor-complain P   aa-complain em P. Repetível
  --with-aide             Instala AIDE e gera baseline (confirmação)
  --with-rkhunter         Instala rkhunter
  --rkhunter-update       rkhunter --update (acesso externo)
  --with-lynis            Executa auditoria Lynis (somente leitura)
  --collect-reports       Relatórios SUID/world-writable em /var/log/ubuntu-hardening/reports

Códigos de saída: 0 ok | 1 abortado/falha crítica | 2 uso inválido | 3 concluído com falhas não críticas
EOF
}

# -------------- PASSO 6 - ARGUMENTOS -----
req_arg() { [[ -n "${2-}" && "${2-}" != -* ]] || usage_err "A opção $1 requer um valor."; }

parse_args() {
  case "${1:-}" in apply|confirm|rollback) SUBCMD="$1"; shift ;; esac
  local v
  while (($#)); do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --dry-run) DRY_RUN=1; shift ;;
      -y|--yes) ASSUME_YES=1; shift ;;
      --force) FORCE=1; shift ;;
      --admin-user) req_arg "$1" "${2-}"; valid_user "$2" || usage_err "Usuário inválido: '$2'"; ADMIN_USERS+=("$2"); shift 2 ;;
      --ssh-port) req_arg "$1" "${2-}"; valid_port "$2" || usage_err "Porta SSH inválida: '$2'"; SSH_PORT="$2"; SSH_PORT_SET=1; shift 2 ;;
      --restrict-ssh-users) RESTRICT_SSH_USERS=1; shift ;;
      --allow-password-auth) ALLOW_PASSWORD_AUTH=1; shift ;;
      --root-ssh-keys-only) ROOT_KEYS_ONLY=1; shift ;;
      --allow-tcp-forward) ALLOW_TCP_FWD=1; shift ;;
      --allow-agent-forward) ALLOW_AGENT_FWD=1; shift ;;
      --skip-ssh-crypto) SKIP_SSH_CRYPTO=1; shift ;;
      --allow-port) req_arg "$1" "${2-}"; valid_portproto "$2" || usage_err "Formato inválido para --allow-port: '$2' (use PORT/tcp ou PORT/udp)"; EXTRA_PORTS+=("$2"); shift 2 ;;
      --allow-ssh-from) req_arg "$1" "${2-}"; valid_cidr "$2" || usage_err "IP/CIDR inválido para --allow-ssh-from: '$2'"; SSH_ALLOW_FROM+=("$2"); shift 2 ;;
      --ssh-no-ratelimit) SSH_NO_RATELIMIT=1; shift ;;
      --ufw-reset) UFW_RESET=1; shift ;;
      --fail2ban-ignoreip) req_arg "$1" "${2-}"; valid_cidr "$2" || usage_err "IP/CIDR inválido: '$2'"; F2B_IGNORE+=("$2"); shift 2 ;;
      --fail2ban-ignore-current-ip) F2B_IGNORE_CURRENT=1; shift ;;
      --full-upgrade) FULL_UPGRADE=1; shift ;;
      --remove-legacy-pkgs) REMOVE_LEGACY=1; shift ;;
      --sysctl-extended) SYSCTL_EXT=1; shift ;;
      --disable-ip-forward) SYSCTL_NOFWD=1; shift ;;
      --disable-ipv6-ra) SYSCTL_NORA=1; shift ;;
      --strict-rpfilter) SYSCTL_STRICT_RPF=1; shift ;;
      --block-module) req_arg "$1" "${2-}"; valid_name "$2" || usage_err "Nome de módulo inválido: '$2'"; BLOCK_MODULES+=("$2"); shift 2 ;;
      --no-default-modules) NO_DEFAULT_MODULES=1; shift ;;
      --block-usb) BLOCK_USB=1; shift ;;
      --block-thunderbolt) BLOCK_TB=1; shift ;;
      --sudo-io-log) SUDO_IO_LOG=1; shift ;;
      --tmout) req_arg "$1" "${2-}"; [[ "$2" =~ ^[0-9]+$ ]] && (( 10#$2 >= 60 && 10#$2 <= 86400 )) || usage_err "--tmout deve estar entre 60 e 86400 segundos"; TMOUT_SECS=$((10#$2)); shift 2 ;;
      --cron-allow) CRON_ALLOW=1; shift ;;
      --harden-shm) HARDEN_SHM=1; shift ;;
      --disable-service) req_arg "$1" "${2-}"; valid_name "$2" || usage_err "Nome de serviço inválido: '$2'"; DISABLE_SERVICES+=("$2"); shift 2 ;;
      --mask-services) MASK_SERVICES=1; shift ;;
      --audit-tune-logs) AUDIT_TUNE=1; shift ;;
      --audit-immutable) AUDIT_IMMUTABLE=1; shift ;;
      --apparmor-enforce) req_arg "$1" "${2-}"; [[ "$2" =~ ^/[A-Za-z0-9._/+-]+$ ]] || usage_err "Perfil/programa inválido: '$2' (use caminho absoluto)"; AA_ENFORCE+=("$2"); shift 2 ;;
      --apparmor-complain) req_arg "$1" "${2-}"; [[ "$2" =~ ^/[A-Za-z0-9._/+-]+$ ]] || usage_err "Perfil/programa inválido: '$2' (use caminho absoluto)"; AA_COMPLAIN+=("$2"); shift 2 ;;
      --with-aide) WITH_AIDE=1; shift ;;
      --with-rkhunter) WITH_RKH=1; shift ;;
      --rkhunter-update) RKH_UPDATE=1; WITH_RKH=1; shift ;;
      --with-lynis) WITH_LYNIS=1; shift ;;
      --collect-reports) COLLECT_REPORTS=1; shift ;;
      --rollback-minutes) req_arg "$1" "${2-}"; [[ "$2" =~ ^[0-9]+$ ]] && (( 10#$2 >= 2 && 10#$2 <= 120 )) || usage_err "--rollback-minutes deve estar entre 2 e 120"; ROLLBACK_MINUTES=$((10#$2)); shift 2 ;;
      --no-auto-rollback) NO_AUTO_ROLLBACK=1; shift ;;
      --backup-dir) req_arg "$1" "${2-}"; [[ "$2" =~ ^/var/backups/ubuntu-hardening-[0-9]{8}-[0-9]{6}$ ]] || usage_err "Diretório de backup inválido: '$2'"; RB_BACKUP_DIR="$2"; shift 2 ;;
      --skip) req_arg "$1" "${2-}"; v="$2"
              if [[ " $VALID_STEPS " != *" $v "* ]]; then usage_err "STEP inválido: '$v'. Válidos: $VALID_STEPS"; fi
              SKIP["$v"]=1; shift 2 ;;
      *) usage_err "Opção desconhecida: '$1'" ;;
    esac
  done
}

# -------------- PASSO 7 - BACKUP E ESCRITA ATOMICA -----
backup_init() {
  install -d -m 700 -o root -g root "$STATE_DIR" "$LOG_DIR"
  BACKUP_DIR="/var/backups/ubuntu-hardening-$TS"
  install -d -m 700 -o root -g root "$BACKUP_DIR" "$BACKUP_DIR/files" "$BACKUP_DIR/state-before"
  install -m 600 -o root -g root /dev/null "$BACKUP_DIR/manifest.txt"
  LOG_FILE="$LOG_DIR/hardening-$TS.log"
  install -m 600 -o root -g root /dev/null "$LOG_FILE"
  info "Backup (modo 700): $BACKUP_DIR | Log: $LOG_FILE"
}

track_file() {
  local p="$1"
  if [[ -n "${TRACKED[$p]:-}" || $DRY_RUN -eq 1 ]]; then return 0; fi
  if [[ -e "$p" || -L "$p" ]]; then
    install -d -m 700 "$BACKUP_DIR/files$(dirname -- "$p")"
    cp -a -- "$p" "$BACKUP_DIR/files$p"
    printf 'existed|%s\n' "$p" >>"$BACKUP_DIR/manifest.txt"
  else
    printf 'created|%s\n' "$p" >>"$BACKUP_DIR/manifest.txt"
  fi
  TRACKED["$p"]=1
}

restore_file() {
  local p="$1"
  if ((DRY_RUN)); then return 0; fi
  if [[ -e "$BACKUP_DIR/files$p" || -L "$BACKUP_DIR/files$p" ]]; then
    cp -a -- "$BACKUP_DIR/files$p" "$p.hrd-restore.$$"
    mv -f -- "$p.hrd-restore.$$" "$p"
  else
    rm -f -- "$p"
  fi
  warn "Arquivo restaurado ao estado anterior: $p"
}

install_atomic() {
  local dest="$1" mode="$2" owner="${3:-root:root}" pv="${4:-}"
  local new dir base tmp
  FILE_CHANGED=0
  new="$(mktemp "$WORK_DIR/new.XXXXXX")"
  cat >"$new"
  if [[ ! -s "$new" ]]; then rm -f -- "$new"; die "Conteúdo vazio gerado para $dest (abortado por segurança)."; fi
  if [[ -n "$pv" ]]; then
    if ! "$pv" "$new"; then rm -f -- "$new"; die "Validação prévia falhou para $dest. Nada foi alterado."; fi
  fi
  if [[ -f "$dest" ]] && cmp -s -- "$new" "$dest"; then
    info "Sem mudanças: $dest"; rm -f -- "$new"; return 0
  fi
  FILE_CHANGED=1
  if ((DRY_RUN)); then
    info "[dry-run] $dest seria alterado (modo $mode, dono $owner):"
    if [[ -f "$dest" ]]; then
      { diff -u -- "$dest" "$new" || [[ $? -eq 1 ]]; } | sed 's/^/      /'
    else
      sed 's/^/      + /' "$new"
    fi
    rm -f -- "$new"; return 0
  fi
  track_file "$dest"
  dir="$(dirname -- "$dest")"; base="$(basename -- "$dest")"
  if [[ ! -d "$dir" ]]; then install -d -m 755 -o root -g root "$dir"; fi
  tmp="$(mktemp "$dir/.${base}.XXXXXX")"
  install -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" -- "$new" "$tmp"
  mv -f -- "$tmp" "$dest"
  rm -f -- "$new"
  APPLIED+=("arquivo: $dest"); info "Instalado: $dest"
}

snap() {
  local name="$1"; shift
  if ! have "$1"; then info "Estado inicial '$name': ferramenta '$1' ausente."; return 0; fi
  if ! "$@" >"$BACKUP_DIR/state-before/$name.txt" 2>&1; then
    warn "Estado inicial '$name' incompleto (comando retornou erro)."
  fi
  chmod 600 "$BACKUP_DIR/state-before/$name.txt"
}

record_state() {
  info "Registrando estado inicial em $BACKUP_DIR/state-before/ ..."
  snap services systemctl list-units --type=service --state=running --no-pager
  snap unit-files-enabled systemctl list-unit-files --state=enabled --no-pager
  snap listening ss -tulpn
  snap ufw-verbose ufw status verbose
  snap ufw-added ufw show added
  snap sshd-effective sshd -T
  snap sysctl-all sysctl -a
  snap audit-status auditctl -s
  snap audit-rules auditctl -l
  snap apparmor aa-status
  snap fail2ban fail2ban-client status
  snap packages dpkg-query -W
  snap mounts findmnt
  snap time timedatectl status
  if [[ -r /etc/default/ufw ]]; then cp -a /etc/default/ufw "$BACKUP_DIR/state-before/default-ufw.txt"; fi
}

# -------------- PASSO 8 - PRE-VERIFICACOES -----
check_admin_user() {
  local u="$1" shell home
  valid_user "$u" || die "Nome de usuário inválido: '$u'"
  getent passwd "$u" >/dev/null || die "Usuário '$u' não existe."
  [[ "$(id -u "$u")" -ne 0 ]] || die "O administrador não pode ser root (uid 0)."
  shell="$(getent passwd "$u" | cut -d: -f7)"
  grep -qxF -- "$shell" /etc/shells || die "Shell de '$u' ($shell) não está em /etc/shells."
  case "$shell" in */nologin|*/false) die "Usuário '$u' tem shell sem login ($shell)." ;; esac
  home="$(getent passwd "$u" | cut -d: -f6)"
  [[ -d "$home" ]] || die "Home de '$u' ($home) não existe."
}

ssh_uses_socket() { systemctl is-active --quiet ssh.socket 2>/dev/null; }

effective_ssh_ports() {
  if ssh_uses_socket; then
    systemctl show ssh.socket -p Listen --value | sed -n 's/.*:\([0-9][0-9]*\) (Stream).*/\1/p'
  else
    sshd -T | awk '$1=="port"{print $2}'
  fi | sort -un
}

port_listening() { ss -H -tln | awk -v p=":$1" 'substr($4, length($4)-length(p)+1)==p {f=1} END{exit !f}'; }

preflight() {
  [[ $EUID -eq 0 ]] || die "Execute como root (sudo)."
  [[ -r /etc/os-release ]] || die "/etc/os-release ausente."
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "Somente Ubuntu é suportado (detectado: ${ID:-desconhecido})."
  case "${VERSION_ID:-}" in
    20.04|22.04|24.04) info "Ubuntu ${VERSION_ID} detectado (suportado)." ;;
    *) die "Ubuntu ${VERSION_ID:-?} não suportado (suportados: 20.04, 22.04, 24.04)." ;;
  esac
  need_cmds bash apt-get dpkg dpkg-query systemctl systemd-run sshd ssh ssh-keygen visudo awk sed grep \
            find install getent flock mktemp diff cmp stat python3 ss readlink cut sort uname date who \
            id tee mount findmnt cp mv rm chmod chown

  ((${#ADMIN_USERS[@]})) || usage_err "Informe ao menos um --admin-user."
  local u
  for u in "${ADMIN_USERS[@]}"; do check_admin_user "$u"; done

  mapfile -t CURRENT_SSH_PORTS < <(effective_ssh_ports)
  if ((${#CURRENT_SSH_PORTS[@]} == 0)); then
    die "Não foi possível determinar a porta SSH atual (sshd inativo?). Corrija antes de endurecer."
  fi
  if ((SSH_PORT_SET)); then TARGET_SSH_PORT="$SSH_PORT"; else TARGET_SSH_PORT="${CURRENT_SSH_PORTS[0]}"; fi
  info "Porta SSH atual: $(join_by , "${CURRENT_SSH_PORTS[@]}") | alvo: $TARGET_SSH_PORT"

  local v; v="$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\([0-9]\+\)\.\([0-9]\+\).*/\1 \2/p')"
  [[ -n "$v" ]] || die "Não foi possível detectar a versão do OpenSSH."
  IFS=' ' read -r SSH_MAJOR SSH_MINOR <<<"$v"
  info "OpenSSH local: ${SSH_MAJOR}.${SSH_MINOR}"

  if ((DRY_RUN == 0)); then
    exec {LOCK_FD}>"$LOCK_FILE"
    flock -n "$LOCK_FD" || die "Outra execução do script está em andamento (lock: $LOCK_FILE)."
  fi
  if [[ -f "$STATE_DIR/pending" && $DRY_RUN -eq 0 ]]; then
    die "Existe um rollback pendente de execução anterior. Rode 'confirm' (se tudo OK) ou 'rollback' antes de aplicar de novo."
  fi
}

print_plan() {
  info "================ PLANO (v$VERSION) ================"
  info "Modo: $([[ $DRY_RUN -eq 1 ]] && echo DRY-RUN || echo APLICAR) | admins: $(join_by , "${ADMIN_USERS[@]}") | SSH alvo: $TARGET_SSH_PORT"
  local s
  for s in $VALID_STEPS; do
    if step_enabled "$s"; then info "  etapa: $s"; else info "  etapa: $s (PULADA)"; fi
  done
  info "Opt-ins ativos: $( { ((FULL_UPGRADE)) && printf 'full-upgrade '; ((REMOVE_LEGACY)) && printf 'remove-legacy '; \
     ((UFW_RESET)) && printf 'ufw-reset '; ((RESTRICT_SSH_USERS)) && printf 'restrict-ssh-users '; \
     ((ALLOW_PASSWORD_AUTH)) && printf 'allow-password-auth '; ((SUDO_IO_LOG)) && printf 'sudo-io-log '; \
     ((HARDEN_SHM)) && printf 'harden-shm '; ((AUDIT_IMMUTABLE)) && printf 'audit-immutable '; \
     ((WITH_AIDE)) && printf 'aide '; ((CRON_ALLOW)) && printf 'cron-allow '; true; } )"
  if ((${#DISABLE_SERVICES[@]})); then info "Serviços a desabilitar: $(join_by , "${DISABLE_SERVICES[@]}")"; fi
  if ((NO_AUTO_ROLLBACK)); then warn "Rollback automático DESATIVADO (--no-auto-rollback)."; fi
  warn "Mudanças em SSH/UFW podem derrubar novas conexões. Mantenha esta sessão e um console (hipervisor) abertos."
}

# -------------- PASSO 9 - PACOTES -----
add_pkg() { if ! pkg_installed "$1"; then PKGS+=("$1"); fi; }

step_packages() {
  info "== Pacotes =="
  local APT_OPTS=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
  if ((!DRY_RUN)); then
    local d="$BACKUP_DIR/state-before/apt" p
    install -d -m 700 "$d"
    for p in /etc/apt/sources.list /etc/apt/sources.list.d /etc/apt/apt.conf.d; do
      if [[ -e "$p" ]]; then cp -a -- "$p" "$d/"; fi
    done
  fi
  info "apt-get update atualiza somente índices. --force-confold preserva configs existentes."
  run apt-get update -qq
  if ((!DRY_RUN)); then apt-cache policy >"$BACKUP_DIR/state-before/apt/policy.txt" 2>&1; fi

  if ((FULL_UPGRADE)); then
    if confirm "apt-get upgrade atualizará TODOS os pacotes (pode reiniciar serviços e exigir reboot)."; then
      run apt-get "${APT_OPTS[@]}" upgrade
      applied "Upgrade geral de pacotes executado"
    else skipped "upgrade geral (sem confirmação)"; fi
  fi

  PKGS=()
  if step_enabled ufw; then add_pkg ufw; fi
  if step_enabled fail2ban; then add_pkg fail2ban; fi
  if step_enabled auditd; then add_pkg auditd; fi
  if step_enabled apparmor && ((${#AA_ENFORCE[@]} + ${#AA_COMPLAIN[@]})); then add_pkg apparmor-utils; fi
  if step_enabled auth; then add_pkg libpam-pwquality; fi
  if step_enabled autoupdates; then add_pkg unattended-upgrades; fi
  if ((WITH_AIDE)); then add_pkg aide; add_pkg aide-common; fi
  if ((WITH_RKH)); then add_pkg rkhunter; fi
  if ((WITH_LYNIS)); then add_pkg lynis; fi
  if ((${#PKGS[@]})); then
    info "Instalando: ${PKGS[*]}"
    run apt-get install "${APT_OPTS[@]}" --no-install-recommends "${PKGS[@]}"
    if ((!DRY_RUN)); then
      local p
      for p in "${PKGS[@]}"; do pkg_installed "$p" || die "Falha ao instalar o pacote '$p'."; done
    fi
    applied "Pacotes instalados: ${PKGS[*]}"
  else
    info "Todos os pacotes necessários já estão instalados."
  fi

  if ((REMOVE_LEGACY)); then
    local legacy=(telnet rsh-client rsh-redone-client nis talk ntalk xinetd) found=() l
    for l in "${legacy[@]}"; do if pkg_installed "$l"; then found+=("$l"); fi; done
    if ((${#found[@]})); then
      info "Inventário de pacotes legados instalados: ${found[*]}"
      if confirm "Remover (purge) ${found[*]}? (autoremove NÃO será executado)"; then
        run apt-get purge "${APT_OPTS[@]}" "${found[@]}"
        applied "Pacotes legados removidos: ${found[*]}"
      else skipped "remoção de pacotes legados"; fi
    else info "Nenhum pacote legado instalado."; fi
  fi
  if [[ -f /var/run/reboot-required ]]; then REBOOT_NEEDED=1; fi
}

# -------------- PASSO 10 - ROLLBACK -----
write_rollback_script() {
  local f="$BACKUP_DIR/rollback.sh"
  {
    printf '#!/usr/bin/env bash\n# Gerado por ubuntu-hardening.sh %s em %s\n' "$VERSION" "$TS"
    printf 'BACKUP_DIR=%q\n' "$BACKUP_DIR"
    cat <<'EOS'
set -uo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
STATE_DIR=/var/lib/ubuntu-hardening
RBLOG="$BACKUP_DIR/rollback.log"
rlog() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$RBLOG"; }
rlog "== ROLLBACK iniciado (backup: $BACKUP_DIR) =="

while IFS='|' read -r st p; do
  [[ -n "${p:-}" ]] || continue
  case "$st" in
    existed)
      if [[ -e "$BACKUP_DIR/files$p" || -L "$BACKUP_DIR/files$p" ]]; then
        if cp -a -- "$BACKUP_DIR/files$p" "$p.rb.$$" && mv -f -- "$p.rb.$$" "$p"; then rlog "restaurado: $p"; else rlog "ERRO restaurando $p"; fi
      fi ;;
    created) if rm -f -- "$p"; then rlog "removido (criado pelo hardening): $p"; else rlog "ERRO removendo $p"; fi ;;
  esac
done <"$BACKUP_DIR/manifest.txt"

if [[ -f "$BACKUP_DIR/sysctl_prev" ]]; then
  while IFS='=' read -r k v; do
    [[ -n "${k:-}" ]] || continue
    sysctl -q -w "$k=$v" >/dev/null 2>&1 && rlog "sysctl $k=$v" || rlog "AVISO: não foi possível restaurar sysctl $k"
  done <"$BACKUP_DIR/sysctl_prev"
fi
if [[ -f "$BACKUP_DIR/perms_prev" ]]; then
  while IFS='|' read -r p m o; do
    [[ -n "${p:-}" ]] || continue
    chown "$o" -- "$p" && chmod "$m" -- "$p" && rlog "perm restaurada: $p ($o $m)"
  done <"$BACKUP_DIR/perms_prev"
fi
if [[ -f "$BACKUP_DIR/shm_prev" ]]; then
  mount -o "remount,$(cat "$BACKUP_DIR/shm_prev")" /dev/shm && rlog "/dev/shm restaurado"
fi
if [[ -f "$BACKUP_DIR/services_state" ]]; then
  while IFS='|' read -r s en act msk; do
    [[ -n "${s:-}" ]] || continue
    [[ "$msk" == 1 ]] && systemctl unmask "$s" || true
    if [[ "$en" == enabled ]]; then
      systemctl enable "$s" || rlog "AVISO: não foi possível reabilitar $s"
    elif [[ "$en" == disabled ]]; then
      systemctl disable "$s" || rlog "AVISO: não foi possível desabilitar $s"
    fi
    if [[ "$act" == active ]]; then
      systemctl start "$s" || rlog "AVISO: não foi possível iniciar $s"
    else
      systemctl stop "$s" || rlog "AVISO: não foi possível parar $s"
    fi
    rlog "serviço restaurado: $s (enabled=$en active=$act)"
  done <"$BACKUP_DIR/services_state"
fi
if [[ -f "$BACKUP_DIR/apparmor_prev" ]]; then
  while IFS='|' read -r p mode; do
    [[ -n "${p:-}" ]] || continue
    if [[ "$mode" == enforce ]]; then aa-enforce "$p"; else aa-complain "$p"; fi
    rlog "apparmor $p -> $mode"
  done <"$BACKUP_DIR/apparmor_prev"
fi

systemctl daemon-reload
if sshd -t; then
  if systemctl is-active --quiet ssh.socket; then systemctl restart ssh.socket; fi
  systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service
  rlog "SSH reiniciado com configuração restaurada"
else
  rlog "ERRO: sshd -t falhou após restore; SSH NÃO foi reiniciado. Verifique manualmente."
fi
if command -v ufw >/dev/null 2>&1 && [[ -f "$BACKUP_DIR/ufw_prior" ]]; then
  if [[ "$(cat "$BACKUP_DIR/ufw_prior")" == inactive ]]; then ufw --force disable; else ufw --force reload; fi
  rlog "UFW restaurado (estado anterior: $(cat "$BACKUP_DIR/ufw_prior"))"
fi
if systemctl is-active --quiet fail2ban; then systemctl restart fail2ban; fi
if command -v augenrules >/dev/null 2>&1; then augenrules --load >/dev/null 2>&1 || rlog "AVISO: auditd imutável ou regras inválidas; recarregue após reboot"; fi
systemctl restart systemd-journald 2>/dev/null
rm -f "$STATE_DIR/pending"
rlog "== ROLLBACK concluído. Pacotes instalados NÃO são removidos. =="
EOS
  } >"$f"
  chmod 700 "$f"
}

schedule_rollback() {
  if ((NO_AUTO_ROLLBACK)); then warn "Sem rollback automático: recuperação só manual (sudo $SELF rollback)."; return 0; fi
  if ((DRY_RUN)); then info "[dry-run] agendaria rollback automático em ${ROLLBACK_MINUTES} min via systemd-run"; return 0; fi
  local unit="ubuntu-hardening-rollback-$TS"
  write_rollback_script
  if ! systemd-run --quiet --on-active="${ROLLBACK_MINUTES}m" --unit="$unit" \
    --description="Rollback automático do ubuntu-hardening ($TS)" /bin/bash "$BACKUP_DIR/rollback.sh"; then
    die "Não foi possível agendar o rollback automático. Nenhuma etapa de hardening foi aplicada."
  fi
  if ! systemctl is-active --quiet "$unit.timer"; then
    systemctl stop "$unit.service" 2>/dev/null || true
    die "Timer de rollback não ficou ativo. Nenhuma etapa de hardening foi aplicada."
  fi
  printf 'UNIT=%s\nBACKUP_DIR=%s\n' "$unit" "$BACKUP_DIR" >"$STATE_DIR/pending"
  chmod 600 "$STATE_DIR/pending"
  applied "Rollback automático agendado para ${ROLLBACK_MINUTES} min (cancele com: sudo $SELF confirm)"
}

# -------------- PASSO 11 - BANNERS -----
step_banners() {
  info "== Banners =="
  local msg=$'*** ACESSO RESTRITO ***\nSistema monitorado. Acesso nao autorizado e proibido e sujeito a\nmedidas legais. Atividades sao registradas e auditadas.'
  install_atomic /etc/issue.net 0644 root:root <<<"$msg"
  install_atomic /etc/issue 0644 root:root <<<"$msg"
}

# -------------- PASSO 12 - FIREWALL UFW -----
step_ufw() {
  info "== Firewall (UFW) =="
  if ((!DRY_RUN)); then need_cmds ufw; elif ! have ufw; then info "[dry-run] ufw ainda não instalado; passos simulados."; fi
  local was_active=0 verb="limit" src p
  if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then was_active=1; fi
  if ((!DRY_RUN)); then
    printf '%s\n' "$([[ $was_active -eq 1 ]] && echo active || echo inactive)" >"$BACKUP_DIR/ufw_prior"
    local f
    for f in /etc/ufw/*.rules /etc/ufw/*.conf /etc/default/ufw; do if [[ -f "$f" ]]; then track_file "$f"; fi; done
  fi
  if ((SSH_NO_RATELIMIT)); then verb="allow"; fi

  if ((${#SSH_ALLOW_FROM[@]})); then
    local cip; cip="$(current_client_ip)"
    if [[ -n "$cip" ]] && ! ip_in_cidrs "$cip" "${SSH_ALLOW_FROM[@]}"; then
      warn "Seu IP atual ($cip) NÃO está em --allow-ssh-from."
      confirm "Prosseguir mesmo assim? (novas conexões deste IP serão bloqueadas)" || die "Abortado: inclua seu IP em --allow-ssh-from."
    fi
  fi

  if ((UFW_RESET)); then
    if confirm "--ufw-reset APAGARÁ todas as regras UFW existentes (backup em $BACKUP_DIR)."; then
      run ufw --force reset
      applied "UFW resetado (regras anteriores em $BACKUP_DIR/files/etc/ufw)"
    else die "Reset do UFW negado; abortando para não aplicar política parcial."; fi
  fi

  local ports
  mapfile -t ports < <(printf '%s\n' "$TARGET_SSH_PORT" "${CURRENT_SSH_PORTS[@]}" | sort -un)
  for p in "${ports[@]}"; do
    valid_port "$p" || die "Porta SSH inválida detectada: $p"
    if ((${#SSH_ALLOW_FROM[@]})); then
      for src in "${SSH_ALLOW_FROM[@]}"; do
        run ufw "$verb" from "$src" to any port "$p" proto tcp comment "hardening-ssh"
      done
    else
      run ufw "$verb" "$p/tcp" comment "hardening-ssh"
    fi
    PORTS_OPENED+=("$p/tcp (SSH)")
  done
  for p in "${EXTRA_PORTS[@]}"; do
    run ufw allow "$p" comment "hardening-extra"
    PORTS_OPENED+=("$p")
  done

  if ((!DRY_RUN)); then
    local added; added="$(ufw show added)"
    if ! grep -Eq "[ /]${TARGET_SSH_PORT}(/tcp| proto tcp)" <<<"$added"; then
      die "Regra SSH para a porta $TARGET_SSH_PORT não encontrada no UFW. Política NÃO foi endurecida."
    fi
  fi
  run ufw default deny incoming
  if [[ -r /etc/default/ufw ]] && grep -q '^DEFAULT_OUTPUT_POLICY="DROP"' /etc/default/ufw; then
    warn "UFW com saída DROP preexistente: preservado (garanta DNS/apt/NTP liberados)."
  fi
  if ((was_active == 0)); then
    run ufw --force enable
    applied "UFW habilitado (default deny incoming; SSH liberado em: ${ports[*]})"
  else
    applied "UFW já ativo: regras adicionadas e default deny incoming garantido"
  fi
  if ((!DRY_RUN)); then
    ufw status verbose | tee -a "$LOG_FILE" >/dev/null
    ufw status | grep -q '^Status: active' || die "UFW não ficou ativo."
  fi
  if have docker && [[ -n "$(systemctl is-active docker 2>/dev/null || true)" ]]; then
    warn "Docker detectado: portas publicadas (-p) contornam o UFW (iptables do Docker). Revise DOCKER-USER."
  fi
  if ((${#CURRENT_SSH_PORTS[@]} > 0)) && [[ "${CURRENT_SSH_PORTS[0]}" != "$TARGET_SSH_PORT" ]]; then
    info "Após validar a nova porta: remova a regra antiga (ufw status numbered; ufw delete N)."
  fi
}

# -------------- PASSO 13 - SSH -----
pv_sshd() { if have sshd; then sshd -t -f "$1"; fi; }

filter_algs() {
  local q="$1" want="$2" supported out="" a
  supported="$(ssh -Q "$q")"
  local IFS=','
  for a in $want; do
    if grep -qxF -- "$a" <<<"$supported"; then out+="${out:+,}$a"; fi
  done
  printf '%s' "$out"
}

user_ssh_paths() {
  local u="$1" home uid pats p
  home="$(getent passwd "$u" | cut -d: -f6)"; uid="$(id -u "$u")"
  pats="$(sshd -T -C "user=$u,host=localhost,addr=127.0.0.1" 2>/dev/null | awk '$1=="authorizedkeysfile"{$1=""; print; exit}')" || pats=""
  if [[ -z "${pats// /}" ]]; then pats=".ssh/authorized_keys .ssh/authorized_keys2"; fi
  local IFS=' '
  for p in $pats; do
    p="${p//%%/%}"; p="${p//%h/$home}"; p="${p//%u/$u}"; p="${p//%U/$uid}"
    if [[ "$p" != /* ]]; then p="$home/$p"; fi
    printf '%s\n' "$p"
  done
}

strict_modes_ok() {
  local p="$1" u="$2" owner mode
  owner="$(stat -c %U -- "$p")"; mode="$(stat -c %a -- "$p")"
  if [[ "$owner" != "$u" && "$owner" != root ]]; then warn "StrictModes: $p pertence a '$owner' (esperado '$u')."; return 1; fi
  if (( (8#$mode & 8#022) != 0 )); then warn "StrictModes: $p tem modo $mode (grupo/outros com escrita); o sshd ignoraria a chave."; return 1; fi
  return 0
}

user_key_ok() {
  local u="$1" home f line bits kt n=0
  home="$(getent passwd "$u" | cut -d: -f6)"
  strict_modes_ok "$home" "$u" || return 1
  while IFS= read -r f; do
    if [[ ! -f "$f" ]]; then continue; fi
    strict_modes_ok "$(dirname -- "$f")" "$u" || return 1
    strict_modes_ok "$f" "$u" || return 1
    while IFS= read -r line; do
      bits="${line%% *}"; kt="${line##*(}"; kt="${kt%)}"
      case "$kt" in
        ED25519|ED25519-SK|ECDSA|ECDSA-SK) n=$((n + 1)) ;;
        RSA) if [[ "$bits" =~ ^[0-9]+$ ]] && ((bits >= 2048)); then n=$((n + 1)); fi ;;
        *) : ;;
      esac
    done < <(ssh-keygen -l -f "$f" 2>/dev/null)
  done < <(user_ssh_paths "$u")
  ((n > 0))
}

gen_sshd_fragment() {
  local pass_auth="$1" root_val="$2" fwd agent kbd="KbdInteractiveAuthentication"
  fwd="$([[ $ALLOW_TCP_FWD -eq 1 ]] && echo yes || echo no)"
  agent="$([[ $ALLOW_AGENT_FWD -eq 1 ]] && echo yes || echo no)"
  if ((SSH_MAJOR < 8 || (SSH_MAJOR == 8 && SSH_MINOR < 7))); then kbd="ChallengeResponseAuthentication"; fi
  printf '%s\n' "# Gerado por ubuntu-hardening.sh $VERSION em $TS"
  printf '%s\n' "# NOTA: no Ubuntu o 1º valor encontrado vale; este arquivo usa prefixo 00- para vencer o 50-cloud-init.conf"
  if ((SSH_PORT_SET)); then printf 'Port %s\n' "$SSH_PORT"; fi
  printf 'PermitRootLogin %s\n' "$root_val"
  if ((RESTRICT_SSH_USERS)); then printf 'AllowUsers %s\n' "$(join_by ' ' "${ADMIN_USERS[@]}")"; fi
  printf 'PubkeyAuthentication yes\nPasswordAuthentication %s\n%s no\nPermitEmptyPasswords no\n' "$pass_auth" "$kbd"
  printf 'MaxAuthTries 3\nLoginGraceTime 30\nClientAliveInterval 300\nClientAliveCountMax 2\nLogLevel VERBOSE\n'
  printf 'X11Forwarding no\nAllowAgentForwarding %s\nAllowTcpForwarding %s\nPermitTunnel no\nGatewayPorts no\n' "$agent" "$fwd"
  printf 'PermitUserEnvironment no\nHostbasedAuthentication no\nIgnoreRhosts yes\n'
  if step_enabled banners && [[ -f /etc/issue.net ]]; then printf 'Banner /etc/issue.net\n'; fi
  if ((!SKIP_SSH_CRYPTO)); then
    local c m k
    c="$(filter_algs cipher chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr)"
    m="$(filter_algs mac hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com)"
    k="$(filter_algs kex sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512)"
    if [[ -z "$c" || -z "$m" || -z "$k" ]]; then die "Nenhum algoritmo moderno suportado pelo OpenSSH local; use --skip-ssh-crypto."; fi
    printf 'Ciphers %s\nMACs %s\nKexAlgorithms %s\n' "$c" "$m" "$k"
  fi
}

verify_sshd_effective() {
  local pass_auth="$1" root_val="$2" eff
  eff="$(sshd -T -C "user=${ADMIN_USERS[0]},host=localhost,addr=127.0.0.1")"
  grep -qx "permitrootlogin $root_val" <<<"$eff" || { warn "sshd -T: permitrootlogin diferente de $root_val"; return 1; }
  grep -qx "passwordauthentication $pass_auth" <<<"$eff" || { warn "sshd -T: passwordauthentication diferente de $pass_auth"; return 1; }
  if ((RESTRICT_SSH_USERS)); then grep -q '^allowusers ' <<<"$eff" || { warn "sshd -T: allowusers ausente"; return 1; }; fi
  if ((SSH_PORT_SET && ! $(ssh_uses_socket && echo 1 || echo 0))); then
    grep -qx "port $SSH_PORT" <<<"$eff" || { warn "sshd -T: porta diferente de $SSH_PORT"; return 1; }
  fi
  return 0
}

step_ssh() {
  info "== SSH =="
  local u pass_auth="no" root_val="no" all_keys=1
  if ((ROOT_KEYS_ONLY)); then root_val="prohibit-password"; fi
  for u in "${ADMIN_USERS[@]}"; do
    if user_key_ok "$u"; then info "'$u': chave pública utilizável encontrada (tipo, tamanho e permissões OK)."
    else all_keys=0; warn "'$u': NENHUMA chave pública válida/utilizável."; fi
  done
  if ((ALLOW_PASSWORD_AUTH)); then
    pass_auth="yes"; warn "RISCO: PasswordAuthentication=yes mantido por opção explícita (--allow-password-auth)."
  elif ((!all_keys)); then
    die "Abortado: faltam chaves SSH válidas para o(s) admin(s). Instale-as (ssh-copy-id) ou use --allow-password-auth (arriscado)."
  else
    local members g m others=()
    for g in sudo admin; do
      members="$(getent group "$g" | cut -d: -f4)" || members=""
      local IFS=','
      for m in $members; do
        if [[ -n "$m" && " ${ADMIN_USERS[*]} " != *" $m "* ]] && getent passwd "$m" >/dev/null && ! user_key_ok "$m"; then others+=("$m"); fi
      done
    done
    if ((${#others[@]})); then
      warn "Membros de sudo/admin SEM chave SSH válida (perderão acesso por senha): ${others[*]}"
      confirm "Desabilitar senha mesmo assim?" || die "Abortado para não bloquear: ${others[*]}."
    fi
  fi
  if ((!RESTRICT_SSH_USERS)); then info "AllowUsers NÃO será definido (qualquer usuário com credencial válida continua autorizado). Use --restrict-ssh-users para restringir."; fi

  local ch=0 sock_ch=0
  gen_sshd_fragment "$pass_auth" "$root_val" | { :; }
  install_atomic /etc/ssh/sshd_config.d/00-hardening.conf 0600 root:root pv_sshd < <(gen_sshd_fragment "$pass_auth" "$root_val")
  ch=$FILE_CHANGED

  if ((SSH_PORT_SET)) && ssh_uses_socket && [[ "$SSH_PORT" != "${CURRENT_SSH_PORTS[0]}" ]]; then
    info "ssh.socket ativo: a porta é definida pelo socket; criando override ListenStream=$SSH_PORT."
    install_atomic /etc/systemd/system/ssh.socket.d/override.conf 0644 root:root <<EOF
[Socket]
ListenStream=
ListenStream=$SSH_PORT
EOF
    sock_ch=$FILE_CHANGED
  fi

  if ((ch == 0 && sock_ch == 0)); then info "SSH já está conforme; nenhum reinício necessário."; return 0; fi
  if ((DRY_RUN)); then info "[dry-run] validaria com sshd -t / sshd -T e reiniciaria o SSH"; return 0; fi

  if ! sshd -t; then
    restore_file /etc/ssh/sshd_config.d/00-hardening.conf
    if ((sock_ch)); then restore_file /etc/systemd/system/ssh.socket.d/override.conf; fi
    die "sshd -t falhou com a nova configuração; arquivos restaurados. SSH NÃO foi reiniciado."
  fi
  if ! verify_sshd_effective "$pass_auth" "$root_val"; then
    restore_file /etc/ssh/sshd_config.d/00-hardening.conf
    if ((sock_ch)); then restore_file /etc/systemd/system/ssh.socket.d/override.conf; fi
    die "Configuração efetiva (sshd -T) difere do esperado (algum drop-in anterior vence?); restaurado."
  fi
  info "sshd -t e sshd -T OK. Reiniciando SSH (sessões existentes são preservadas)."
  systemctl daemon-reload
  if ssh_uses_socket; then systemctl restart ssh.socket; systemctl try-restart ssh.service
  else systemctl restart ssh.service; fi

  local i ok=0
  for i in 1 2 3 4 5 6 7 8 9 10; do if port_listening "$TARGET_SSH_PORT"; then ok=1; break; fi; sleep 1; done
  if ((!ok)); then
    err "SSH não está escutando na porta $TARGET_SSH_PORT após reinício. Revertendo TUDO agora."
    /bin/bash "$BACKUP_DIR/rollback.sh" || true
    die "Rollback imediato executado. Veja $BACKUP_DIR/rollback.log"
  fi
  applied "SSH endurecido e escutando na porta $TARGET_SSH_PORT (teste uma NOVA sessão antes de confirmar)"
}

# -------------- PASSO 14 - FAIL2BAN -----
step_fail2ban() {
  info "== Fail2ban =="
  local ign=("127.0.0.1/8" "::1") cip i
  ign+=("${F2B_IGNORE[@]}")
  if ((F2B_IGNORE_CURRENT)); then
    cip="$(current_client_ip)"
    if [[ -n "$cip" ]]; then ign+=("$cip"); warn "fail2ban ignorará o IP atual ($cip): atacante nesse IP não será banido."; fi
  fi
  local banline=""
  if [[ -f /etc/fail2ban/action.d/ufw.conf ]] && ! step_enabled ufw && false; then banline=""; fi
  if [[ -f /etc/fail2ban/action.d/ufw.conf ]] && step_enabled ufw; then banline="banaction = ufw"; fi
  install_atomic /etc/fail2ban/jail.d/99-hardening.local 0644 root:root <<EOF
[DEFAULT]
ignoreip = $(join_by ' ' "${ign[@]}")
bantime = 1h
findtime = 10m
maxretry = 4
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 4w
${banline}

[sshd]
enabled = true
port = $TARGET_SSH_PORT
EOF
  if ((DRY_RUN)); then info "[dry-run] validaria com fail2ban-client -t e reiniciaria"; return 0; fi
  if ! fail2ban-client -t >/dev/null 2>&1; then
    restore_file /etc/fail2ban/jail.d/99-hardening.local
    fail_soft "fail2ban-client -t falhou com a nova configuração (arquivo restaurado)."
    return 0
  fi
  systemctl enable fail2ban >/dev/null 2>&1
  if ((FILE_CHANGED)) || ! systemctl is-active --quiet fail2ban; then systemctl restart fail2ban; fi
  local ok=0
  for i in 1 2 3 4 5 6 7 8 9 10; do if fail2ban-client ping >/dev/null 2>&1; then ok=1; break; fi; sleep 1; done
  if ((ok)) && fail2ban-client status sshd >/dev/null 2>&1; then applied "Fail2ban ativo com jail sshd (porta $TARGET_SSH_PORT)"
  else fail_soft "Fail2ban não respondeu (ping/status sshd). Verifique: journalctl -u fail2ban"; fi
}

# -------------- PASSO 15 - SYSCTL -----
detect_router_roles() {
  ROLES=()
  local s
  for s in docker containerd kubelet libvirtd; do if systemctl is-active --quiet "$s" 2>/dev/null; then ROLES+=("$s"); fi; done
  if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]]; then ROLES+=("ip_forward=1 já ativo"); fi
  if have ip; then
    if ip -o link show type wireguard 2>/dev/null | grep -q .; then ROLES+=(wireguard); fi
    if ip -o link show type bridge 2>/dev/null | grep -q .; then ROLES+=(bridge); fi
    if ip -o tuntap show 2>/dev/null | grep -q .; then ROLES+=(tun/tap); fi
  fi
  if systemctl list-units --state=active --no-legend 'openvpn*' 2>/dev/null | grep -q .; then ROLES+=(openvpn); fi
}

step_sysctl() {
  info "== Kernel (sysctl) =="
  detect_router_roles
  local router=0
  if ((${#ROLES[@]})); then router=1; info "Papel de roteamento/virtualização detectado: $(join_by , "${ROLES[@]}") (send_redirects e ip_forward preservados)."; fi
  if ((SYSCTL_NOFWD && router)); then die "--disable-ip-forward recusado: detectado $(join_by , "${ROLES[@]}")."; fi

  local table=(
    "net.ipv4.conf.all.accept_source_route|eq|0|base" "net.ipv4.conf.default.accept_source_route|eq|0|base"
    "net.ipv4.conf.all.accept_redirects|eq|0|base" "net.ipv4.conf.default.accept_redirects|eq|0|base"
    "net.ipv4.conf.all.secure_redirects|eq|0|base" "net.ipv4.conf.default.secure_redirects|eq|0|base"
    "net.ipv4.conf.all.send_redirects|eq|0|router" "net.ipv4.conf.default.send_redirects|eq|0|router"
    "net.ipv4.conf.all.log_martians|eq|1|base" "net.ipv4.conf.default.log_martians|eq|1|base"
    "net.ipv4.icmp_echo_ignore_broadcasts|eq|1|base" "net.ipv4.icmp_ignore_bogus_error_responses|eq|1|base"
    "net.ipv4.tcp_syncookies|eq|1|base" "net.ipv4.tcp_rfc1337|eq|1|base"
    "net.ipv6.conf.all.accept_redirects|eq|0|base" "net.ipv6.conf.default.accept_redirects|eq|0|base"
    "net.ipv6.conf.all.accept_source_route|eq|0|base" "net.ipv6.conf.default.accept_source_route|eq|0|base"
    "kernel.randomize_va_space|ge|2|base" "kernel.kptr_restrict|ge|2|base" "kernel.dmesg_restrict|ge|1|base"
    "kernel.yama.ptrace_scope|ge|1|base" "kernel.unprivileged_bpf_disabled|ge|1|base" "net.core.bpf_jit_harden|ge|2|base"
    "fs.protected_hardlinks|ge|1|base" "fs.protected_symlinks|ge|1|base" "fs.suid_dumpable|eq|0|base"
    "kernel.perf_event_paranoid|ge|3|ext" "kernel.kexec_load_disabled|ge|1|ext" "kernel.sysrq|eq|0|ext"
    "dev.tty.ldisc_autoload|eq|0|ext" "vm.unprivileged_userfaultfd|eq|0|ext" "vm.mmap_min_addr|ge|65536|ext"
    "fs.protected_fifos|ge|2|ext" "fs.protected_regular|ge|2|ext"
    "net.ipv4.conf.all.rp_filter|eq|1|rpf" "net.ipv4.conf.default.rp_filter|eq|1|rpf"
    "net.ipv6.conf.all.accept_ra|eq|0|ra" "net.ipv6.conf.default.accept_ra|eq|0|ra"
    "net.ipv4.ip_forward|eq|0|fwd"
  )
  local entry key mode val cat path cur target lines="" applied_keys=() n_skip=0
  local prev_file=""
  if ((!DRY_RUN)); then prev_file="$BACKUP_DIR/sysctl_prev"; : >>"$prev_file"; chmod 600 "$prev_file"; fi
  for entry in "${table[@]}"; do
    IFS='|' read -r key mode val cat <<<"$entry"
    case "$cat" in
      ext) if ((!SYSCTL_EXT)); then continue; fi ;;
      rpf) if ((!SYSCTL_STRICT_RPF)); then continue; fi ;;
      ra)  if ((!SYSCTL_NORA)); then continue; fi ;;
      fwd) if ((!SYSCTL_NOFWD)); then continue; fi ;;
      router) if ((router)); then continue; fi ;;
      *) : ;;
    esac
    path="/proc/sys/${key//.//}"
    if [[ ! -e "$path" ]]; then info "sysctl $key: inexistente neste kernel (ignorado, não é erro)."; n_skip=$((n_skip + 1)); continue; fi
    cur="$(<"$path")"
    if ! [[ "$cur" =~ ^-?[0-9]+$ ]]; then warn "sysctl $key: valor atual não numérico ('$cur'); ignorado."; continue; fi
    target="$val"
    if [[ "$mode" == "ge" ]] && ((cur > val)); then target="$cur"; fi
    lines+="${key} = ${target}"$'\n'
    applied_keys+=("$key=$target")
    if [[ "$cur" != "$target" ]]; then
      if ((DRY_RUN)); then info "[dry-run] sysctl -w $key=$target (atual: $cur)"
      else
        printf '%s=%s\n' "$key" "$cur" >>"$prev_file"
        if ! sysctl -q -w "$key=$target" >/dev/null 2>&1; then fail_soft "sysctl $key=$target falhou (parâmetro existe: erro real)."; fi
      fi
    fi
  done
  if [[ -z "$lines" ]]; then info "Nenhum parâmetro sysctl aplicável."; return 0; fi
  install_atomic /etc/sysctl.d/99-hardening.conf 0644 root:root <<EOF
${lines}
EOF
  if ((!DRY_RUN)); then
    local kv bad=0
    for kv in "${applied_keys[@]}"; do
      key="${kv%%=*}"; target="${kv#*=}"
      if [[ "$(<"/proc/sys/${key//.//}")" != "$target" ]]; then warn "sysctl $key efetivo difere de $target"; bad=1; fi
    done
    if ((bad == 0)); then applied "sysctl: ${#applied_keys[@]} parâmetros aplicados e verificados ($n_skip inexistentes ignorados)"; fi
  fi
  info "Impactos: ptrace_scope>=1 limita gdb/strace attach; log_martians gera logs; accept_redirects=0 pode afetar hosts que dependem de ICMP redirect."
}

# -------------- PASSO 16 - MODULOS -----
step_modules() {
  info "== Módulos de kernel =="
  local mods=() m
  if ((!NO_DEFAULT_MODULES)); then mods+=(cramfs freevxfs jffs2 hfs hfsplus dccp rds tipc); fi
  mods+=("${BLOCK_MODULES[@]}")
  if ((BLOCK_USB)); then
    if confirm "Bloquear usb-storage impede pendrives/HDs USB (mouse/teclado não são afetados)."; then mods+=(usb-storage); else skipped "bloqueio usb-storage"; fi
  fi
  if ((BLOCK_TB)); then
    if confirm "Bloquear thunderbolt desabilita periféricos Thunderbolt."; then mods+=(thunderbolt); else skipped "bloqueio thunderbolt"; fi
  fi
  local final=() loaded
  loaded="$(lsmod | awk 'NR>1{print $1}')"
  for m in "${mods[@]}"; do
    if grep -qx -- "${m//-/_}" <<<"$loaded"; then warn "Módulo '$m' está CARREGADO/em uso: não será bloqueado."; continue; fi
    final+=("$m")
  done
  if ((${#final[@]} == 0)); then info "Nenhum módulo a bloquear."; return 0; fi
  local body="" 
  for m in "${final[@]}"; do body+="install ${m} /bin/false"$'\n'"blacklist ${m}"$'\n'; done
  install_atomic /etc/modprobe.d/99-hardening.conf 0644 root:root <<EOF
${body}
EOF
  if ((FILE_CHANGED && !DRY_RUN)); then
    if ! modprobe -c >/dev/null 2>&1; then restore_file /etc/modprobe.d/99-hardening.conf; fail_soft "modprobe -c reportou erro; arquivo restaurado."; return 0; fi
    applied "Módulos bloqueados (valem para próximos carregamentos): ${final[*]}"
    REBOOT_NEEDED=1
  fi
}

# -------------- PASSO 17 - AUTENTICACAO E SUDO -----
pv_sudoers() { if have visudo; then visudo -cf "$1" >/dev/null; fi; }

step_auth() {
  info "== Autenticação / sudo / contas =="
  info "login.defs afeta principalmente NOVOS usuários; contas existentes NÃO são alteradas."
  install_atomic /etc/login.defs 0644 root:root < <(awk '
    BEGIN { n=split("PASS_MAX_DAYS=365,PASS_MIN_DAYS=1,PASS_WARN_AGE=14,UMASK=027", a, ","); for(i=1;i<=n;i++){ split(a[i], p, "="); want[p[1]]=p[2] } }
    { if (($1 in want) && $0 !~ /^[[:space:]]*#/) { printf "%s\t%s\n", $1, want[$1]; seen[$1]=1 } else print }
    END { for (k in want) if (!(k in seen)) printf "%s\t%s\n", k, want[k] }' /etc/login.defs)

  install_atomic /etc/security/pwquality.conf.d/99-hardening.conf 0644 root:root <<'EOF'
minlen = 14
minclass = 3
maxrepeat = 3
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
EOF

  local sudo_extra=""
  if ((SUDO_IO_LOG)); then
    warn "sudo log_input/log_output PODE REGISTRAR SENHAS, tokens e dados sensíveis digitados em comandos sudo."
    if confirm "Habilitar log de entrada/saída do sudo em /var/log/sudo-io (modo 700)?"; then
      sudo_extra=$'Defaults log_input, log_output\nDefaults iolog_dir=/var/log/sudo-io\n'
      if ((!DRY_RUN)); then install -d -m 700 -o root -g root /var/log/sudo-io; fi
    else skipped "sudo I/O log"; fi
  fi
  install_atomic /etc/sudoers.d/99-hardening 0440 root:root pv_sudoers <<EOF
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults passwd_tries=3
${sudo_extra}
EOF
  if ((FILE_CHANGED && !DRY_RUN)); then
    if ! visudo -c >/dev/null 2>&1; then restore_file /etc/sudoers.d/99-hardening; die "visudo -c falhou; drop-in sudoers restaurado."; fi
  fi
  install_atomic /etc/logrotate.d/ubuntu-hardening-sudo 0644 root:root <<'EOF'
/var/log/sudo.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    create 0600 root root
}
EOF

  if ((TMOUT_SECS > 0)); then
    install_atomic /etc/profile.d/99-hardening-tmout.sh 0644 root:root <<EOF
case \$- in *i*) TMOUT=${TMOUT_SECS}; export TMOUT ;; esac
EOF
  fi

  if have passwd; then info "Estado da conta root: $(passwd -S root 2>/dev/null || echo desconhecido) (não alterado; evita perder acesso administrativo)."; fi
}

step_autoupdates() {
  info "== Atualizações automáticas =="
  if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
    info "20auto-upgrades já existe: preservado."
  else
    install_atomic /etc/apt/apt.conf.d/20auto-upgrades 0644 root:root <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  fi
}

# -------------- PASSO 18 - ARQUIVOS E PERMISSOES -----
fix_perm() {
  local p="$1" mode="$2" own="$3" cm co
  if [[ ! -e "$p" ]]; then info "Inexistente, ignorado: $p"; return 0; fi
  cm="$(stat -c %a -- "$p")"; co="$(stat -c %U:%G -- "$p")"
  if [[ "$cm" == "$mode" && "$co" == "$own" ]]; then return 0; fi
  info "Permissão $p: $co $cm -> $own $mode"
  if ((DRY_RUN)); then return 0; fi
  printf '%s|%s|%s\n' "$p" "$cm" "$co" >>"$BACKUP_DIR/perms_prev"
  chown "$own" -- "$p"; chmod "$mode" -- "$p"
  APPLIED+=("permissão: $p -> $own $mode")
}

step_files() {
  info "== Arquivos e permissões =="
  if ((!DRY_RUN)); then : >>"$BACKUP_DIR/perms_prev"; chmod 600 "$BACKUP_DIR/perms_prev"; fi
  fix_perm /etc/passwd 644 root:root
  fix_perm /etc/group 644 root:root
  fix_perm /etc/shadow 640 root:shadow
  fix_perm /etc/gshadow 640 root:shadow
  fix_perm /etc/crontab 600 root:root
  info "Diretórios cron.* e /boot/grub/grub.cfg NÃO são alterados (padrão da distro; evita quebrar gestão/boot)."

  if ((CRON_ALLOW)); then
    if [[ -f /etc/cron.allow ]]; then warn "/etc/cron.allow já existe: preservado."
    else
      local users=(root) f
      users+=("${ADMIN_USERS[@]}")
      if [[ -d /var/spool/cron/crontabs ]]; then
        while IFS= read -r f; do users+=("$f"); done < <(find /var/spool/cron/crontabs -maxdepth 1 -type f -printf '%f\n')
      fi
      info "cron.allow incluirá: $(printf '%s\n' "${users[@]}" | sort -u | paste -sd, -)"
      if confirm "Criar /etc/cron.allow (usuários fora da lista perdem cron)?"; then
        install_atomic /etc/cron.allow 0640 root:root < <(printf '%s\n' "${users[@]}" | sort -u)
      else skipped "cron.allow"; fi
    fi
  fi

  if ((HARDEN_SHM)); then harden_shm; fi
  if ((COLLECT_REPORTS)); then collect_reports; fi
}

pv_fstab() { findmnt --verify --tab-file "$1" >/dev/null 2>&1; }

harden_shm() {
  local cur; cur="$(findmnt -no OPTIONS /dev/shm 2>/dev/null)" || cur=""
  if [[ ",$cur," == *",noexec,"* && ",$cur," == *",nosuid,"* && ",$cur," == *",nodev,"* ]]; then info "/dev/shm já está com nodev,nosuid,noexec."; return 0; fi
  if grep -Eq '^[^#]*[[:space:]]/dev/shm[[:space:]]' /etc/fstab; then
    warn "/etc/fstab já tem entrada para /dev/shm: não alterada automaticamente (edite manualmente)."; return 0
  fi
  warn "noexec em /dev/shm quebra aplicações que executam código de memória compartilhada (alguns navegadores, JITs, bancos)."
  if ! confirm "Aplicar nodev,nosuid,noexec em /dev/shm?"; then skipped "hardening /dev/shm"; return 0; fi
  if ((!DRY_RUN)); then printf '%s' "$cur" >"$BACKUP_DIR/shm_prev"; fi
  install_atomic /etc/fstab 0644 root:root pv_fstab < <(cat /etc/fstab; printf '%s\n' "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0")
  if ((!DRY_RUN)); then
    if mount -o remount,nodev,nosuid,noexec /dev/shm && [[ ",$(findmnt -no OPTIONS /dev/shm)," == *",noexec,"* ]]; then
      applied "/dev/shm remontado com nodev,nosuid,noexec"
    else
      restore_file /etc/fstab; mount -o "remount,$cur" /dev/shm || true
      fail_soft "Remount de /dev/shm falhou; fstab restaurado."
    fi
  fi
}

collect_reports() {
  local out="$LOG_DIR/reports"
  if ((DRY_RUN)); then info "[dry-run] geraria relatórios SUID/SGID e world-writable em $out"; return 0; fi
  install -d -m 700 -o root -g root "$out"
  if ! find / -xdev -type f -perm -0002 >"$out/world-writable-$TS.txt" 2>"$out/find-errors-$TS.txt"; then
    warn "find (world-writable) reportou erros; veja $out/find-errors-$TS.txt"
  fi
  if ! find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>>"$out/find-errors-$TS.txt" | sort >"$out/suid-sgid-baseline-$TS.txt"; then
    warn "find (SUID/SGID) reportou erros; veja $out/find-errors-$TS.txt"
  fi
  chmod 600 "$out"/*
  applied "Relatórios gerados em $out (modo 600)"
}

# -------------- PASSO 19 - SERVICOS -----
step_services() {
  info "== Serviços =="
  local c; local cand=(avahi-daemon cups cups-browsed rpcbind snmpd smbd nmbd nfs-server bluetooth ModemManager vsftpd slapd isc-dhcp-server)
  for c in "${cand[@]}"; do
    if systemctl cat "$c.service" >/dev/null 2>&1; then
      info "Candidato encontrado (NÃO alterado): $c -> enabled=$(systemctl is-enabled "$c.service" 2>/dev/null || true) active=$(systemctl is-active "$c.service" 2>/dev/null || true)"
    fi
  done
  if ((${#DISABLE_SERVICES[@]} == 0)); then info "Nenhum --disable-service informado: nenhum serviço será alterado."; return 0; fi
  local s en act msk deps
  if ((!DRY_RUN)); then : >>"$BACKUP_DIR/services_state"; chmod 600 "$BACKUP_DIR/services_state"; fi
  for s in "${DISABLE_SERVICES[@]}"; do
    if ! systemctl cat "$s" >/dev/null 2>&1; then warn "Serviço '$s' não existe: ignorado."; continue; fi
    en="$(systemctl is-enabled "$s" 2>/dev/null || true)"
    act="$(systemctl is-active "$s" 2>/dev/null || true)"
    deps="$(systemctl list-dependencies --reverse --plain "$s" 2>/dev/null | sed -n '2,12p' | paste -sd' ' -)" || deps=""
    info "'$s': enabled=$en active=$act | dependentes: ${deps:-nenhum}"
    if ! confirm "Desabilitar e parar '$s'?"; then skipped "serviço $s"; continue; fi
    msk=0
    if ((MASK_SERVICES)) && confirm "MASCARAR '$s' (impede qualquer início, inclusive por dependência)?"; then msk=1; fi
    if ((!DRY_RUN)); then printf '%s|%s|%s|%s\n' "$s" "$en" "$act" "$msk" >>"$BACKUP_DIR/services_state"; fi
    run systemctl disable --now "$s"
    if ((msk)); then run systemctl mask "$s"; fi
    SERVICES_CHANGED+=("$s")
    applied "Serviço desabilitado: $s$([[ $msk -eq 1 ]] && echo ' (mascarado)')"
  done
}

# -------------- PASSO 20 - AUDITD -----
audit_syscalls_valid() {
  local arch="$1" out="" s; shift
  for s in "$@"; do if ausyscall --arch "$arch" --exact "$s" >/dev/null 2>&1; then out+="${out:+,}$s"; fi; done
  printf '%s' "$out"
}
emit_watch() { if [[ -e "$1" ]] && ! grep -qF -- "-w $1 " <<<"$AUDIT_EXISTING"; then printf '%s\n' "-w $1 -p $2 -k $3"; fi; }
emit_sc() {
  local a="$1" m="$2" key="$3" filt="$4" list; shift 4
  list="$(audit_syscalls_valid "$m" "$@")"
  if [[ -n "$list" ]]; then printf '%s\n' "-a always,exit -F arch=$a $filt -S $list -k $key"; fi
}

gen_audit_rules() {
  printf '%s\n' "## Gerado por ubuntu-hardening.sh $VERSION em $TS" \
    "## Não contém -D/-b/-f: regras da distro e de agentes de segurança são preservadas."
  local p
  for p in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/security/opasswd; do emit_watch "$p" wa identity; done
  for p in /etc/sudoers /etc/sudoers.d/; do emit_watch "$p" wa scope; done
  for p in /etc/pam.d/ /etc/security/ /etc/login.defs; do emit_watch "$p" wa pam; done
  for p in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/; do emit_watch "$p" wa sshd; done
  for p in /var/log/lastlog /var/log/faillog; do emit_watch "$p" wa logins; done
  for p in /var/run/utmp /var/log/wtmp /var/log/btmp; do emit_watch "$p" wa session; done
  for p in /etc/crontab /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ /var/spool/cron/; do emit_watch "$p" wa cron; done
  for p in /etc/systemd/system/ /usr/lib/systemd/system/; do emit_watch "$p" wa systemd; done
  for p in /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d/; do emit_watch "$p" wa ld_preload; done
  for p in /etc/hosts /etc/hostname /etc/netplan/; do emit_watch "$p" wa network; done
  for p in /etc/ufw/ /etc/fail2ban/ /etc/apparmor/ /etc/apparmor.d/ /etc/audit/; do emit_watch "$p" wa sec_tamper; done
  for p in /etc/sysctl.conf /etc/sysctl.d/ /etc/modprobe.d/; do emit_watch "$p" wa kernel_cfg; done
  for p in /sbin/insmod /sbin/rmmod /sbin/modprobe; do emit_watch "$p" x modules; done
  emit_watch /etc/localtime wa time-change
  local machine arches=() pair a m
  machine="$(uname -m)"
  case "$machine" in
    x86_64) arches=(b64:x86_64 b32:i386) ;;
    aarch64) arches=(b64:aarch64) ;;
    *) printf '%s\n' "## Arquitetura $machine sem regras de syscall (não validada)" ;;
  esac
  if have ausyscall; then
    local AU="-F auid>=1000 -F auid!=4294967295"
    for pair in "${arches[@]}"; do
      a="${pair%%:*}"; m="${pair##*:}"
      emit_sc "$a" "$m" time-change "" adjtimex settimeofday clock_settime
      emit_sc "$a" "$m" system-locale "" sethostname setdomainname
      emit_sc "$a" "$m" modules "" init_module finit_module delete_module
      emit_sc "$a" "$m" tracing "" ptrace
      emit_sc "$a" "$m" priv_esc "-C euid!=uid -F euid=0" execve
      emit_sc "$a" "$m" mounts "$AU" mount
      emit_sc "$a" "$m" delete "$AU" unlinkat renameat renameat2
      emit_sc "$a" "$m" perm_mod "$AU" fchmod fchmodat fchown fchownat setxattr lsetxattr fsetxattr removexattr
    done
  else
    printf '%s\n' "## ausyscall ausente: regras de syscall omitidas"
  fi
}

audit_enabled_flag() { auditctl -s 2>/dev/null | awk '$1=="enabled"{print $2}'; }

set_auditd_conf() {
  awk -v k="$1" -v v="$2" '$1==k && $2=="=" {print k " = " v; f=1; next} {print} END{if(!f) print k " = " v}' /etc/audit/auditd.conf
}

step_auditd() {
  info "== auditd =="
  if ((!DRY_RUN)); then need_cmds auditctl augenrules; elif ! have auditctl; then info "[dry-run] auditd ainda não instalado; regras seriam geradas após a instalação."; fi
  AUDIT_EXISTING="$(find /etc/audit/rules.d -maxdepth 1 -name '*.rules' ! -name '99-hardening.rules' ! -name '99-zz-finalize.rules' -exec cat {} + 2>/dev/null)" || AUDIT_EXISTING=""
  install_atomic /etc/audit/rules.d/99-hardening.rules 0640 root:root < <(gen_audit_rules)
  local rules_ch=$FILE_CHANGED fin_ch=0 conf_ch=0

  if ((AUDIT_TUNE)) && [[ -f /etc/audit/auditd.conf ]]; then
    install_atomic /etc/audit/auditd.conf 0640 root:root < <(set_auditd_conf max_log_file 50 | awk -v k=num_logs '$1==k && $2=="=" {print k " = 10"; f=1; next} {print} END{if(!f) print k " = 10"}')
    conf_ch=$FILE_CHANGED
  fi
  info "Mantidos: space_left_action/admin_space_left_action da distro (sem halt automático)."

  if ((AUDIT_IMMUTABLE)); then
    if confirm "'-e 2' torna as regras IMUTÁVEIS até o reboot (alterá-las exige reiniciar)."; then
      install_atomic /etc/audit/rules.d/99-zz-finalize.rules 0640 root:root <<'EOF'
-e 2
EOF
      fin_ch=$FILE_CHANGED; REBOOT_NEEDED=1
    else skipped "auditd imutável"; fi
  fi

  if ((DRY_RUN)); then info "[dry-run] rodaria: augenrules --check; augenrules --load; auditctl -s/-l"; return 0; fi
  if ((conf_ch)); then systemctl reload auditd || warn "Reload do auditd falhou; reinicie o serviço manualmente."; fi
  systemctl enable --now auditd >/dev/null 2>&1
  if ((rules_ch == 0 && fin_ch == 0)); then info "Regras do auditd já aplicadas."; else
    if [[ "$(audit_enabled_flag)" == "2" ]]; then
      warn "auditd está IMUTÁVEL (enabled=2): novas regras só serão carregadas após reboot."; REBOOT_NEEDED=1
    else
      info "augenrules --check (apenas informa se as regras compiladas divergem; NÃO valida sintaxe):"
      augenrules --check 2>&1 | tee -a "$LOG_FILE" || true
      if augenrules --load >>"$LOG_FILE" 2>&1; then
        applied "Regras do auditd carregadas (preservando regras existentes)"
      else
        restore_file /etc/audit/rules.d/99-hardening.rules
        if ((fin_ch)); then restore_file /etc/audit/rules.d/99-zz-finalize.rules; fi
        augenrules --load >>"$LOG_FILE" 2>&1 || warn "Recarga das regras anteriores também falhou."
        fail_soft "augenrules --load falhou com as novas regras (restauradas). Veja $LOG_FILE"
        return 0
      fi
    fi
  fi
  auditctl -s | tee -a "$LOG_FILE" >/dev/null
  if auditctl -l 2>/dev/null | grep -q 'No rules'; then fail_soft "auditctl -l: nenhuma regra carregada."; fi
  info "Recomendado (manual): kernel param audit=1 no GRUB para auditar processos desde o boot."
}

# -------------- PASSO 21 - APPARMOR -----
aa_mode() {
  aa-status 2>/dev/null | awk -v p="$1" '
    /profiles are in enforce mode/ {m="enforce"; next}
    /profiles are in complain mode/ {m="complain"; next}
    /^[0-9]+ (profiles|processes)/ {m=""}
    m && $1==p {print m; exit}'
}

step_apparmor() {
  info "== AppArmor =="
  if ! have aa-status; then info "aa-status ausente; apenas verificação informativa."; return 0; fi
  if aa-status --enabled 2>/dev/null; then info "AppArmor habilitado no kernel."; else warn "AppArmor NÃO está habilitado no kernel/serviço."; fi
  info "Perfis NÃO são promovidos em massa; use --apparmor-complain/--apparmor-enforce por perfil, revisando logs."
  local p prev
  if ((!DRY_RUN)); then : >>"$BACKUP_DIR/apparmor_prev"; chmod 600 "$BACKUP_DIR/apparmor_prev"; fi
  for p in "${AA_COMPLAIN[@]}" "${AA_ENFORCE[@]}"; do
    if [[ ! -e "$p" ]]; then warn "Programa/perfil '$p' não existe: ignorado."; continue; fi
    prev="$(aa_mode "$p")"
    if [[ -z "$prev" ]]; then warn "Perfil '$p' não encontrado no aa-status (sem estado anterior p/ rollback): ignorado."; continue; fi
    if ((!DRY_RUN)); then printf '%s|%s\n' "$p" "$prev" >>"$BACKUP_DIR/apparmor_prev"; fi
    if [[ " ${AA_COMPLAIN[*]} " == *" $p "* ]]; then
      run aa-complain "$p"
      if ((!DRY_RUN)) && [[ "$(aa_mode "$p")" != complain ]]; then fail_soft "aa-complain $p não refletiu no aa-status."; else applied "AppArmor: $p -> complain"; fi
    else
      run aa-enforce "$p"
      if ((!DRY_RUN)) && [[ "$(aa_mode "$p")" != enforce ]]; then fail_soft "aa-enforce $p não refletiu no aa-status."; else applied "AppArmor: $p -> enforce"; fi
    fi
  done
  if ((!DRY_RUN)); then aa-status 2>&1 | sed -n '1,6p' | tee -a "$LOG_FILE" >/dev/null; fi
}

# -------------- PASSO 22 - LOGGING E TEMPO -----
step_logging() {
  info "== journald =="
  install_atomic /etc/systemd/journald.conf.d/99-hardening.conf 0644 root:root <<'EOF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=1G
MaxRetentionSec=6month
EOF
  if ((FILE_CHANGED && !DRY_RUN)); then
    systemctl restart systemd-journald
    systemctl is-active --quiet systemd-journald || fail_soft "systemd-journald não voltou após reinício."
  fi
  warn "Logs locais não resistem a comprometimento do host: envie auditd/auth/ufw/fail2ban/sudo ao SIEM (Wazuh/Elastic). ForwardToSyslog não foi alterado (evita duplicação)."
}

step_time() {
  info "== Sincronização de tempo =="
  local active=() s sync
  for s in chrony chronyd systemd-timesyncd ntp ntpd openntpd; do if systemctl is-active --quiet "$s" 2>/dev/null; then active+=("$s"); fi; done
  if ((${#active[@]} == 0)); then warn "Nenhum serviço de tempo ativo: logs/SIEM sem hora confiável. Instale chrony ou habilite systemd-timesyncd."; fi
  if ((${#active[@]} > 1)); then warn "Múltiplos serviços de tempo ativos (${active[*]}): conflito."; fi
  sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" || sync="desconhecido"
  info "Serviços de tempo ativos: ${active[*]:-nenhum} | NTPSynchronized=$sync (nada foi alterado)"
  if [[ "$sync" == "no" ]]; then warn "Relógio NÃO sincronizado."; fi
}

# -------------- PASSO 23 - OPCIONAIS -----
step_aide() {
  info "== AIDE =="
  if ! confirm "AIDE vai registrar o estado ATUAL como baseline: só vale se este host for sabidamente ÍNTEGRO."; then skipped "AIDE"; return 0; fi
  if [[ -s /var/lib/aide/aide.db ]]; then warn "Baseline do AIDE já existe: não sobrescrita."; return 0; fi
  run aideinit -y -f
  if ((!DRY_RUN)); then
    if [[ ! -s /var/lib/aide/aide.db.new ]]; then fail_soft "AIDE: baseline não foi criada."; return 0; fi
    install -m 600 -o root -g root /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    sha256sum /var/lib/aide/aide.db >"$STATE_DIR/aide.db.sha256"
    install -m 600 /var/lib/aide/aide.db "$BACKUP_DIR/aide.db"
    applied "AIDE: baseline criada (aide.db + sha256 em $STATE_DIR)"
    warn "Copie /var/lib/aide/aide.db e o .sha256 para armazenamento EXTERNO somente-leitura; baseline local pode ser adulterada."
  fi
}

step_rkhunter() {
  info "== rkhunter =="
  if ((RKH_UPDATE)); then
    if ((DRY_RUN)); then info "[dry-run] rkhunter --update (acesso externo)"; else
      local rc=0; rkhunter --update >>"$LOG_FILE" 2>&1 || rc=$?
      if ((rc == 1)); then fail_soft "rkhunter --update falhou (rc=1)."; else info "rkhunter --update concluído (rc=$rc)."; fi
    fi
  fi
  if confirm "rkhunter --propupd registra propriedades ATUAIS como legítimas (não prova que o host está limpo)."; then
    run rkhunter --propupd
    applied "rkhunter: baseline de propriedades registrada"
  else skipped "rkhunter --propupd"; fi
}

step_lynis() {
  info "== Lynis (somente leitura) =="
  if ((DRY_RUN)); then info "[dry-run] lynis audit system --quick"; return 0; fi
  if lynis audit system --quick --no-colors --logfile "$LOG_DIR/lynis-$TS.log" --report-file "$LOG_DIR/lynis-report-$TS.dat" >"$LOG_DIR/lynis-$TS.out" 2>&1; then
    chmod 600 "$LOG_DIR"/lynis-*"$TS"*; applied "Lynis executado: $LOG_DIR/lynis-report-$TS.dat"
  else fail_soft "Lynis retornou erro; veja $LOG_DIR/lynis-$TS.out"; fi
}

# -------------- PASSO 24 - VERIFICACAO E RESUMO -----
post_checks() {
  if ((DRY_RUN)); then return 0; fi
  info "== Verificações finais =="
  sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|allowusers|allowtcpforwarding) ' | tee -a "$LOG_FILE" >/dev/null
  if port_listening "$TARGET_SSH_PORT"; then info "SSH escutando em $TARGET_SSH_PORT."; else fail_soft "SSH NÃO está escutando em $TARGET_SSH_PORT!"; fi
}

print_list() {
  local -n _arr="$2"
  printf '\n%s (%d):\n' "$1" "${#_arr[@]}"
  if ((${#_arr[@]})); then printf '  - %s\n' "${_arr[@]}"; else printf '  (nenhum)\n'; fi
}

print_summary() {
  local rc="$1"
  printf '\n==================== RESUMO (%s) — código de saída %s ====================\n' "$([[ $DRY_RUN -eq 1 ]] && echo DRY-RUN || echo APLICADO)" "$rc"
  print_list "Alterações aplicadas" APPLIED
  print_list "Ignoradas/puladas" SKIPPED
  print_list "Avisos" WARNINGS
  print_list "Falhas" FAILURES
  print_list "Portas liberadas no UFW" PORTS_OPENED
  print_list "Serviços alterados" SERVICES_CHANGED
  printf '\nBackup: %s\nLog: %s\nReboot necessário: %s\n' "${BACKUP_DIR:-n/a}" "$LOG_FILE" "$([[ $REBOOT_NEEDED -eq 1 ]] && echo SIM || echo não)"
  if [[ -f "$STATE_DIR/pending" ]]; then
    cat <<EOF

ROLLBACK AUTOMÁTICO ATIVO (em ~${ROLLBACK_MINUTES} min tudo será revertido!)
  1) Abra uma NOVA sessão SSH e teste (porta $TARGET_SSH_PORT, sudo, serviços).
  2) Se estiver tudo OK:      sudo $SELF confirm
  3) Para reverter agora:     sudo $SELF rollback
EOF
  fi
  cat <<'EOF'

Comandos de validação pós-execução:
  sudo sshd -t && sudo sshd -T | grep -Ei '^(port|permitrootlogin|passwordauthentication|allowusers|ciphers|macs|kexalgorithms) '
  sudo ss -tlnp | grep -E 'sshd|ssh'
  sudo ufw status verbose && sudo ufw show added
  sudo fail2ban-client ping && sudo fail2ban-client status sshd
  sudo sysctl -a 2>/dev/null | grep -E 'kptr_restrict|dmesg_restrict|accept_redirects|ptrace_scope'
  sudo auditctl -s && sudo auditctl -l | head -n 30
  sudo aa-status | head -n 20
  sudo visudo -c && sudo systemctl is-active auditd fail2ban ufw apparmor
  timedatectl show -p NTPSynchronized --value
  sudo lynis audit system --quick
EOF
}

# -------------- PASSO 25 - SUBCOMANDOS -----
read_pending() {
  [[ -f "$STATE_DIR/pending" ]] || die "Nenhum rollback pendente em $STATE_DIR/pending."
  P_UNIT="$(sed -n 's/^UNIT=//p' "$STATE_DIR/pending")"
  P_BDIR="$(sed -n 's/^BACKUP_DIR=//p' "$STATE_DIR/pending")"
  [[ "$P_UNIT" =~ ^ubuntu-hardening-rollback-[0-9]{8}-[0-9]{6}$ ]] || die "Arquivo pending corrompido (UNIT)."
  [[ "$P_BDIR" =~ ^/var/backups/ubuntu-hardening-[0-9]{8}-[0-9]{6}$ ]] || die "Arquivo pending corrompido (BACKUP_DIR)."
}

cmd_confirm() {
  [[ $EUID -eq 0 ]] || die "Execute como root (sudo)."
  need_cmds systemctl sshd ss
  read_pending
  local ok=0 p
  while IFS= read -r p; do if port_listening "$p"; then ok=1; fi; done < <(effective_ssh_ports)
  if ((!ok && !FORCE)); then die "SSH não está escutando em nenhuma porta configurada. Corrija ou use --force (o rollback continuará agendado até lá)."; fi
  systemctl stop "$P_UNIT.timer"
  if systemctl is-active --quiet "$P_UNIT.timer"; then die "Não foi possível parar $P_UNIT.timer."; fi
  rm -f "$STATE_DIR/pending"
  log "Hardening CONFIRMADO; rollback automático cancelado. Backup mantido em $P_BDIR."
  info "Se alterou a porta SSH, remova as regras UFW antigas: sudo ufw status numbered; sudo ufw delete N"
}

cmd_rollback() {
  [[ $EUID -eq 0 ]] || die "Execute como root (sudo)."
  need_cmds systemctl flock
  exec {LOCK_FD}>"$LOCK_FILE"
  flock -n "$LOCK_FD" || die "Outra execução em andamento."
  local bdir="$RB_BACKUP_DIR"
  if [[ -f "$STATE_DIR/pending" ]]; then
    read_pending
    if [[ -z "$bdir" ]]; then bdir="$P_BDIR"; fi
    systemctl stop "$P_UNIT.timer" 2>/dev/null || warn "Timer $P_UNIT já inativo."
  fi
  [[ -n "$bdir" ]] || die "Sem rollback pendente; informe --backup-dir /var/backups/ubuntu-hardening-<ts>."
  [[ -x "$bdir/rollback.sh" ]] || die "$bdir/rollback.sh não encontrado/executável."
  confirm "Reverter TODAS as alterações registradas em $bdir?" || die "Cancelado."
  /bin/bash "$bdir/rollback.sh"
}

# -------------- PASSO 26 - EXECUCAO PRINCIPAL -----
main() {
  parse_args "$@"
  case "$SUBCMD" in
    confirm) cmd_confirm; return 0 ;;
    rollback) cmd_rollback; return 0 ;;
    *) : ;;
  esac
  preflight
  WORK_DIR="$(mktemp -d /tmp/ubuntu-hardening.XXXXXX)"
  if ((!DRY_RUN)); then backup_init; fi
  SUMMARY_READY=1
  print_plan
  confirm "Aplicar o plano acima neste servidor?" || die "Cancelado (nada foi alterado). Use --yes para automação ou --dry-run para simular."
  if ((!DRY_RUN)); then record_state; fi

  step_packages
  schedule_rollback

  if step_enabled banners; then step_banners; fi
  if step_enabled ufw; then step_ufw; fi
  if step_enabled ssh; then step_ssh; fi
  if step_enabled fail2ban; then step_fail2ban; fi
  if step_enabled sysctl; then step_sysctl; fi
  if step_enabled modules; then step_modules; fi
  if step_enabled auth; then step_auth; fi
  if step_enabled autoupdates; then step_autoupdates; fi
  if step_enabled files; then step_files; fi
  if step_enabled services; then step_services; fi
  if step_enabled auditd; then step_auditd; fi
  if step_enabled apparmor; then step_apparmor; fi
  if step_enabled logging; then step_logging; fi
  if step_enabled time; then step_time; fi
  if ((WITH_AIDE)); then step_aide; fi
  if ((WITH_RKH)); then step_rkhunter; fi
  if ((WITH_LYNIS)); then step_lynis; fi
  post_checks
  if [[ -f /var/run/reboot-required ]]; then REBOOT_NEEDED=1; fi
  return 0
}

main "$@"

#!/bin/sh
#
# Юнит-тесты разбора серверов из конфига podkop по режимам url, urltest, selector,
# outbound, и того, как синхронизация адреса ведёт себя вне режима url.
#
# Запуск:  sh tests/endpoints_unit.sh [путь-к-podkop-watchdog]
#
# Код вырезается из скрипта по комментариям-границам, как в ddns_unit.sh, и
# гоняется против поддельного uci с таблицей опций в файле.

set -u

WATCHDOG="${1:-$(dirname "$0")/../podkop-watchdog}"
[ -f "$WATCHDOG" ] || { echo "нет файла $WATCHDOG"; exit 2; }

STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/endpoints-unit.XXXXXX") || exit 2
trap 'rm -rf "$STATE_DIR"' EXIT

LOG="$STATE_DIR/log"
log() { echo "[log $1] $2" >> "$LOG"; }
state_get() { v=$(cat "$1" 2>/dev/null); [ -n "$v" ] && echo "$v" || echo "$2"; }
state_put() { printf '%s\n' "$2" > "$1"; }
run_bounded() { shift; "$@"; }
uci_has_foreign_changes() { [ -n "$(uci changes "$1" 2>/dev/null)" ]; }
mark_restart() { :; }
wait_for_chain() { return 0; }
RECOVERY_EVERY=300; SETTLE_RESTART=60
F_MODE="$STATE_DIR/mode"; F_FAILS="$STATE_DIR/fails"
F_BACKOFF="$STATE_DIR/backoff"; F_RECOVERY="$STATE_DIR/recovery"

# Поддельный uci: строки "podkop.<секция>.<опция>=<значение>", списки через пробел,
# как их отдаёт настоящий `uci get`. Понимает ровно то, что зовёт код.
DB="$STATE_DIR/db"
STAGED=0
uci() {
    [ "$1" = "-q" ] && shift
    case "$1" in
        changes) [ "$STAGED" = 1 ] && echo "podkop.main.proxy_config_type='urltest'"; return 0 ;;
        get)
            v=$(awk -v k="$2" 'index($0, k "=") == 1 { print substr($0, length(k) + 2); f=1 } END { exit !f }' "$DB") || return 1
            printf '%s\n' "$v" ;;
        show)
            awk -F. '{ print $1 "." $2 "=section" }' "$DB" | sort -u ;;
        *) return 1 ;;
    esac
}

cut_range() {
    sed -n "/^$1/,/^$2/p" "$WATCHDOG" > "$3"
    [ -s "$3" ] || { echo "не нашёл '$1' в $WATCHDOG: границы переименовали?"; exit 2; }
}
cut_range '# Ссылки на серверы, которыми секция может пользоваться СЕЙЧАС' '# Сводка "жив ли прямой интернет"' "$STATE_DIR/ep.sh"
cut_range '# --- синхронизация адреса прокси с доменом' '# --- точка входа' "$STATE_DIR/ddns.sh"
grep -q '^proxy_endpoints()' "$STATE_DIR/ep.sh" || { echo "в вырезке нет proxy_endpoints"; exit 2; }
grep -q '^ddns_section_active()' "$STATE_DIR/ddns.sh" || { echo "в вырезке нет ddns_section_active"; exit 2; }
UNINSTALL="$(dirname "$WATCHDOG")/uninstall.sh"
# От ps_parse до конца left_on_ip_from_memory: разбор строки, валидаторы, признак
# активной секции и сборщик LEFT_ON_IP идут в файле подряд.
sed -n '/^ps_parse()/,/^restore_domains()/p' "$UNINSTALL" | sed '$d' > "$STATE_DIR/un.sh"
for f in ps_section_active left_on_ip_from_memory ps_is_ipv4_literal; do
    grep -q "^$f()" "$STATE_DIR/un.sh" || { echo "в вырезке из $UNINSTALL нет $f"; exit 2; }
done
. "$STATE_DIR/ep.sh"
. "$STATE_DIR/ddns.sh"
. "$STATE_DIR/un.sh"
DDNS_CONF="$STATE_DIR/conf"; DDNS_BAK="$STATE_DIR/bak"; F_DDNS_MOAN="$STATE_DIR/moaned"

SYNCED="$STATE_DIR/synced"
ddns_sync_one() { echo "$1 $2" >> "$SYNCED"; }

fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
check() { [ "$2" = "$3" ] && ok "$1" || bad "$1: ждал '$3', получил '$2'"; }
db() { printf '%s\n' "$@" > "$DB"; }

L1='vless://00000000-0000-4000-8000-000000000001@a.example.com:443?security=reality&sni=x.ru#one'
L2='vless://00000000-0000-4000-8000-000000000002@b.example.com:8443?security=reality&sni=y.ru#two'
L3='vless://00000000-0000-4000-8000-000000000003@9.9.9.9:443?type=tcp#three'
SS='ss://YWVzLTI1Ni1nY206c2VjcmV0cGFzc3dvcmQ=#legacy'

# --- выбор ссылок по режиму ---
db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=url" "podkop.main.proxy_string=$L3"
check "url: один сервер из proxy_string" "$(proxy_endpoints_line)" "9.9.9.9:443"

db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" \
   "podkop.main.urltest_proxy_links=$L1 $L2" "podkop.main.proxy_string=$L3"
check "urltest: оба сервера из списка, старая proxy_string не в счёт" "$(proxy_endpoints_line)" "a.example.com:443, b.example.com:8443"

db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=selector" \
   "podkop.main.selector_proxy_links=$L2 $L3" "podkop.main.urltest_proxy_links=$L1"
check "selector: свой список, чужой urltest не в счёт" "$(proxy_endpoints_line)" "b.example.com:8443, 9.9.9.9:443"

db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=outbound" "podkop.main.proxy_string=$L3"
proxy_endpoints >/dev/null && bad "outbound: адреса быть не должно" || ok "outbound: адреса нет"
check "outbound: строка status падает в запасной вариант" "$(proxy_endpoints_line || echo NONE)" "NONE"

db "podkop.main.connection_type=vpn" "podkop.main.proxy_config_type=url" "podkop.main.proxy_string=$L3"
proxy_endpoints >/dev/null && bad "vpn: proxy_string не читается" || ok "vpn: proxy_string не читается"

db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=url" "podkop.main.proxy_string=$L3" \
   "podkop.extra.connection_type=proxy" "podkop.extra.proxy_config_type=urltest" "podkop.extra.urltest_proxy_links=$L1 $L2"
check "две секции: все серверы" "$(proxy_endpoints | sort | tr '\n' ' ')" "9.9.9.9:443 a.example.com:443 b.example.com:8443 "

db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" "podkop.main.urltest_proxy_links=$SS $L1"
out=$(proxy_endpoints_line)
check "ss:// без @ помечен, секрет не печатается" "$out" "(ссылка не разобрана), a.example.com:443"
case "$out" in *YWVz*) bad "секрет ss:// в выводе" ;; esac

db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" "podkop.main.urltest_proxy_links=$SS"
proxy_endpoints >/dev/null && bad "только ss://: адреса нет" || ok "только ss://: адреса нет"
check "только ss://: status пишет не распознан" "$(proxy_endpoints_line || echo NONE)" "NONE"

db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" \
   "podkop.main.urltest_proxy_links=$L1 $L2" "podkop.main.urltest_fallback_links=$L3"
check "urltest: запасные серверы тоже" "$(proxy_endpoints_line)" "a.example.com:443, b.example.com:8443, 9.9.9.9:443"

db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" "podkop.main.urltest_proxy_links=$L1 $L1 $L2"
check "повторы убраны" "$(proxy_endpoints_line)" "a.example.com:443, b.example.com:8443"

# --- проба: хоть один живой ---
ALIVE=""
curl() { for a in "$@"; do case "$a" in https://*) case " $ALIVE " in *" ${a#https://} "*) return 0 ;; esac ;; esac; done; return 7; }
db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" "podkop.main.urltest_proxy_links=$L1 $L2"
ALIVE="b.example.com:8443"; PROXY_ALIVE=""
probe_proxy_host && check "первый мёртв, второй жив: ответивший" "$PROXY_ALIVE" "b.example.com:8443" || bad "первый мёртв, второй жив: должна пройти"
ALIVE="a.example.com:443"; PROXY_ALIVE=""
probe_proxy_host && check "первый жив: ответивший" "$PROXY_ALIVE" "a.example.com:443" || bad "первый жив: должна пройти"
ALIVE=""
probe_proxy_host && bad "оба мертвы: должна провалиться" || ok "оба мертвы: провал"
db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" \
   "podkop.main.urltest_proxy_links=$L1" "podkop.main.urltest_fallback_links=$L2"
ALIVE="b.example.com:8443"; PROXY_ALIVE=""
probe_proxy_host && check "основной мёртв, запасной жив" "$PROXY_ALIVE" "b.example.com:8443" || bad "основной мёртв, запасной жив: должна пройти"
db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" "podkop.main.urltest_proxy_links=$L1 $SS"
ALIVE=""; PROXY_ALIVE=""; : > "$LOG"
probe_proxy_host && check "разобранный мёртв, есть неразобранный: вслепую" "$PROXY_ALIVE" "?" || bad "разобранный мёртв, есть неразобранный: должна пройти вслепую"
grep -q 'часть ссылок не разобрана' "$LOG" && ok "неразобранная: строка в журнале" || bad "неразобранная: строки в журнале нет"
db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=outbound"
: > "$LOG"; PROXY_ALIVE=""
probe_proxy_host && check "адреса нет: подъём вслепую" "$PROXY_ALIVE" "?" || bad "адреса нет: должна пройти вслепую"
grep -q 'вслепую' "$LOG" && ok "адреса нет: строка в журнале" || bad "адреса нет: строки в журнале нет"

# --- синхронизация адреса: перебор режимов ---
for mode in url urltest selector outbound ""; do
    for ct in proxy vpn; do
        db "podkop.main.connection_type=$ct" "podkop.main.proxy_config_type=$mode"
        if ddns_section_active main; then got=1; else got=0; fi
        want=0; [ "$ct/$mode" = "proxy/url" ] && want=1
        check "ddns_section_active $ct/$mode" "$got" "$want"
        if ps_section_active main; then got=1; else got=0; fi
        check "uninstall ps_section_active $ct/$mode" "$got" "$want"
    done
done

# urltest, proxy_string нет, память есть: память удаляется, синхронизации нет
db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" "podkop.main.urltest_proxy_links=$L1 $L2"
echo "main frnx.example.com 9.9.9.9" > "$DDNS_CONF"; : > "$SYNCED"; : > "$LOG"
handle_ddns
check "urltest без proxy_string: память стёрта" "$(cat "$DDNS_CONF")" ""
check "urltest без proxy_string: синхронизации нет" "$(cat "$SYNCED")" ""
grep -q 'забываю домен frnx.example.com' "$LOG" && ok "urltest без proxy_string: строка в журнале" || bad "нет строки про забытый домен"

# urltest, старая proxy_string уцелела: память остаётся, синхронизации нет
db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" \
   "podkop.main.urltest_proxy_links=$L1 $L2" "podkop.main.proxy_string=$L3"
echo "main frnx.example.com 9.9.9.9" > "$DDNS_CONF"; : > "$SYNCED"
handle_ddns
check "urltest со старой proxy_string: память цела" "$(cat "$DDNS_CONF")" "main frnx.example.com 9.9.9.9"
check "urltest со старой proxy_string: синхронизации нет" "$(cat "$SYNCED")" ""

# несохранённые правки в podkop: память не трогается вовсе
db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" "podkop.main.urltest_proxy_links=$L1"
echo "main frnx.example.com 9.9.9.9" > "$DDNS_CONF"; STAGED=1
handle_ddns
STAGED=0
check "черновик в uci: память цела" "$(cat "$DDNS_CONF")" "main frnx.example.com 9.9.9.9"

# черновик в режиме url: синхронизации нет, но в журнале есть подсказка про /overlay
db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=url" "podkop.main.proxy_string=$L3"
: > "$SYNCED"; : > "$LOG"; rm -f "$F_DDNS_MOAN"; STAGED=1
handle_ddns
STAGED=0
check "черновик в url: синхронизации нет" "$(cat "$SYNCED")" ""
grep -q "df /overlay" "$LOG" && ok "черновик в url: подсказка в журнале" || bad "черновик в url: журнал молчит"

# черновик без дела для синхронизации: журнал пуст
for cfg in "podkop.main.connection_type=vpn" "podkop.main.connection_type=proxy podkop.main.proxy_config_type=urltest podkop.main.urltest_proxy_links=$L1"; do
    # shellcheck disable=SC2086
    db $cfg
    rm -f "$DDNS_CONF" "$F_DDNS_MOAN"; : > "$LOG"; STAGED=1
    handle_ddns
    STAGED=0
    check "черновик без дела ($(echo "$cfg" | cut -c1-40)): журнал пуст" "$(cat "$LOG")" ""
done

# деинсталлятор: наш IP в неактивной proxy_string обязан попасть в LEFT_ON_IP
db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" \
   "podkop.main.urltest_proxy_links=$L1" "podkop.main.proxy_string=$L3"
echo "main frnx.example.com 9.9.9.9" > "$DDNS_CONF"; LEFT_ON_IP=""
left_on_ip_from_memory
check "uninstall: IP в неактивной секции назван" "$LEFT_ON_IP" "frnx.example.com"

# url: синхронизация идёт как раньше
db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=url" "podkop.main.proxy_string=$L3"
echo "main frnx.example.com 9.9.9.9" > "$DDNS_CONF"; : > "$SYNCED"
handle_ddns
check "url: синхронизация вызвана" "$(cat "$SYNCED")" "main frnx.example.com"

# секция без памяти в urltest: ничего не пишется
db "podkop.main.connection_type=proxy" "podkop.main.proxy_config_type=urltest" "podkop.main.urltest_proxy_links=$L1"
: > "$DDNS_CONF"; : > "$LOG"
handle_ddns
check "urltest без памяти: журнал пуст" "$(cat "$LOG")" ""

echo "---"
[ "$fail" = 0 ] && echo "ВСЕ ТЕСТЫ ПРОШЛИ" || { echo "ЕСТЬ ПРОВАЛЫ"; exit 1; }

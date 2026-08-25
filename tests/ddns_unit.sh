#!/bin/sh
#
# Юнит-тесты синхронизации адреса прокси с доменом.
#
# Запуск:  sh tests/ddns_unit.sh [путь-к-podkop-watchdog]
#
# Код синка НЕ копируется сюда, а вырезается из настоящего скрипта по маркерам
# секций и подключается через `.`. Раньше здесь лежала копия, и она уже успела
# разойтись с оригиналом — комментарии про то, где живёт домен, отличались
# дословно. Копия тестов, отставшая от кода, хуже отсутствия тестов: она
# продолжает показывать зелёный на функциях, которых в бою уже нет.

set -u

WATCHDOG="${1:-$(dirname "$0")/../podkop-watchdog}"
[ -f "$WATCHDOG" ] || { echo "нет файла $WATCHDOG"; exit 2; }

STATE_DIR=/tmp/ddns-unit
rm -rf "$STATE_DIR"; mkdir -p "$STATE_DIR"

# Заглушки того, на что синк опирается, но что к его логике не относится.
# Определяются ДО подключения секции: она их только зовёт, но не объявляет.
log() { echo "[log $1] $2" >&2; }
state_get() { v=$(cat "$1" 2>/dev/null); [ -n "$v" ] && echo "$v" || echo "$2"; }
state_put() { printf '%s\n' "$2" > "$1"; }
run_bounded() { limit="$1"; shift; "$@"; }
uci() { return 1; }
uci_has_foreign_changes() { return 1; }
mark_restart() { :; }
wait_for_chain() { return 0; }
RECOVERY_EVERY=300; SETTLE_RESTART=60
F_MODE="$STATE_DIR/mode"; F_FAILS="$STATE_DIR/fails"
F_BACKOFF="$STATE_DIR/backoff"; F_RECOVERY="$STATE_DIR/recovery"

# Вырезаем секцию синка из настоящего скрипта. Границы — те же комментарии-
# разделители, что и в файле; если их переименуют, тест упадёт здесь с внятной
# ошибкой, а не пройдёт вхолостую на пустом наборе функций.
SECTION="$STATE_DIR/section.sh"
sed -n '/^# --- синхронизация адреса прокси с доменом/,/^# --- точка входа/p' \
    "$WATCHDOG" > "$SECTION"
[ -s "$SECTION" ] || { echo "не нашёл секцию синка в $WATCHDOG — маркеры переименовали?"; exit 2; }
grep -q '^ddns_valid_public_ipv4()' "$SECTION" \
    || { echo "вырезанная секция не содержит ddns_valid_public_ipv4 — границы съехали"; exit 2; }

. "$SECTION"

# Пути памяти уводим в песочницу: секция задала боевые /etc/podkop-ddns.*
DDNS_CONF="$STATE_DIR/conf"
DDNS_BAK="$STATE_DIR/bak"
F_DDNS_MOAN="$STATE_DIR/moaned"

echo "тестирую $WATCHDOG"
echo "секция вырезана: $(wc -l < "$SECTION") строк"
echo "---"

fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }

# --- валидатор IP: образцы с известным ответом ---
for ip in 9.9.9.9 1.1.1.1 77.88.8.8 8.8.8.8 223.255.255.255; do
    ddns_valid_public_ipv4 "$ip" && ok "valid: $ip" || bad "valid: $ip должен пройти"
done
for ip in "" 0.0.0.0 10.1.2.3 127.0.0.1 169.254.1.1 192.168.1.10 198.18.0.5 198.19.255.1 \
          172.16.0.1 172.31.255.254 100.64.0.1 100.127.255.255 224.0.0.1 255.255.255.255 \
          "1.2.3" "1.2.3.4.5" "1.2.3.256" "a.b.c.d" "1..2.3" ".1.2.3" "1.2.3." "1.2.3.4 " ; do
    ddns_valid_public_ipv4 "$ip" && bad "invalid: '$ip' не должен проходить" || ok "invalid: '$ip'"
done
# не-приватные из тех же /8, что и приватные диапазоны
for ip in 172.15.0.1 172.32.0.1 100.63.0.1 100.128.0.1 198.17.0.1 198.20.0.1 11.0.0.1; do
    ddns_valid_public_ipv4 "$ip" && ok "valid: $ip" || bad "valid: $ip должен пройти"
done

# --- парсер URL ---
U='vless://00000000-0000-4000-8000-000000000000@9.9.9.9:443?encryption=none&flow=xtls-rprx-vision&sni=www.example.com&spx=%2F&type=tcp#tag'
if ddns_parse_url "$U"; then
    [ "$DDNS_HOST" = "9.9.9.9" ] && ok "parse host" || bad "parse host: '$DDNS_HOST'"
    [ "$DDNS_PORT" = "443" ] && ok "parse port" || bad "parse port: '$DDNS_PORT'"
    R="${DDNS_PRE}@1.2.3.4:${DDNS_PORT}${DDNS_POST}"
    E=$(printf '%s' "$U" | sed 's|@9\.9\.9\.9:|@1.2.3.4:|')
    [ "$R" = "$E" ] && ok "rebuild lossless" || { bad "rebuild"; echo "  got: $R"; echo "  exp: $E"; }
else bad "parse: не разобрал корректный url"; fi

U2='vless://uuid@vpn.example.com:443?type=tcp#tag'
ddns_parse_url "$U2" && [ "$DDNS_HOST" = "vpn.example.com" ] && ok "parse domain host" || bad "parse domain host"

for u in 'novless' 'vless://nohost' 'vless://u@host' 'vless://u@[::1]:443?x' 'vless://u@a@b:443' 'vless://u@host:abc?x'; do
    ddns_parse_url "$u" && bad "parse: '$u' должен отказать (host=$DDNS_HOST)" || ok "parse reject: '$u'"
done

# --- списки ---
L="1.1.1.1
2.2.2.2"
ddns_list_has "$L" "2.2.2.2" && ok "list_has hit" || bad "list_has hit"
ddns_list_has "$L" "3.3.3.3" && bad "list_has miss" || ok "list_has miss"
ddns_list_has "$L" "" && bad "list_has empty" || ok "list_has empty"
I=$(ddns_intersect "$L" "2.2.2.2
9.9.9.9")
[ "$I" = "2.2.2.2" ] && ok "intersect" || bad "intersect: '$I'"
I2=$(ddns_intersect "$L" "8.8.8.8")
[ -z "$I2" ] && ok "intersect empty" || bad "intersect empty: '$I2'"

# --- новое: IPv4-литерал vs домен ---
for x in 9.9.9.9 1.2.3.4 0.0.0.0 255.255.255.255; do
    ddns_is_ipv4_literal "$x" && ok "literal: $x" || bad "literal: $x должен считаться IP"
done
for x in vpn.example.com example.com 1.2.3 1.2.3.4.5 "a.b.c.d" "" "1.2.3.4x"; do
    ddns_is_ipv4_literal "$x" && bad "literal: '$x' не IP" || ok "not literal: '$x'"
done

# --- новое: валидатор домена ---
for d in vpn.example.com sub.example.co.uk my-vpn.example.com; do
    ddns_valid_domain "$d" && ok "domain: $d" || bad "domain: $d должен пройти"
done
for d in "" "-evil.com" "localhost" 'a$(touch /tmp/X).ru' "a b.ru" "ev'il.ru" "домен.рф" "x.ru
"; do
    ddns_valid_domain "$d" && bad "domain: '$d' не должен проходить" || ok "domain reject: '$d'"
done

# --- память conf: три поля ---
DDNS_CONF="$STATE_DIR/conf"
rm -f "$DDNS_CONF"
ddns_conf_get main >/dev/null 2>&1 && bad "conf_get без файла" || ok "conf_get без файла"
ddns_conf_set main vpn.example.com - >/dev/null 2>&1
[ "$(ddns_conf_get main)" = "vpn.example.com" ] && ok "conf_set домен" || bad "conf_set домен"
[ -z "$(ddns_conf_get_ip main)" ] && ok "прочерк = IP не наш" || bad "прочерк: '$(ddns_conf_get_ip main)'"
grep -q "^#" "$DDNS_CONF" && ok "шапка" || bad "шапки нет"
ddns_conf_set main vpn.example.com 9.9.9.9 >/dev/null 2>&1
[ "$(ddns_conf_get_ip main)" = "9.9.9.9" ] && ok "наш IP записан" || bad "наш IP: '$(ddns_conf_get_ip main)'"
[ "$(grep -c "^main " "$DDNS_CONF")" = "1" ] && ok "дубля нет" || bad "дубль main"
ddns_conf_set other other.example.org 1.2.3.4 >/dev/null 2>&1
[ "$(ddns_conf_get_ip main)" = "9.9.9.9" ] && ok "чужая секция цела" || bad "чужая секция затёрта"
[ "$(ddns_conf_get other)" = "other.example.org" ] && ok "вторая секция" || bad "вторая секция"
before=$(cat "$DDNS_CONF"); ddns_conf_set main vpn.example.com 9.9.9.9 >/dev/null 2>&1
[ "$before" = "$(cat "$DDNS_CONF")" ] && ok "повтор не пишет файл" || bad "повтор переписал"
ddns_conf_del main
[ -z "$(ddns_conf_get main)" ] && ok "conf_del удалил" || bad "conf_del не удалил"
[ "$(ddns_conf_get other)" = "other.example.org" ] && ok "conf_del не тронул чужую" || bad "conf_del задел чужую"
ddns_conf_del nosuch; ok "conf_del на отсутствующей не падает"

# --- домен: TLD только из букв (находка ревью №5) ---
for d in 12.34 1.2 999.888 "x.123" "a.b2"; do
    ddns_valid_domain "$d" && bad "domain: '$d' не должен проходить" || ok "domain reject: '$d'"
done


# --- документационные диапазоны (находка шестого ревью) ---
for ip in 192.0.2.5 198.51.100.9 203.0.113.77 192.88.99.1; do
    ddns_valid_public_ipv4 "$ip" && bad "TEST-NET: '$ip' не должен проходить" || ok "TEST-NET reject: $ip"
done
for ip in 192.0.3.5 198.51.101.9 203.0.114.77 192.88.100.1; do
    ddns_valid_public_ipv4 "$ip" && ok "соседний диапазон проходит: $ip" || bad "соседний: $ip должен пройти"
done

echo "---"; [ "$fail" = 0 ] && echo "ВСЕ ТЕСТЫ ПРОШЛИ" || echo "ЕСТЬ ПРОВАЛЫ"
exit "$fail"

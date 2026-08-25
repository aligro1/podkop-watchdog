#!/bin/sh
#
# Установщик podkop-watchdog на роутер с OpenWrt + podkop.
#
#   sh <(wget -O - https://raw.githubusercontent.com/aligro1/podkop-watchdog/main/install.sh)
#
# Ставит сторож, синхронизацию адреса прокси с доменом, переводит DNS на
# шифрованный и переносит кэш rule-set из tmpfs во флеш.
#
# Повторный запуск безопасен и является штатным способом обновиться: строки cron
# и rc.local не задваиваются, уже настроенные значения uci не трогаются.
#
# Перед запуском закрой LuCI: `uci commit` сбрасывает журнал изменений целиком,
# и незакоммиченная правка из открытой веб-формы применится заодно с нашей.
#
# Код возврата: 0 — установлено и цепочка проверена; 1 — установлено, но проверка
# не прошла (смотри лог); 2 — прервались с ошибкой. Двойка НЕ значит «ничего не
# тронуто»: шаги идут по порядку, и падение на пятом оставляет сделанным всё до
# него. Что именно успело примениться, всегда написано в тексте ошибки — читай
# его, а не только код.
#
# Ключи (нужны для неинтерактивной установки, руками обычно не требуются):
#   --dns-server URL   какой DoH использовать, без схемы https://
#   --keep-dns         не трогать настройки DNS вообще
#   --no-restart       не перезапускать podkop (изменения вступят позже)
#   --src ПУТЬ         взять файл podkop-watchdog отсюда, а не качать
#   --yes              не задавать вопросов, брать значения по умолчанию
#
# Всё тело — в функции main, вызов последней строкой файла. Это обязательно при
# запуске через `sh <(wget ...)`: ash исполняет по мере чтения, и оборванная
# закачка выполнила бы половину сценария — например сменила бы DNS, но не
# поставила сам скрипт. С функцией недокачанный файл обрывается внутри её
# определения, до вызова дело не доходит, и не выполняется ничего.

set -u

REPO_RAW="https://raw.githubusercontent.com/aligro1/podkop-watchdog/main"

# Без схемы https:// — так требует валидатор поля в LuCI: он берёт кусок до
# первого '/', и в "https://8.8.8.8/dns-query" ему достаётся "https:", после чего
# поле краснеет и конфигурацию не сохранить. Бэкенд podkop оба варианта
# разбирает одинаково (проверено: host 8.8.8.8, порт 443 по умолчанию, path
# /dns-query), так что теряется только несовместимость с веб-интерфейсом.
# Адрес именно IP, а не имя: иначе podkop подставит bootstrap-резолвер, и
# резолв DNS-сервера снова окажется на пути подъёма туннеля.
DNS_DEFAULT="8.8.8.8/dns-query"
DNS_SERVER=""
KEEP_DNS=0
NO_RESTART=0
ASSUME_YES=0
CACHE_PATH="/etc/sing-box/cache.db"
DEST="/usr/bin/podkop-watchdog"
CRONTAB_FILE="/etc/crontabs/root"
SRC=""
NEED_KB=300          # скрипт 64К + кэш 128К + запас
SETTLE_MAX=90        # сколько ждать подъёма цепочки после рестарта

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ✓ %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*"; }
die()  { printf '\nОШИБКА: %s\n' "$*" >&2; exit 2; }

# Значение у ключа обязано существовать и не быть другим ключом. Без этой
# проверки `shift 2` на последнем аргументе в busybox ash не уменьшает $#,
# и разбор уходит в бесконечный цикл, намертво вешая ssh-сессию.
need_val() {
    [ "$1" -ge 2 ] || die "у ключа $2 нет значения"
    case "$3" in
        --*) die "у ключа $2 вместо значения стоит $3" ;;
        # Пустая строка проходила обе проверки выше, и ключ молча превращался
        # в «не задан»: человек написал --dns-server "", получил дефолтный
        # Google и ни слова об этом.
        "")  die "у ключа $2 пустое значение" ;;
    esac
}

# Есть ли кого спрашивать. При запуске через `sh <(wget -O - URL)` скрипт
# приходит файлом через /dev/fd/N, поэтому stdin остаётся терминалом и вопросы
# работают. А вот через `wget -O - URL | sh` stdin занят самим скриптом: там
# спрашивать нечего, и мы молча берём значения по умолчанию.
interactive() {
    [ "$ASSUME_YES" = "0" ] && [ -t 0 ]
}

# Вопрос с ответом по умолчанию. Возвращает ответ в $ANSWER.
ask() {
    local prompt="$1" default="$2"
    ANSWER="$default"
    interactive || return 0
    printf '%s' "$prompt"
    read -r ANSWER || ANSWER="$default"
    [ -n "$ANSWER" ] || ANSWER="$default"
}

# Да/нет с ответом по умолчанию "да".
confirm() {
    ask "$1 [Y/n] " "y"
    case "$ANSWER" in
        [Nn]*) return 1 ;;
        *) return 0 ;;
    esac
}

# Годится ли строка на роль dns_server для podkop: IPv4-литерал, возможно со
# путём. Имя вместо адреса не берём — podkop подставит bootstrap-резолвер, и
# резолв окажется на пути подъёма туннеля, то есть ровно там, откуда уходили.
valid_dns_server() {
    local host="${1%%/*}" rest o
    case "$1" in
        *://*) return 1 ;;   # схему валидатор LuCI не примет
    esac
    case "$host" in
        ""|*[!0-9.]*) return 1 ;;
        *.*.*.*.*) return 1 ;;
        *.*.*.*) ;;
        *) return 1 ;;
    esac
    rest="$host"
    while [ -n "$rest" ]; do
        case "$rest" in
            *.*) o="${rest%%.*}"; rest="${rest#*.}" ;;
            *)   o="$rest"; rest="" ;;
        esac
        [ -n "$o" ] && [ "${#o}" -le 3 ] || return 1
        o=$(printf '%s' "$o" | sed 's/^0*//'); [ -n "$o" ] || o=0
        [ "$o" -le 255 ] || return 1
    done
    return 0
}

# --- скачивание ------------------------------------------------------------

# wget, а не curl: busybox wget есть всегда, а curl в базовой поставке OpenWrt
# отсутствует и ставится из фидов. Проверка на curl идёт ниже и нужна самому
# сторожу, но качать файл до неё надо чем-то, что точно есть.
# Ограничитель времени для init-скриптов. Раньше `/etc/init.d/podkop restart`
# был единственным вызовом в установщике БЕЗ него — при том что сторож городит
# ради этого целый run_bounded с setsid, потому что на этом же роутере
# init-скрипт наблюдаемо подвисал. Цена зависания здесь выше, чем в стороже:
# DNS и cache_path уже закоммичены, и оборванная в этот момент сессия оставляет
# роутер с новым конфигом и не перезапущенным podkop.
run_bounded() {
    limit="$1"; shift
    setsid "$@" >/dev/null 2>&1 &
    cmd_pid=$!
    setsid sh -c "sleep $limit; kill -9 -$cmd_pid 2>/dev/null || kill -9 $cmd_pid 2>/dev/null" &
    killer_pid=$!
    wait "$cmd_pid" 2>/dev/null
    rc=$?
    kill -9 -"$killer_pid" 2>/dev/null || kill -9 "$killer_pid" 2>/dev/null
    wait "$killer_pid" 2>/dev/null
    return "$rc"
}

# Резолвится ли домен через DNS подкопа именно в FakeIP (198.18.0.0/15).
#
# Это половина проверки, которой в установщике не было вовсе, а без неё вторая
# половина ничего не стоит: cloudflare.com/cdn-cgi/trace отвечает `ip=` и через
# туннель, и напрямую. Если перехват не встал, голый curl проходил бы прямым
# путём, а установщик печатал «цепочка работает» — прямо под выводом status, где
# в тот же момент написано «проксируется: НЕТ».
#
# Берём первый именно IPv4-адрес, а не первый Address подряд: busybox nslookup
# печатает и A, и AAAA, и порядок блоков не гарантирован.
probe_proxied() {
    nslookup "$1" 127.0.0.42 2>/dev/null \
        | sed -n '/^Name:/,$p' \
        | awk '/^Address/ { for (i = 2; i <= NF; i++)
                                if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                                    print $i; exit } }' \
        | grep -q '^198\.18\.'
}

fetch() {
    local url="$1" out="$2"
    if command -v wget >/dev/null 2>&1; then
        wget -q -O "$out" "$url" 2>/dev/null && [ -s "$out" ] && return 0
    fi
    if command -v curl >/dev/null 2>&1; then
        curl -fsS -o "$out" "$url" 2>/dev/null && [ -s "$out" ] && return 0
    fi
    return 1
}

main() {

while [ $# -gt 0 ]; do
    case "$1" in
        --dns-server) need_val "$#" "$1" "${2:-}"; DNS_SERVER="$2"; shift 2 ;;
        --src)        need_val "$#" "$1" "${2:-}"; SRC="$2";        shift 2 ;;
        --keep-dns)   KEEP_DNS=1; shift ;;
        --no-restart) NO_RESTART=1; shift ;;
        --yes|-y)     ASSUME_YES=1; shift ;;
        *) die "неизвестный ключ: $1" ;;
    esac
done

say "Установка podkop-watchdog"
say ""

# --- 1. окружение ----------------------------------------------------------

say "1. Проверяю окружение"

[ "$(id -u)" = "0" ] || die "запускать надо от root"
[ -f /etc/openwrt_release ] || die "это не OpenWrt"

. /etc/openwrt_release 2>/dev/null
ok "${DISTRIB_DESCRIPTION:-OpenWrt} на $(cat /tmp/sysinfo/model 2>/dev/null || echo 'неизвестной железке')"

command -v podkop >/dev/null 2>&1 || die "podkop не установлен — сначала поставь его"
uci -q get podkop.settings >/dev/null 2>&1 || die "нет секции podkop.settings, конфиг podkop не найден"
ok "podkop на месте"

# Список — всё, что реально зовут оба скрипта, а не только то, чего «обычно нет».
# Реальнее прочего отсутствуют curl (в базовой поставке OpenWrt его нет) и setsid
# (нет в 23.05). Но проверять только их мало, и вот почему:
#   setsid — на нём держится ограничитель времени, без него зависший init-скрипт
#     навсегда удержит блокировку, и сторож умрёт молча в той самой аварии;
#   sleep — на нём стоит таймер-убийца внутри ограничителя. Скрипт идёт без
#     `set -e`, поэтому пропавший sleep не остановит выполнение: kill выстрелит
#     мгновенно, и КАЖДЫЙ вызов через ограничитель будет убиваться сразу. Весь
#     механизм таймаутов развалится, а выглядеть это будет как «команда не
#     уложилась в лимит»;
#   ps — на нём определение живого sing-box, а от него проверка после загрузки;
#   date — вся арифметика пауз и backoff.
missing=""
for c in curl setsid flock nslookup uci nft logger awk sed grep crontab ps date \
         head tail tr cat cp mv rm mkdir chmod sleep kill printf \
         id dirname wc df sysupgrade; do
    command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
done
if [ -n "$missing" ]; then
    say ""
    say "Не хватает:$missing"
    case "$missing" in
        *curl*)   say "  curl ставится так:  $(command -v apk >/dev/null 2>&1 && echo 'apk add curl' || echo 'opkg update && opkg install curl')" ;;
    esac
    case "$missing" in
        *setsid*) say "  setsid — applet busybox. В OpenWrt 23.05 его нет, в 24+ есть."
                  say "  Отдельным пакетом не ставится: нужна прошивка посвежее." ;;
    esac
    die "без этого watchdog работать не будет"
fi
ok "все нужные команды на месте"

# Сторож дёргает именно init-скрипты, а не CLI podkop. Бинарь на месте, а
# init-скрипт потерян — редкий, но возможный итог ручной установки; проверка
# окружения прошла бы, а перезапуски молча проваливались бы в рантайме.
# dnsmasq здесь не для полноты: сторож дёргает его init-скрипт в аварийном
# восстановлении DNS — то есть в худший момент, чтобы узнать, что скрипта нет.
for f in /etc/init.d/podkop /etc/init.d/sing-box /etc/init.d/dnsmasq; do
    [ -x "$f" ] || die "$f отсутствует или не исполняем — система собрана нестандартно"
done
ok "init-скрипты podkop, sing-box и dnsmasq на месте"

free_kb=$(df -k /overlay 2>/dev/null | awk 'NR==2 {print $4}')
[ -n "$free_kb" ] || free_kb=$(df -k / | awk 'NR==2 {print $4}')
[ -n "$free_kb" ] || die "не смог определить свободное место"
[ "$free_kb" -ge "$NEED_KB" ] || die "во флеше свободно ${free_kb}К, нужно хотя бы ${NEED_KB}К"
ok "свободно ${free_kb}К во флеше"

# --- 2. файл сторожа -------------------------------------------------------

say ""
say "2. Беру файл сторожа"

# Имя /tmp/podkop-watchdog.new, а не просто podkop-watchdog: каталог с тем же
# именем сторож занимает под своё состояние, и файл, легший ровно на этот путь,
# сломал бы его на первом же тике — mkdir -p упёрся бы в обычный файл.
DL="/tmp/podkop-watchdog.new"

if [ -n "$SRC" ]; then
    [ -f "$SRC" ] || die "указанного --src $SRC нет или это не файл"
else
    for c in "$(dirname "$0")/podkop-watchdog" ./podkop-watchdog "$DL"; do
        [ -f "$c" ] && { SRC="$c"; break; }
    done
fi

if [ -z "$SRC" ]; then
    say "  качаю с $REPO_RAW"
    fetch "$REPO_RAW/podkop-watchdog" "$DL" \
        || die "не смог скачать podkop-watchdog.
       Проверь интернет на роутере. Если прокси сейчас лежит — github уходит
       в туннель, и скачать не получится; подними podkop или положи файл
       руками и запусти с ключом --src ПУТЬ"
    SRC="$DL"
fi

case "$SRC" in
    /tmp/podkop-watchdog)
        die "переложи файл: /tmp/podkop-watchdog — это путь каталога состояния watchdog,
       он там же и создаётся. Годится /tmp/podkop-watchdog.new" ;;
esac

# Скачанное могло оказаться страницей ошибки, отдающей 200: у HTML синтаксис
# оболочки не проверить, но и наших констант в нём нет. Проверяем оба признака.
sh -n "$SRC" || die "$SRC не проходит проверку синтаксиса — файл побился при передаче"
grep -q '^PROBE_HOST=' "$SRC" || die "в $SRC нет строки PROBE_HOST= — это не тот файл"
ok "исходник: $SRC ($(wc -c < "$SRC") байт, синтаксис в порядке)"

# --- 3. цель пробы ---------------------------------------------------------

say ""
say "3. Проверяю цель пробы"

# Проба обязана ходить в домен, который РЕАЛЬНО уходит в туннель — иначе она
# померяет прямой интернет и проспит падение прокси.
# Читаем цель пробы ИЗ САМОГО СКРИПТА, а не держим вторую копию здесь. Иначе,
# поправив PROBE_HOST под свои списки, человек получил бы установщик, который
# проверяет один домен, а сторож следит за другим — и «цепочка работает»
# ничего не значило бы.
PROBE_HOST=$(sed -n 's/^PROBE_HOST="\([^"]*\)".*/\1/p' "$SRC" | head -1)
PROBE_URL=$(sed -n 's/^PROBE_URL="\([^"]*\)".*/\1/p' "$SRC" | head -1)
PROBE_MATCH=$(sed -n 's/^PROBE_MATCH="\([^"]*\)".*/\1/p' "$SRC" | head -1)
[ -n "$PROBE_HOST" ] && [ -n "$PROBE_URL" ] && [ -n "$PROBE_MATCH" ] \
    || die "не смог вычитать PROBE_HOST/PROBE_URL/PROBE_MATCH из $SRC — файл не тот или побился"

lists=""
user_domains=""
for s in $(uci -q show podkop | sed -n 's/^podkop\.\([a-z0-9_]*\)=section$/\1/p'); do
    lists="$lists $(uci -q get "podkop.$s.community_lists" 2>/dev/null)"
    user_domains="$user_domains $(uci -q get "podkop.$s.user_domains" 2>/dev/null)"
done

probe_covered=0
case " $lists " in
    *" cloudflare "*) [ "${PROBE_HOST#*cloudflare}" != "$PROBE_HOST" ] && probe_covered=1 ;;
esac
case " $user_domains " in
    *" $PROBE_HOST "*) probe_covered=1 ;;
esac

PROBE_MEANINGFUL=0
if [ "$probe_covered" = "1" ]; then
    PROBE_MEANINGFUL=1
    ok "$PROBE_HOST покрыт списками podkop — проба осмысленна"
else
    say ""
    warn "$PROBE_HOST не найден ни в community-списках, ни в user_domains."
    warn "Значит проба будет мерить ПРЯМОЙ интернет и падения прокси не заметит,"
    warn "а сторож в таком виде бесполезен."
    say ""
    say "  списки секций:  ${lists:-(пусто)}"
    say "  домены секций:  ${user_domains:-(пусто)}"
    say ""
    say "Впиши домен, который у тебя реально уходит в туннель (Enter — оставить"
    say "$PROBE_HOST как есть и разбираться потом руками):"
    ask "  домен: " ""
    if [ -n "$ANSWER" ]; then
        case "$ANSWER" in
            ""|-*|*[!A-Za-z0-9.-]*) die "'$ANSWER' не похож на доменное имя" ;;
            *.*) ;;
            *) die "'$ANSWER' не похож на доменное имя" ;;
        esac
        NEW_PROBE="$ANSWER"
        PROBE_MEANINGFUL=1
        ok "цель пробы будет заменена на $NEW_PROBE"
    else
        NEW_PROBE=""
        warn "оставляю $PROBE_HOST. Цепочку в конце проверять не буду."
    fi
fi
[ -n "${NEW_PROBE:-}" ] || NEW_PROBE=""

# --- 4. шифрованный DNS ----------------------------------------------------

say ""
say "4. Выбираю шифрованный DNS"

# Открытый udp/53 провайдеры режут выборочно: запрос уходит и не возвращается
# по 10-45 секунд. Ломается в том числе резолв адреса самого прокси-сервера,
# а это уже полное отсутствие интернета.
cur_type=$(uci -q get podkop.settings.dns_type)
cur_srv=$(uci -q get podkop.settings.dns_server)

if [ "$KEEP_DNS" = "1" ]; then
    ok "DNS не трогаю (--keep-dns)"
    DNS_SERVER=""
elif [ -n "$DNS_SERVER" ]; then
    valid_dns_server "$DNS_SERVER" \
        || die "--dns-server '$DNS_SERVER' не годится: нужен IP-адрес без схемы https://, например 8.8.8.8/dns-query"
    ok "DNS задан ключом: $DNS_SERVER"
elif ! interactive; then
    DNS_SERVER="$DNS_DEFAULT"
    ok "терминала нет, беру по умолчанию: $DNS_SERVER"
else
    say "  сейчас:  ${cur_type:-(не задан)} ${cur_srv:-(не задан)}"
    say ""
    say "  1) Google      8.8.8.8/dns-query   (по умолчанию)"
    say "  2) Cloudflare  1.1.1.1/dns-query"
    say "  3) Quad9       9.9.9.9/dns-query"
    say "  4) AdGuard     94.140.14.14/dns-query"
    say "  5) свой"
    say "  6) не трогать DNS"
    say ""
    ask "  выбор [1]: " "1"
    case "$ANSWER" in
        1) DNS_SERVER="8.8.8.8/dns-query" ;;
        2) DNS_SERVER="1.1.1.1/dns-query" ;;
        3) DNS_SERVER="9.9.9.9/dns-query" ;;
        4) DNS_SERVER="94.140.14.14/dns-query" ;;
        5)
            say ""
            say "  Нужен IP-адрес без схемы https://, путь через слэш."
            say "  Например: 76.76.2.11/dns-query"
            ask "  адрес: " ""
            valid_dns_server "$ANSWER" \
                || die "'$ANSWER' не годится: нужен IPv4-адрес без схемы https://"
            DNS_SERVER="$ANSWER"
            ;;
        6) KEEP_DNS=1; DNS_SERVER="" ;;
        *) die "нет такого варианта: $ANSWER" ;;
    esac
    [ "$KEEP_DNS" = "1" ] && ok "DNS не трогаю" || ok "выбран $DNS_SERVER"
fi

# Стоп-вопрос: у человека уже настроен шифрованный DNS, и он не наш. Молча
# затирать чужую осознанную настройку нельзя — в отличие от дефолта podkop,
# которым является doh на 1.1.1.1.
if [ "$KEEP_DNS" = "0" ] && [ -n "$DNS_SERVER" ] \
   && [ -n "$cur_srv" ] && [ "$cur_srv" != "$DNS_SERVER" ] \
   && [ "$cur_type" = "doh" ] && [ "$cur_srv" != "1.1.1.1" ]; then
    say ""
    warn "у тебя уже настроен шифрованный DNS: $cur_type $cur_srv"
    warn "Установка заменит его на $DNS_SERVER."
    if ! confirm "  Менять?"; then
        KEEP_DNS=1
        DNS_SERVER=""
        ok "оставляю $cur_srv"
    fi
fi

# --- 5. что будет сделано --------------------------------------------------

# Чужая незакоммиченная правка. `uci commit` сбрасывает журнал ЦЕЛИКОМ, то есть
# применит и её — в том числе поломанную, из-за которой её и не применили. В
# шапке это описано словами «закрой LuCI», но словам человек не подчиняется, а
# сторож ровно эту проверку уже делает в коде. Здесь ситуация не аварийная,
# поэтому в отличие от сторожа спрашиваем, а не продолжаем молча.
if [ -n "$(uci changes podkop 2>/dev/null)" ]; then
    say ""
    warn "в конфиге podkop есть незакоммиченные правки — похоже, открыт LuCI:"
    uci changes podkop 2>/dev/null | sed 's/^/      /'
    warn "Установка применит их заодно со своими."
    if ! confirm "  Всё равно продолжать?"; then
        say "Отменено. Закрой LuCI (или примени правки) и запусти снова."
        exit 0
    fi
fi

cur_cache=$(uci -q get podkop.settings.cache_path)

say ""
say "5. Что сейчас произойдёт"
say ""
say "  файлы     $DEST"
say "            /etc/podkop-ddns.conf и .bak — память синка, заполнятся сами"
say "  cron      две строки: проверка раз в минуту, синк раз в 5 минут"
say "  rc.local  одна строка: проверка через 120с после загрузки"
say "  sysupgrade.conf — пути, которые должны пережить прошивку"
if [ "$cur_cache" != "$CACHE_PATH" ]; then
    say "  podkop    cache_path: ${cur_cache:-/tmp/sing-box/cache.db} -> $CACHE_PATH"
fi
# Только если действительно меняется: строка вида «doh 8.8.8.8 -> doh 8.8.8.8»
# заставляет человека искать разницу там, где её нет.
if [ "$KEEP_DNS" = "0" ] && [ -n "$DNS_SERVER" ] \
   && { [ "$cur_type" != "doh" ] || [ "$cur_srv" != "$DNS_SERVER" ]; }; then
    say "  podkop    DNS: ${cur_type:-?} ${cur_srv:-?} -> doh $DNS_SERVER"
fi
if [ -n "$NEW_PROBE" ]; then
    say "  сторож    цель пробы: $PROBE_HOST -> $NEW_PROBE"
fi
if [ "$NO_RESTART" = "0" ]; then
    say "  podkop    будет перезапущен, связь ненадолго прервётся"
fi
say ""
say "  Настройки podkop при удалении НЕ откатываются — это описано в README."
say ""
if interactive; then
    confirm "  Продолжать?" || { say "Отменено, ничего не тронуто."; exit 0; }
else
    say "  (терминала нет, ставлю с этими значениями)"
fi

# --- 6. файлы --------------------------------------------------------------

say ""
say "6. Ставлю файлы"

# Цель пробы правим в ЗАКАЧАННОЙ копии, до установки: так на диск ложится уже
# готовый файл, и не бывает промежутка, в котором cron зовёт скрипт со старым
# доменом. Меняем три строки разом — они обязаны быть согласованы.
if [ -n "$NEW_PROBE" ]; then
    sed -e "s|^PROBE_HOST=\".*\"|PROBE_HOST=\"$NEW_PROBE\"|" \
        -e "s|^PROBE_URL=\".*\"|PROBE_URL=\"https://$NEW_PROBE/\"|" \
        -e "s|^PROBE_MATCH=\".*\"|PROBE_MATCH=\"\"|" \
        "$SRC" > "$DEST.new" || die "не смог подставить цель пробы"
    PROBE_HOST="$NEW_PROBE"
    PROBE_URL="https://$NEW_PROBE/"
    PROBE_MATCH=""
    warn "PROBE_MATCH очищен: проверять содержимое ответа для чужого домена"
    warn "нельзя вслепую. Проба теперь считает успехом любой ответ 2xx."
    warn "Если хочешь строгую проверку — впиши строку-признак в $DEST"
else
    cp "$SRC" "$DEST.new" || die "не смог записать $DEST.new"
fi

# Через .new и mv, а не прямым cp поверх живого файла: если запись оборвётся,
# по пути $DEST останется огрызок, который cron будет звать каждую минуту.
if [ -f "$DEST" ]; then
    cp "$DEST" "$DEST.bak" || die "не смог сделать бэкап $DEST"
    ok "прежний скрипт сохранён в $DEST.bak"
fi
sh -n "$DEST.new" || { rm -f "$DEST.new"; die "подготовленный файл не проходит проверку синтаксиса"; }
chmod +x "$DEST.new"
mv "$DEST.new" "$DEST" || die "не смог поставить $DEST"
ok "$DEST установлен"

# --- 7. запуск по расписанию ----------------------------------------------

say ""
say "7. Прописываю запуск"

# `{ crontab -l; echo ... } | crontab -` — известная ловушка: если crontab -l
# упадёт, на вход уйдёт пустота, и ЧУЖИЕ задания root молча исчезнут. Поэтому
# читаем отдельно, проверяем код возврата и держим бэкап.
# $2 — как узнать НАШУ прежнюю строку той же задачи, даже если она записана
# иначе. Раньше сравнивалось только точное совпадение, и это ломало обещание
# «повторный запуск не задваивает»: стоило поменять в новой версии расписание
# или флаг команды, и в crontab оставались обе строки — старая и новая, обе
# исполняемые. Поэтому сначала выкидываем все строки, зовущие эту подкоманду, и
# только потом дописываем нужную.
cron_add() {
    local line="$1" marker="$2" cur rc rest
    cur=$(crontab -l 2>/dev/null); rc=$?
    if [ "$rc" != "0" ] && [ -s "$CRONTAB_FILE" ]; then
        die "crontab -l вернул ошибку, а $CRONTAB_FILE не пуст — не рискую перезаписывать"
    fi
    case "
$cur
" in
        *"
$line
"*) ok "уже в cron: $line"; return 0 ;;
    esac
    rest=$(printf '%s\n' "$cur" | grep -vF "$marker")
    if [ "$rest" != "$cur" ]; then
        warn "нашёл прежнюю строку этой задачи с другими параметрами — заменяю"
    fi
    [ -s "$CRONTAB_FILE" ] && cp "$CRONTAB_FILE" "$CRONTAB_FILE.bak"
    printf '%s\n%s\n' "$rest" "$line" | grep -v '^[[:space:]]*$' | crontab - \
        || die "не смог записать crontab (бэкап: $CRONTAB_FILE.bak)"
    crontab -l 2>/dev/null | grep -qF "$line" || die "строка не появилась в crontab"
    [ "$(crontab -l 2>/dev/null | grep -cF "$marker")" = "1" ] \
        || die "в crontab больше одной строки с '$marker' — разберись руками"
    ok "добавлено в cron: $line"
}
cron_add "* * * * * $DEST check" "$DEST check"
cron_add "*/5 * * * * $DEST ddns" "$DEST ddns"

# Проверка после загрузки — против случая, когда podkop не стартовал, а dnsmasq
# уже смотрит в его мёртвый резолвер (issue itdoginfo/podkop#376). Задержка в
# 120с нужна, чтобы дать podkop честно попробовать подняться самому.
BOOT_LINE="(sleep 120; $DEST boot) &"
if grep -qF "$DEST boot" /etc/rc.local 2>/dev/null; then
    ok "проверка после загрузки уже в /etc/rc.local"
else
    [ -f /etc/rc.local ] || printf 'exit 0\n' > /etc/rc.local
    # Собираем файл заново, а НЕ вставляем строку через sed. В ней есть '&', а в
    # правой части sed-подстановки это «весь совпавший текст»: получалось
    # "(sleep 120; ... boot) exit 0" без амперсанда — синтаксически битый
    # rc.local, из-за которого проверка после загрузки не отрабатывала бы вовсе.
    # Поймано на живом роутере; экранировать здесь ненадёжнее, чем не звать sed.
    {
        grep -v '^[[:space:]]*exit 0[[:space:]]*$' /etc/rc.local
        echo ""
        echo "# podkop-watchdog: проверка после загрузки (issue itdoginfo/podkop#376)"
        echo "$BOOT_LINE"
        echo ""
        echo "exit 0"
    } > /tmp/rc.local.new 2>/dev/null || die "не смог собрать новый /etc/rc.local"
    sh -n /tmp/rc.local.new || die "собранный /etc/rc.local не прошёл проверку синтаксиса, файл не тронут"
    mv /tmp/rc.local.new /etc/rc.local || die "не смог записать /etc/rc.local"
    grep -qF "$DEST boot" /etc/rc.local || die "строка в /etc/rc.local не появилась — проверь файл руками"
    ok "проверка после загрузки добавлена в /etc/rc.local"
fi

# Что переживёт обновление прошивки. Список по умолчанию зависит от сборки,
# поэтому не гадаем, а спрашиваем сам sysupgrade и дописываем недостающее —
# включая crontab и rc.local: сам бинарник без них переживёт апгрейд, но звать
# его будет некому, и заметно это станет только в следующую аварию.
keep=$(sysupgrade -l 2>/dev/null)
# /etc/sing-box/ здесь обязателен: sysupgrade сохраняет НЕ весь /etc, а только
# перечисленное в /lib/upgrade/keep.d и в этом файле (проверено на роутере —
# /etc целиком там не значится). Без строки кэш rule-set пропадёт при первой же
# прошивке, и вернётся холодный старт, ради которого его и переносили из tmpfs.
[ -f /etc/sysupgrade.conf ] || : > /etc/sysupgrade.conf
for f in "$DEST" /etc/podkop-ddns.conf /etc/podkop-ddns.bak /etc/sing-box/ \
         "$CRONTAB_FILE" /etc/rc.local; do
    printf '%s\n' "$keep" | grep -qxF "$f" && continue
    grep -qxF "$f" /etc/sysupgrade.conf 2>/dev/null && continue
    echo "$f" >> /etc/sysupgrade.conf
done
ok "пути внесены в /etc/sysupgrade.conf"

# --- 8. настройки podkop ---------------------------------------------------

say ""
say "8. Правлю настройки podkop"

changed=0

# Кэш rule-set обязан пережить перезагрузку. По умолчанию podkop держит его в
# /tmp, то есть в tmpfs: после каждого ребута кэш пуст, sing-box вынужден качать
# списки синхронно через ещё не поднятый туннель, и при проблемах с DNS это
# кончается крэш-лупом и полным отсутствием интернета.
if [ "$cur_cache" = "$CACHE_PATH" ]; then
    ok "cache_path уже $CACHE_PATH"
else
    mkdir -p "$(dirname "$CACHE_PATH")" || die "не смог создать $(dirname "$CACHE_PATH")"
    uci set podkop.settings.cache_path="$CACHE_PATH"; changed=1
    ok "cache_path: ${cur_cache:-(по умолчанию /tmp/sing-box/cache.db)} -> $CACHE_PATH"
fi

if [ "$KEEP_DNS" = "1" ] || [ -z "$DNS_SERVER" ]; then
    ok "DNS не трогаю"
else
    if [ "$cur_type" = "doh" ] && [ "$cur_srv" = "$DNS_SERVER" ]; then
        ok "DNS уже такой: $cur_srv"
    else
        uci set podkop.settings.dns_type="doh"
        uci set podkop.settings.dns_server="$DNS_SERVER"; changed=1
        ok "DNS: ${cur_type:-?} ${cur_srv:-?} -> doh $DNS_SERVER"
    fi
fi

if [ "$changed" = "1" ]; then
    uci commit podkop || die "uci commit podkop не прошёл"
    ok "настройки записаны"
fi

# --- 9. проверка -----------------------------------------------------------

say ""
say "9. Проверяю"

if [ "$NO_RESTART" = "1" ]; then
    say "  podkop не перезапускаю (--no-restart). Изменения вступят при следующем старте."
elif [ "$changed" = "1" ]; then
    run_bounded 60 /etc/init.d/podkop restart \
        || warn "podkop restart завершился нештатно или не уложился в 60с — смотри проверку ниже"
fi

# Первый запуск синка: если в LuCI стоит домен, здесь он попадёт в память и
# сменится на IP. Под --no-restart пропускаем: синк при смене адреса сам зовёт
# `podkop restart`, то есть обещание «ничего не перезапускаю» было бы нарушено
# ровно в самом частом случае — когда в конфиге домен, а не адрес.
if [ "$NO_RESTART" = "1" ]; then
    say "  синк не запускаю: он может перезапустить podkop. Запусти сам: $DEST ddns"
else
    "$DEST" ddns >/dev/null 2>&1
fi

say ""
"$DEST" status
say ""

rc=0
if [ "$PROBE_MEANINGFUL" = "0" ]; then
    warn "Цепочку не проверяю: проба настроена на $PROBE_HOST, а он тут не"
    warn "проксируется — успех такой пробы ничего не доказал бы. Поправь"
    warn "PROBE_HOST/PROBE_URL/PROBE_MATCH в $DEST и проверь сам."
    rc=1
else
    # Не фиксированная пауза, а ожидание: холодный старт sing-box с пустым кэшем
    # (а после переноса cache_path он именно пуст) на живом роутере не укладывался
    # в 20 секунд. Фиксированная пауза дала бы ложное «проба не прошла».
    waited=0
    while :; do
        # Обе половины разом: домен ушёл в туннель И страница отдалась. Порядок
        # важен — без первой проверки успех второй ничего не доказывает.
        if probe_proxied "$PROBE_HOST"; then
            if [ -n "$PROBE_MATCH" ]; then
                curl -fsS --max-time 10 "$PROBE_URL" 2>/dev/null | grep -q "$PROBE_MATCH" && break
            else
                curl -fsS --max-time 10 -o /dev/null "$PROBE_URL" 2>/dev/null && break
            fi
        fi
        waited=$((waited + 5))
        [ "$waited" -ge "$SETTLE_MAX" ] && { rc=1; break; }
        sleep 5
    done
    if [ "$rc" = "0" ]; then
        ok "цепочка работает: $PROBE_HOST уходит в туннель и отвечает (за ${waited}с)"
        # Сбрасываем состояние сторожа в armed. Если он в этот момент сидел в
        # degraded из-за реальной аварии, то без сброса ближайшие тики ушли бы в
        # handle_degraded и ничего не делали до истечения backoff — до получаса,
        # а в конце окна дали бы лишний start/stop с рывком связи. Только что
        # проверенная цепочка означает, что авария закрыта.
        mkdir -p /tmp/podkop-watchdog 2>/dev/null
        printf 'armed\n' > /tmp/podkop-watchdog/mode 2>/dev/null
        printf '0\n' > /tmp/podkop-watchdog/fails 2>/dev/null
    else
        if probe_proxied "$PROBE_HOST"; then
            warn "Домен пробы уходит в туннель, но страница не отдалась за ${SETTLE_MAX}с:"
            warn "DNS от sing-box жив, а сам туннель — нет. Похоже на проблему с сервером."
        else
            warn "$PROBE_HOST НЕ резолвится в FakeIP за ${SETTLE_MAX}с — podkop не перехватил"
            warn "dnsmasq. Трафик идёт напрямую, прокси не работает."
        fi
        warn "Установка выполнена. Смотри:  logread | grep podkop-watchdog"
        warn "                              $DEST status"
    fi
fi

say ""
if [ "$rc" = "0" ]; then
    say "Готово. Дальше:"
else
    say "Установлено, но НЕ проверено. Дальше:"
fi
say "  состояние   $DEST status"
say "  лог         logread | grep podkop-watchdog"
say "  домен       вписывай обычной ссылкой в LuCI, синк подхватит его сам"
say "  удаление    sh <(wget -O - $REPO_RAW/uninstall.sh)"
exit "$rc"

}

main "$@"

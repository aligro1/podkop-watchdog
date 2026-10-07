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
# Перед запуском примени или отмени непринятые изменения в веб-интерфейсе.
# Наш `uci commit` их не подхватит (rpcd держит правки сессии LuCI в отдельном
# каталоге /var/run/rpcd/uci-<сессия>, а консольный uci работает с /tmp/.uci),
# зато нажатое позже "Save & Apply" перезапишет наши настройки своими.
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
#   --log-level УР     уровень записи сторожа в syslog: off, err, warn или info (журнал он не трогает)
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
CONF="/etc/podkop-watchdog.conf"
LOG_LEVEL=""
CRONTAB_FILE="/etc/crontabs/root"
SRC=""
NEED_KB=700          # скрипт ~120К и его .bak, кэш 128К, журнал ~130К и его .new при обрезке, запас
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
    # Кириллица тут не украшение: вопросы русские, а "нет" и "н" без неё
    # читаются как согласие. Цена ошибки: затёртый чужой DNS и применённые
    # заодно чужие незакоммиченные правки.
    case "$ANSWER" in
        [Nn]*|[Нн]*) return 1 ;;
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

# Значение ключа из файла: $1 это файл, $2 это ключ. Разбор тот же, что в стороже
# (см. conf_get там), и это обязано оставаться так: разъедутся два разбора, и
# установщик будет проверять один сайт, а сторож следить за другим.
conf_get() {
    local raw
    [ -r "$1" ] || return 1
    grep -qE "^[[:space:]]*$2[[:space:]]*=" "$1" 2>/dev/null || return 1
    raw=$(sed -n "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*//p" "$1" 2>/dev/null | head -1)
    case "$raw" in
        \"*) raw="${raw#\"}"; raw="${raw%%\"*}" ;;
        \'*) raw="${raw#\'}"; raw="${raw%%\'*}" ;;
        # Режем только комментарий, а не первый пробел: см. conf_get в стороже.
        *)   raw="${raw%%#*}"; raw="${raw%"${raw##*[! 	]}"}" ;;
    esac
    printf '%s\n' "$raw"
    return 0
}

# Правка одной строки в $CONF. Файл создаётся отдельно, heredoc'ом в шаге 6;
# сюда попадают только уже существующие настройки, так что правка ключом
# --log-level не затирает чужие значения, а обновление вообще не трогает файл.
#
# Значения сюда приходят только после whitelist-проверки (уровень логов) или
# проверки на доменное имя, поэтому спецсимволы sed (&, |, \) в них не бывают.
conf_set() {
    local key="$1" val="$2"
    # Выражение то же, что в conf_get: искать строже, чем читаем, значит однажды
    # дописать второй ключ ниже первого. Сторож возьмёт первый (верхний), а
    # установщик отрапортует про свой, и оба будут думать про разные сайты.
    if grep -qE "^[[:space:]]*$key[[:space:]]*=" "$CONF" 2>/dev/null; then
        sed -E "s|^[[:space:]]*$key[[:space:]]*=.*|$key=\"$val\"|" "$CONF" > "$CONF.new" \
            && mv "$CONF.new" "$CONF" || die "не смог записать $CONF"
    else
        # Без этого дописанная строка склеится с последней: файл правят руками,
        # и завершающий перевод строки в нём есть не всегда. Склейка дала бы
        # PROBE_MATCH=LOG_LEVEL=warn, то есть признак, который в ответе не
        # найдётся никогда, и сторож погасил бы podkop на живом туннеле.
        [ -s "$CONF" ] && [ -n "$(tail -c1 "$CONF")" ] && printf '\n' >> "$CONF"
        printf '%s="%s"\n' "$key" "$val" >> "$CONF" || die "не смог дописать $CONF"
    fi
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
        --log-level)  need_val "$#" "$1" "${2:-}"
                      case "$2" in
                          off|err|warn|info) LOG_LEVEL="$2" ;;
                          *) die "--log-level '$2': нужно off, err, warn или info" ;;
                      esac
                      shift 2 ;;
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

# --- 3. контрольный сайт ---------------------------------------------------

say ""
say "3. Проверяю контрольный сайт"

# Сторож обязан следить за сайтом, который РЕАЛЬНО уходит в туннель, иначе он
# померяет прямой интернет и проспит падение прокси.
#
# Порядок источников важен, и третий в нём не лишний. Сначала $CONF: там лежит
# то, что человек выбрал в прошлый раз. Затем УСТАНОВЛЕННЫЙ сторож: у тех, кто
# ставился до появления конфига, цель вписана прямо в его тело, и без этого шага
# первое же обновление вернуло бы им cloudflare.com, то есть ровно ту потерю
# настройки, ради которой конфиг и заводился. И только потом умолчания из
# скачанного файла. Вторую копию значений здесь не держим: разъедься она со
# скриптом, установщик проверял бы один сайт, а сторож следил за другим, и
# "цепочка работает" ничего не значило бы.
# Умолчания берём из скачанного файла и дальше идём ровно тем же путём, что
# сторож в своём блоке "файл настроек": ключ, которого в конфиге нет, оставляет
# умолчание нетронутым, а явно пустой PROBE_MATCH применяется как значение.
# Любое отступление здесь означает, что установщик проверит цепочку по одному
# адресу, отрапортует успех, а сторож будет следить по другому.
SRC_HOST=$(conf_get "$SRC" PROBE_HOST)
SRC_URL=$(conf_get "$SRC" PROBE_URL)
SRC_MATCH=$(conf_get "$SRC" PROBE_MATCH)
[ -n "$SRC_HOST" ] && [ -n "$SRC_URL" ] \
    || die "не смог вычитать PROBE_HOST/PROBE_URL из $SRC: файл не тот или побился"

PROBE_HOST="$SRC_HOST"; PROBE_URL="$SRC_URL"; PROBE_MATCH="$SRC_MATCH"; PROBE_FROM=""
for f in "$CONF" "$DEST"; do
    [ -r "$f" ] || continue
    # Источник выбирается по наличию ЛЮБОГО из трёх ключей, а не только
    # PROBE_HOST: конфиг, правленный руками, может задавать один PROBE_MATCH,
    # и сторож его применит. Не применим мы, и разойдёмся с ним ровно на этом.
    grep -qE "^[[:space:]]*PROBE_(HOST|URL|MATCH)[[:space:]]*=" "$f" 2>/dev/null || continue
    PROBE_FROM="$f"
    if conf_v=$(conf_get "$f" PROBE_HOST) && [ "$conf_v" != "$PROBE_HOST" ]; then
        PROBE_HOST="$conf_v"
        PROBE_URL="https://$conf_v/"
        PROBE_MATCH=""
    fi
    conf_v=$(conf_get "$f" PROBE_URL)   && PROBE_URL="$conf_v"
    conf_v=$(conf_get "$f" PROBE_MATCH) && PROBE_MATCH="$conf_v"
    break
done

# Проверка домена взята из сторожа целиком: у него она строже, и то, что он
# отвергнет, установщик принимать не вправе.
probe_bad=0
case "$PROBE_HOST" in
    ""|-*|*[!A-Za-z0-9.-]*|*..*) probe_bad=1 ;;
    *.*) case "${PROBE_HOST##*.}" in ""|*[!A-Za-z]*) probe_bad=1 ;; esac ;;
    *) probe_bad=1 ;;
esac
if [ "$probe_bad" = "1" ]; then
    # Не die, а откат: сторож на таком значении поступит ровно так же, и
    # разойтись с ним нельзя. Плюс негодная строка в конфиге не повод не дать
    # человеку обновиться: скажем и поедем дальше на умолчаниях.
    warn "PROBE_HOST '$PROBE_HOST' из ${PROBE_FROM:-$SRC} не похож на доменное имя"
    warn "(кириллицу пиши в punycode). Беру $SRC_HOST, как сделает и сторож."
    PROBE_HOST="$SRC_HOST"; PROBE_URL="$SRC_URL"; PROBE_MATCH="$SRC_MATCH"
    PROBE_FROM=""
fi

# Признак от прежнего сайта на новом не найдётся никогда: сторож его чистит,
# чистим и мы, иначе разойдёмся с ним на первом же тике.
if [ "$PROBE_HOST" != "$SRC_HOST" ] && [ "$PROBE_MATCH" = "$SRC_MATCH" ]; then
    PROBE_MATCH=""
    warn "PROBE_MATCH остался от $SRC_HOST, а следим за $PROBE_HOST: очищаю, как это сделает и сторож"
fi
case "$PROBE_URL" in
    "https://$PROBE_HOST"|"https://$PROBE_HOST/"*) ;;
    *) PROBE_URL="https://$PROBE_HOST/"; PROBE_MATCH="" ;;
esac

case "$PROBE_FROM" in
    "$CONF") ok "настройки из $CONF: слежу за $PROBE_HOST" ;;
    # Про перенос говорим только если переносить было что: в новом скрипте по
    # этому пути лежит встроенное умолчание, а не чья-то настройка.
    "$DEST") [ "$PROBE_HOST" = "$SRC_HOST" ] \
                 || ok "перенёс настройку из установленного сторожа: $PROBE_HOST" ;;
esac

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
    ok "$PROBE_HOST покрыт списками podkop, проверка осмысленна"
else
    say ""
    warn "$PROBE_HOST не найден ни в community-списках, ни в user_domains."
    warn "Значит сторож будет мерить ПРЯМОЙ интернет и падения прокси не заметит,"
    warn "а сторож в таком виде бесполезен."
    say ""
    say "  списки секций:  ${lists:-(пусто)}"
    say "  домены секций:  ${user_domains:-(пусто)}"
    say ""
    say "Впиши сайт, который у тебя реально уходит в туннель (Enter, чтобы оставить"
    say "$PROBE_HOST как есть и разбираться потом руками):"
    ask "  домен: " ""
    if [ -n "$ANSWER" ]; then
        # Та же проверка, что у сторожа: примем то, что он отвергнет, и он
        # молча уедет на cloudflare.com, а мы отрапортуем про введённый домен.
        ans_bad=0
        case "$ANSWER" in
            ""|-*|*[!A-Za-z0-9.-]*|*..*) ans_bad=1 ;;
            *.*) case "${ANSWER##*.}" in ""|*[!A-Za-z]*) ans_bad=1 ;; esac ;;
            *) ans_bad=1 ;;
        esac
        [ "$ans_bad" = "0" ] \
            || die "'$ANSWER' не похож на доменное имя (кириллицу пиши в punycode)"
        NEW_PROBE="$ANSWER"
        PROBE_MEANINGFUL=1
        ok "контрольный сайт будет заменён на $NEW_PROBE"
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

# Стоп-вопрос: у человека уже прописан свой DNS, и он не наш. Молча затирать
# осознанную настройку нельзя. Исключение одно: нетронутый дефолт podkop, а это
# udp на 77.88.8.8 (podkop/files/etc/config/podkop). Его меняем без вопросов,
# ради шифрованного резолва всё и затевается. Раньше здесь стояло, что дефолт
# podkop это doh на 1.1.1.1, и из-за этого молча затирались и чужой DoT, и
# осознанно выбранный doh 1.1.1.1.
if [ "$KEEP_DNS" = "0" ] && [ -n "$DNS_SERVER" ] \
   && [ -n "$cur_srv" ] && [ "$cur_srv" != "$DNS_SERVER" ] \
   && { [ "$cur_type" != "udp" ] || [ "$cur_srv" != "77.88.8.8" ]; }; then
    say ""
    warn "у тебя уже прописан свой DNS: ${cur_type:-?} $cur_srv"
    warn "Установка заменит его на doh $DNS_SERVER."
    if ! confirm "  Менять?"; then
        KEEP_DNS=1
        DNS_SERVER=""
        ok "оставляю $cur_srv"
    fi
fi

# --- 5. что будет сделано --------------------------------------------------

# Чужая незакоммиченная правка. `uci commit` сбрасывает журнал ЦЕЛИКОМ, то есть
# применит и её, в том числе поломанную, из-за которой её и не применили.
#
# Речь именно про КОНСОЛЬНЫЕ правки (/tmp/.uci): черновик из открытой вкладки
# LuCI сюда не попадает, rpcd держит его в каталоге своей сессии, и `uci
# changes` его не видит. Сторож эту же проверку делает в коде и просто уходит до
# следующего тика; здесь ситуация не аварийная, поэтому спрашиваем.
if [ -n "$(uci changes podkop 2>/dev/null)" ]; then
    say ""
    warn "в конфиге podkop есть незакоммиченные правки из консоли:"
    uci changes podkop 2>/dev/null | sed 's/^/      /'
    warn "Установка применит их заодно со своими."
    if ! confirm "  Всё равно продолжать?"; then
        say "Отменено. Примени или откати их (uci commit podkop / uci revert podkop)"
        say "и запусти снова."
        exit 0
    fi
fi

cur_cache=$(uci -q get podkop.settings.cache_path)

say ""
say "5. Что сейчас произойдёт"
say ""
say "  файлы     $DEST"
say "            $CONF: настройки, создастся если его ещё нет"
say "            /etc/podkop-ddns.conf и .bak — память синхронизации, заполнятся сами"
say "            /etc/podkop-watchdog.log — журнал событий, заполнится сам (до 500 строк)"
say "  cron      две строки: проверка раз в минуту, синхронизация раз в 5 минут"
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
    say "  сторож    контрольный сайт: $PROBE_HOST -> $NEW_PROBE"
fi
# Про рестарт говорим, только если он и правда будет. Рестарт делается в шаге 9
# при changed=1, а changed зависит ровно от двух величин, и обе уже известны
# здесь. Обещать прерывание связи и не прервать — то же враньё в выводе, что и
# строка «DNS: doh 8.8.8.8 -> doh 8.8.8.8» там, где менять нечего.
will_restart=0
[ "$cur_cache" != "$CACHE_PATH" ] && will_restart=1
if [ "$KEEP_DNS" = "0" ] && [ -n "$DNS_SERVER" ] \
   && { [ "$cur_type" != "doh" ] || [ "$cur_srv" != "$DNS_SERVER" ]; }; then
    will_restart=1
fi
if [ "$NO_RESTART" = "1" ]; then
    say "  podkop    не перезапускаю (--no-restart)"
elif [ "$will_restart" = "1" ]; then
    say "  podkop    будет перезапущен, связь ненадолго прервётся"
else
    say "  podkop    менять нечего, перезапуск не нужен"
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

# Сам скрипт кладётся как есть: контрольный сайт живёт в $CONF, а не в теле
# файла. Раньше три строки правились здесь через sed, и обновление их теряло:
# новый файл приезжал с cloudflare.com, о чём человеку никто не говорил.
cp "$SRC" "$DEST.new" || die "не смог записать $DEST.new"
if [ -n "$NEW_PROBE" ]; then
    PROBE_HOST="$NEW_PROBE"
    PROBE_URL="https://$NEW_PROBE/"
    PROBE_MATCH=""
    warn "PROBE_MATCH очищен: проверять содержимое ответа для чужого домена"
    warn "нельзя вслепую. Проверка теперь засчитывает любой ответ, кроме ошибки."
    warn "Если хочешь строгую проверку, впиши строку-признак в $CONF"
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

# Файл настроек. Создаётся один раз и при обновлении не переписывается: в нём
# лежит выбор человека, а обновление обязано его сохранить. Меняем в нём ровно
# то, что человек задал в этом запуске.
if [ ! -f "$CONF" ]; then
    # Через .new и mv, как $DEST и rc.local: оборвавшаяся запись (кончился
    # overlay) оставила бы огрызок, а ветка создания заходит только когда файла
    # нет, то есть повторный запуск его уже не починил бы.
    cat > "$CONF.new" <<CONF_EOF || die "не смог записать $CONF.new"
# Настройки podkop-watchdog. Переживают обновление сторожа и прошивку роутера.
# После правки ничего перезапускать не нужно: файл читается на каждом запуске.

# Сколько сторож пишет в syslog: off (молчать), err, warn или info.
# Журнал событий /etc/podkop-watchdog.log этот ключ не трогает: туда пишется всегда.
LOG_LEVEL="${LOG_LEVEL:-info}"

# Контрольный сайт: по нему проверяется, жив ли туннель. Обязан уходить в
# прокси, иначе проверка меряет прямой интернет. PROBE_MATCH это строка, которая
# должна найтись в ответе; пустая означает "годится любой ответ, кроме ошибки".
PROBE_HOST="$PROBE_HOST"
PROBE_URL="$PROBE_URL"
PROBE_MATCH="$PROBE_MATCH"

# Домены, по которым проверяется внешний DNS. Обязаны быть ВНЕ списков podkop,
# иначе они отдаются локально из FakeIP и проверка ослепнет. Раскомментируй,
# чтобы задать свои.
#UPSTREAM_HOSTS="openwrt.org debian.org"
CONF_EOF
    mv "$CONF.new" "$CONF" || die "не смог поставить $CONF"
    ok "$CONF создан"
else
    conf_touched=0
    [ -n "$LOG_LEVEL" ] && { conf_set LOG_LEVEL "$LOG_LEVEL"; conf_touched=1; ok "$CONF: LOG_LEVEL -> $LOG_LEVEL"; }
    if [ -n "$NEW_PROBE" ]; then
        conf_set PROBE_HOST  "$PROBE_HOST"
        conf_set PROBE_URL   "$PROBE_URL"
        conf_set PROBE_MATCH "$PROBE_MATCH"
        conf_touched=1
        ok "$CONF: контрольный сайт -> $PROBE_HOST"
    fi
    [ "$conf_touched" = "0" ] && ok "$CONF оставлен как есть"
fi

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
for f in "$DEST" "$CONF" /etc/podkop-ddns.conf /etc/podkop-ddns.bak /etc/podkop-watchdog.log /etc/sing-box/ \
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

# Первый прогон синхронизации: если в LuCI стоит домен, здесь он попадёт в память
# и сменится на IP. Под --no-restart пропускаем: синхронизация при смене адреса зовёт
# `podkop restart`, то есть обещание «ничего не перезапускаю» было бы нарушено
# ровно в самом частом случае — когда в конфиге домен, а не адрес.
if [ "$NO_RESTART" = "1" ]; then
    say "  синхронизацию не запускаю: она может перезапустить podkop. Запусти сам: $DEST ddns"
else
    "$DEST" ddns >/dev/null 2>&1
fi

rc=0
if [ "$PROBE_MEANINGFUL" = "0" ]; then
    warn "Цепочку не проверяю: сторож настроен на $PROBE_HOST, а он тут не"
    warn "проксируется, успех такой проверки ничего не доказал бы. Поправь"
    warn "PROBE_HOST и PROBE_URL в $CONF, PROBE_MATCH очисти, и проверь сам."
    rc=1
else
    # Не фиксированная пауза, а ожидание: холодный старт sing-box с пустым кэшем
    # (а после переноса cache_path он именно пуст) на живом роутере не укладывался
    # в 20 секунд. Фиксированная пауза дала бы ложное "проверка не прошла".
    waited=0
    while :; do
        # Обе половины разом: домен ушёл в туннель И страница отдалась. Порядок
        # важен — без первой проверки успех второй ничего не доказывает.
        if probe_proxied "$PROBE_HOST"; then
            if [ -n "$PROBE_MATCH" ]; then
                curl -fsS --max-time 10 "$PROBE_URL" 2>/dev/null | grep -q -e "$PROBE_MATCH" && break
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
            warn "Контрольный сайт уходит в туннель, но страница не отдалась за ${SETTLE_MAX}с:"
            warn "DNS от sing-box жив, а сам туннель — нет. Похоже на проблему с сервером."
        else
            warn "$PROBE_HOST НЕ резолвится в FakeIP за ${SETTLE_MAX}с — podkop не перехватил"
            warn "dnsmasq. Трафик идёт напрямую, прокси не работает."
        fi
        warn "Установка выполнена. Смотри:  $DEST log"
        warn "                              $DEST status"
    fi
fi

# status печатаем ПОСЛЕ проверки, а не до неё. Раньше он шёл сразу за
# рестартом podkop, то есть снимался в те секунды, когда sing-box ещё не
# поднялся: человек читал «проксируется: НЕТ», «sing-box НЕ найден» — и строкой
# ниже «цепочка работает». Пугающая и неверная картина на ровном месте.
say ""
"$DEST" status

say ""
if [ "$rc" = "0" ]; then
    say "Готово. Дальше:"
else
    say "Установлено, но НЕ проверено. Дальше:"
fi
say "  состояние   $DEST status"
say "  журнал      $DEST log"
say "  домен       вписывай обычной ссылкой в интерфейсе podkop, сторож подхватит"
say "  удаление    sh <(wget -O - $REPO_RAW/uninstall.sh)"
exit "$rc"

}

main "$@"

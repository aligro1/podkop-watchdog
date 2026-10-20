#!/bin/sh
#
# Снятие podkop-watchdog с роутера.
#
#   sh <(wget -O - https://raw.githubusercontent.com/aligro1/podkop-watchdog/main/uninstall.sh)
#
# Настройки DNS и кэша podkop НЕ откатываются: DoH вместо открытого udp/53 и кэш
# rule-set во флеше полезны сами по себе, а возврат на udp/53 это возврат к
# резаному провайдером резолву, то есть поломка, а не восстановление. Что именно
# осталось изменённым и как вернуть руками, скрипт печатает в конце.
#
# Откатывается одно: домен в строке подключения, который сторож подменял на IP.
# Про это скрипт спрашивает, потому что без сторожа домен снова придётся
# резолвить до подъёма туннеля.
#
# Перед запуском примени или отмени непринятые изменения в веб-интерфейсе: когда
# мы возвращаем домен, делается `uci commit podkop`, и он применит заодно чужие
# КОНСОЛЬНЫЕ правки. Черновик из вкладки LuCI сюда не попадает, rpcd держит его
# в каталоге своей сессии, зато нажатое там позже "Save & Apply" перезапишет
# возвращённый домен обратно.
#
# Ключи:
#   --purge            снести и файлы памяти синхронизации (/etc/podkop-ddns.conf и .bak),
#                      и журнал событий /etc/podkop-watchdog.log
#   --keep-files       не трогать файлы памяти и журнал (поведение по умолчанию)
#   --restore-domain   вернуть домен, не спрашивая; нужен при запуске без терминала
#   --keep-ip          не возвращать домен и не спрашивать
#
# Всё тело — в функции main, вызов последней строкой файла. Это обязательно при
# запуске через `sh <(wget ...)`: ash исполняет по мере чтения, и оборванная
# закачка выполнила бы половину сценария — например сняла бы cron, но не подняла
# podkop. С функцией недокачанный файл обрывается внутри её определения, до
# вызова дело не доходит, и не выполняется ничего.

set -u

DEST="/usr/bin/podkop-watchdog"
CRONTAB_FILE="/etc/crontabs/root"
STATE_DIR="/tmp/podkop-watchdog"
CONF="/etc/podkop-watchdog.conf"
DDNS_CONF="/etc/podkop-ddns.conf"
DDNS_BAK="/etc/podkop-ddns.bak"
JOURNAL="/etc/podkop-watchdog.log"
LOCK_WAIT=180     # сек ожидания чужого прогона watchdog
START_WAIT=90     # сек ожидания подъёма podkop из degraded

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ✓ %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*"; }
die()  { printf '\nОШИБКА: %s\n' "$*" >&2; exit 2; }

# Есть ли кого спрашивать. Через `sh <(wget -O - URL)` stdin остаётся
# терминалом и вопросы работают; через `wget -O - URL | sh` он занят самим
# скриптом, и спрашивать нечего.
interactive() { [ -t 0 ]; }

# Да/нет с ответом по умолчанию "да". Без терминала возвращает НЕТ, а не "да":
# единственный вопрос здесь про возврат домена в конфиг, и решать это за
# человека молча нельзя, см. restore_domains.
confirm() {
    local ans
    interactive || return 1
    printf '%s [Y/n] ' "$1"
    read -r ans || ans="y"
    # Кириллица здесь не украшение: промпт русский, а "нет" и "н" без неё
    # читаются как согласие, и единственный вопрос в файле переписывает конфиг
    # podkop и перезапускает прокси.
    case "${ans:-y}" in
        [Nn]*|[Нн]*) return 1 ;;
        *) return 0 ;;
    esac
}

# Ограничитель времени для init-скриптов. Такой же, как в install.sh, и по той
# же причине: на этом роутере init-скрипт podkop наблюдаемо подвисал. Здесь цена
# зависания выше, чем там: cron уже снят, домен уже закоммичен, и повисший
# насмерть деинсталлятор оставляет роутер с полуснятым сторожем.
# Дескриптор 9 в фоновых ветках закрываем: на нём висит общий лок сторожа,
# который держит этот скрипт. Унаследованный фоном лок пережил бы наш выход, и
# следующий прогон сторожа (если человек поставит его заново) встал бы в очередь
# к процессу, которого уже нет.
run_bounded() {
    limit="$1"; shift
    setsid "$@" >/dev/null 2>&1 9>&- &
    cmd_pid=$!
    setsid sh -c "sleep $limit; kill -9 -$cmd_pid 2>/dev/null || kill -9 $cmd_pid 2>/dev/null" 9>&- &
    killer_pid=$!
    wait "$cmd_pid" 2>/dev/null
    rc=$?
    kill -9 -"$killer_pid" 2>/dev/null || kill -9 "$killer_pid" 2>/dev/null
    wait "$killer_pid" 2>/dev/null
    return "$rc"
}

# Отвечает ли DNS от sing-box. Тот же признак живого podkop, что и на шаге 3.
podkop_dns_alive() {
    nslookup fakeip.podkop.fyi 127.0.0.42 >/dev/null 2>&1
}

# Разбор строки подключения на "всё до @", хост, порт и хвост. Логика повторяет
# ddns_parse_url из podkop-watchdog, где и объяснено, почему второй '@' и IPv6
# в скобках считаются неразбираемыми. Копия, а не вызов оригинала: секция
# сторожа тянет за собой log, state_get и лок, а нам нужны четыре подстроки.
ps_parse() {
    local url="$1" rest hostport
    PS_PRE=""; PS_HOST=""; PS_PORT=""; PS_POST=""
    case "$url" in *://*@*) ;; *) return 1 ;; esac
    PS_PRE="${url%%@*}"
    rest="${url#*@}"
    case "$rest" in *@*) return 1 ;; esac
    hostport="${rest%%[?#/]*}"
    PS_POST="${rest#"$hostport"}"
    case "$hostport" in
        \[*) return 1 ;;
        *:*) ;;
        *) return 1 ;;
    esac
    PS_PORT="${hostport##*:}"
    PS_HOST="${hostport%:*}"
    case "$PS_PORT" in ""|*[!0-9]*) return 1 ;; esac
    [ -n "$PS_HOST" ] || return 1
    return 0
}

# Годится ли строка на роль домена. Та же проверка, что ddns_valid_domain в
# стороже: домен уходит в proxy_string, и строка вида `-` или `1.2` там сделает
# ссылку, с которой podkop не поднимется.
ps_valid_domain() {
    case "$1" in
        ""|-*|*[!A-Za-z0-9.-]*) return 1 ;;
    esac
    case "$1" in
        *.*) case "${1##*.}" in ""|*[!A-Za-z]*) return 1 ;; esac; return 0 ;;
    esac
    return 1
}

ps_is_ipv4_literal() {
    case "$1" in
        *[!0-9.]*)   return 1 ;;
        *.*.*.*.*)   return 1 ;;
        *.*.*.*)     return 0 ;;
        *)           return 1 ;;
    esac
}

# Секция, где proxy_string и правда в деле: режим url. В urltest и selector
# podkop её не читает, и возвращать туда домен значит делать commit и рестарт
# podkop ради опции, которой никто не пользуется. Тот же признак, что
# ddns_section_active в podkop-watchdog: разъедутся, и сторож и деинсталлятор
# поспорят, какая секция живая.
ps_section_active() {
    [ "$(uci -q get "podkop.$1.connection_type")" = "proxy" ] \
        && [ "$(uci -q get "podkop.$1.proxy_config_type")" = "url" ]
}

# Сложить в LEFT_ON_IP все домены из памяти, чьи секции сейчас стоят на IP.
# Нужна на ранних выходах из restore_domains: инвариант "домен, который мы не
# вернули, обязан быть назван в конце" держится и тогда, когда до разбора по
# секциям дело не дошло. Режим секции здесь не важен: IP в неактивной
# proxy_string тоже наш, и вернётся человек в режим url, получит его уже без
# сторожа.
left_on_ip_from_memory() {
    local section domain ip rest ps
    [ -f "$DDNS_CONF" ] || return 0
    while read -r section domain ip rest <&8 || [ -n "$section" ]; do
        case "$section" in ""|\#*) section=""; continue ;; esac
        ps=$(uci -q get "podkop.$section.proxy_string")
        if [ -n "$ps" ] && ps_parse "$ps" && ps_is_ipv4_literal "$PS_HOST" \
           && [ -n "$domain" ] && [ "$domain" != "-" ]; then
            LEFT_ON_IP="${LEFT_ON_IP}${LEFT_ON_IP:+, }$domain"
        fi
        section=""
    done 8< "$DDNS_CONF"
}

# Вернуть домены в строки подключения там, где IP поставили мы.
#
# Пока сторож работал, в podkop.<секция>.proxy_string стоял IP, а домен лежал в
# нашей памяти. После удаления вернуть его будет неоткуда, и человек останется
# с адресом, который однажды протухнет.
#
# Меняем только те секции, где в конфиге стоит ровно ТОТ IP, что записан третьим
# полем: иначе адрес сменили руками, и наш домен там уже не при чём.
restore_domains() {
    # restored держим через пробел: по нему идёт сверка `case " $restored "`,
    # и запятая внутри сломала бы совпадение для всех секций, кроме последней.
    local section domain ip rest ps changed=0 restored="" restored_dom=""
    if [ ! -f "$DDNS_CONF" ]; then
        ok "памяти синхронизации нет, возвращать нечего"
        return 0
    fi
    if [ "$RESTORE" = "0" ]; then
        ok "домен не возвращаю (--keep-ip)"
        left_on_ip_from_memory
        return 0
    fi
    # Чужие незакоммиченные правки: `uci commit podkop` применит и их вместе с
    # нашей. Сторож в такой ситуации просто уходит до следующего тика
    # (ddns_sync_one), а у нас следующего тика не будет, поэтому спрашиваем.
    if [ -n "$(uci changes podkop 2>/dev/null)" ]; then
        warn "в конфиге podkop есть незакоммиченные правки:"
        uci changes podkop 2>/dev/null | sed 's/^/      /'
        warn "возврат домена их закоммитит заодно."
        if [ "$RESTORE" != "1" ] && ! confirm "  Всё равно возвращать домен?"; then
            ok "домен не возвращаю, правки не трогаю"
            left_on_ip_from_memory
            return 0
        fi
    fi
    # Читаем через дескриптор 8, а не через stdin: внутри цикла мы спрашиваем
    # человека, и обычный `< "$DDNS_CONF"` забрал бы у read его ответ. Условие
    # `|| [ -n "$section" ]` обрабатывает последнюю строку без завершающего
    # перевода: файл лежит в /etc, правится руками и переживает прошивку.
    while read -r section domain ip rest <&8 || [ -n "$section" ]; do
        case "$section" in ""|\#*) section=""; continue ;; esac
        ps=$(uci -q get "podkop.$section.proxy_string")
        if [ -z "$ps" ]; then section=""; continue; fi
        # Неактивную секцию не возвращаем (рестарт ради опции, которую podkop не
        # читает), но наш IP в ней назвать обязаны: см. left_on_ip_from_memory.
        if ! ps_section_active "$section"; then
            ok "секция '$section' не в режиме url, домен не возвращаю"
            if ps_parse "$ps" && ps_is_ipv4_literal "$PS_HOST" \
               && [ -n "${domain:-}" ] && [ "$domain" != "-" ]; then
                LEFT_ON_IP="${LEFT_ON_IP}${LEFT_ON_IP:+, }$domain"
            fi
            section=""; continue
        fi
        if ! ps_parse "$ps"; then
            warn "секция '$section': строку подключения не разобрал, не трогаю"
            ps_is_ipv4_literal "$PS_HOST" && LEFT_ON_IP="${LEFT_ON_IP}${LEFT_ON_IP:+, }${domain:-?}"
            section=""; continue
        fi
        # Всё, из-за чего домен вернуть нельзя, обязано попасть в LEFT_ON_IP,
        # если в конфиге сейчас IP-литерал: этот список человек читает вместо
        # сорока строк вывода, и молча потерянный домен там страшнее лишнего.
        if ! ps_valid_domain "${domain:-}"; then
            ps_is_ipv4_literal "$PS_HOST" \
                && LEFT_ON_IP="${LEFT_ON_IP}${LEFT_ON_IP:+, }?"
            section=""; continue
        fi
        if [ -z "$ip" ] || [ "$ip" = "-" ] || [ "$PS_HOST" != "$ip" ]; then
            if ps_is_ipv4_literal "$PS_HOST"; then
                ok "секция '$section': в конфиге $PS_HOST, а ставили мы ${ip:--}, не трогаю"
                LEFT_ON_IP="${LEFT_ON_IP}${LEFT_ON_IP:+, }$domain"
            fi
            section=""; continue
        fi
        if [ "$RESTORE" != "1" ] && ! interactive; then
            LEFT_ON_IP="${LEFT_ON_IP}${LEFT_ON_IP:+, }$domain"
            warn "секция '$section': терминала нет, домен $domain не возвращаю (см. --restore-domain)"
            section=""; continue
        fi
        if [ "$RESTORE" != "1" ]; then
            say ""
            say "  секция '$section': сейчас $ip, до установки был домен $domain"
            say "  Домен резолвится ДО подъёма туннеля, и именно поэтому роутер мог"
            say "  не подниматься после перезагрузки. Без сторожа это вернётся."
            if ! confirm "  Вернуть $domain?"; then
                LEFT_ON_IP="${LEFT_ON_IP}${LEFT_ON_IP:+, }$domain"
                ok "секция '$section': оставляю $ip"
                section=""; continue
            fi
        fi
        # warn вместо die: одна неудачная секция не повод бросать деинсталляцию
        # на середине, оставив снятый cron и неудалённые файлы.
        if uci set "podkop.$section.proxy_string=${PS_PRE}@${domain}:${PS_PORT}${PS_POST}"; then
            changed=1
            restored="${restored}${restored:+ }$section"
            restored_dom="${restored_dom}${restored_dom:+, }$domain"
            ok "секция '$section': вернул $domain"
        else
            warn "секция '$section': не смог записать proxy_string, оставляю $ip"
            LEFT_ON_IP="${LEFT_ON_IP}${LEFT_ON_IP:+, }$domain"
        fi
        section=""
    done 8< "$DDNS_CONF"

    [ "$changed" = "1" ] || return 0

    if ! uci commit podkop; then
        # Правка осталась бы висеть в /tmp/.uci и применилась бы при первом
        # чужом `uci commit podkop`, уже без нашего ведома.
        uci revert podkop 2>/dev/null
        warn "uci commit podkop не прошёл, правку откатил: в конфиге остался IP"
        LEFT_ON_IP="${LEFT_ON_IP}${LEFT_ON_IP:+, }$restored_dom"
        return 0
    fi
    ok "конфиг podkop записан (секции: $(echo $restored | tr ' ' ','))"

    if ! run_bounded 60 /etc/init.d/podkop restart; then
        warn "podkop restart завершился нештатно или не уложился в 60с"
    fi
    waited=0
    while [ "$waited" -lt "$START_WAIT" ]; do
        podkop_dns_alive && break
        waited=$((waited + 5))
        sleep 5
    done
    if podkop_dns_alive; then
        ok "podkop поднялся с доменом за ${waited}с, DNS отвечает"
        return 0
    fi
    # Домен может не резолвиться, это ровно та авария, ради которой сторож и
    # писался, только сторожа уже нет. Печатаем готовый откат: IP у нас на
    # руках, а искать его человеку будет негде.
    warn "podkop не поднялся за ${START_WAIT}с после возврата домена."
    warn "Интернет сейчас может не работать. Вернуть адрес обратно:"
    while read -r section domain ip rest <&8 || [ -n "$section" ]; do
        case "$section" in ""|\#*) section=""; continue ;; esac
        case " $restored " in *" $section "*) ;; *) section=""; continue ;; esac
        ps=$(uci -q get "podkop.$section.proxy_string")
        ps_parse "$ps" && say "  uci set podkop.$section.proxy_string='${PS_PRE}@${ip}:${PS_PORT}${PS_POST}'"
        section=""
    done 8< "$DDNS_CONF"
    say "  uci commit podkop && /etc/init.d/podkop restart"
}

# Снять строку из crontab, сохранив чужие задания.
#
# `{ crontab -l; ... } | crontab -` — известная ловушка: если crontab -l упадёт,
# на вход уйдёт пустота и ЧУЖИЕ задания root молча исчезнут. Поэтому читаем
# отдельно, проверяем код возврата и держим бэкап.
cron_del() {
    pattern="$1"
    cur=$(crontab -l 2>/dev/null); rc=$?
    if [ "$rc" != "0" ] && [ -s "$CRONTAB_FILE" ]; then
        die "crontab -l вернул ошибку, а $CRONTAB_FILE не пуст — не рискую перезаписывать"
    fi
    printf '%s\n' "$cur" | grep -qF "$pattern" || return 0
    [ -s "$CRONTAB_FILE" ] && cp "$CRONTAB_FILE" "$CRONTAB_FILE.bak"
    printf '%s\n' "$cur" | grep -vF "$pattern" | grep -v '^[[:space:]]*$' | crontab - \
        || die "не смог записать crontab (бэкап: $CRONTAB_FILE.bak)"
    crontab -l 2>/dev/null | grep -qF "$pattern" \
        && die "строка '$pattern' осталась в crontab — сними её руками"
    ok "убрано из cron: $pattern"
}

main() {
    PURGE=0
    # 1 возвращать домен молча, 0 не возвращать, пусто спросить.
    RESTORE=""
    # Домены, которые так и остались IP-адресами в конфиге: человек отказался
    # или терминала не было. О них напоминаем в самом конце.
    LEFT_ON_IP=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --purge)          PURGE=1; shift ;;
            --keep-files)     PURGE=0; shift ;;
            --restore-domain) RESTORE=1; shift ;;
            --keep-ip)        RESTORE=0; shift ;;
            *) die "неизвестный ключ: $1" ;;
        esac
    done

    say "Снятие podkop-watchdog"
    say ""

    [ "$(id -u)" = "0" ] || die "запускать надо от root"

    # Список того, что реально зовёт этот скрипт. Раньше проверки не было вовсе,
    # но раньше он и не перезапускал podkop, и не снимал ожидающие прогоны:
    # молча не сработавший pgrep вернул бы IP обратно уже после "Готово", а
    # отсутствие setsid оставило бы podkop с доменом и без перезапуска.
    for c in uci crontab flock nslookup grep sed awk cut tr pgrep setsid kill; do
        command -v "$c" >/dev/null 2>&1 \
            || die "нет команды $c, без неё снимать сторожа небезопасно"
    done

    found=0
    [ -f "$DEST" ] && found=1
    crontab -l 2>/dev/null | grep -qF "$DEST" && found=1
    grep -qF "$DEST" /etc/rc.local 2>/dev/null && found=1
    if [ "$found" = "0" ]; then
        say "podkop-watchdog не найден: ни файла, ни строк в cron и rc.local."
        say "Снимать нечего."
        exit 0
    fi

    # --- 1. дождаться чужого прогона -------------------------------------
    #
    # Watchdog мог именно сейчас идти долгой веткой (подъём из degraded длится
    # до ~150с) и держать общий лок. Снести файл под ним не опасно — открытый
    # файл доживёт до конца, — но прогон в конце запишет состояние и может
    # погасить podkop уже ПОСЛЕ того, как мы его подняли. Поэтому берём тот же
    # лок и ждём очереди.
    #
    # busybox flock умеет только [-sxun], флага ожидания -w у него нет —
    # поэтому ждём циклом.
    say "1. Жду, пока watchdog закончит текущий прогон"
    if [ -d "$STATE_DIR" ]; then
        exec 9>"$STATE_DIR/lock"
        waited=0
        while ! flock -n 9; do
            waited=$((waited + 5))
            if [ "$waited" -ge "$LOCK_WAIT" ]; then
                warn "за ${LOCK_WAIT}с лок не освободился — снимаю без него"
                break
            fi
            sleep 5
        done
        [ "$waited" -lt "$LOCK_WAIT" ] && ok "лок взят (ждал ${waited}с)"
    else
        ok "каталог состояния не найден, ждать нечего"
    fi

    # Режим читаем ДО того, как что-то трогать: дальше каталог состояния будет
    # удалён, а решение «поднимать ли podkop» зависит именно от него.
    mode=$(cat "$STATE_DIR/mode" 2>/dev/null)
    [ -n "$mode" ] || mode=armed

    # --- 2. снять расписание ---------------------------------------------
    #
    # ПЕРВЫМ делом, до подъёма podkop: иначе минутный тик влезет в середину и
    # начнёт собственную эскалацию поверх наших действий.
    say ""
    say "2. Снимаю расписание"
    cron_del "$DEST check"
    cron_del "$DEST ddns"

    # Тик ddns, успевший стартовать до снятия cron, не выходит, а ЖДЁТ общий лок
    # до 60с. Лок держим мы, до самого конца прогона, поэтому он получит его
    # сразу после нашего выхода: увидит в proxy_string домен, сочтёт его свежей
    # ручной правкой и подменит обратно на IP, заодно воскресив только что
    # снесённый файл памяти. Человеку при этом уже сказали "вернул домен".
    # Раз лок у нас, всё живое по этому пути это ожидающие, а не работающие.
    # Ищем `ddns` и `boot`: лока ждут только они. Тик `check` берёт его через
    # flock -n и выходит сразу, а `status` лока не трогает вовсе. `boot` живёт
    # своей подоболочкой из rc.local (`sleep 120; ... boot`), поэтому вырезанная
    # строка его уже не отменяет, а первое, что он делает после захвата лока, это
    # синхронизация адреса. Шаблон с аргументом заодно не цепляет чужие командные
    # строки, где путь к сторожу просто упомянут.
    # Своих предков в этот список собираем не для красоты: pgrep ищет по всей
    # командной строке, и если путь к сторожу упомянут в команде, которой
    # запустили сам деинсталлятор, под нож пойдёт собственная сессия. У busybox
    # ps нет -o, поэтому родителя читаем из /proc.
    self_chain=""
    chain_pid=$$
    while [ -n "$chain_pid" ] && [ "$chain_pid" != "1" ] && [ "$chain_pid" != "0" ]; do
        self_chain="$self_chain $chain_pid"
        chain_pid=$(cut -d' ' -f4 "/proc/$chain_pid/stat" 2>/dev/null)
    done
    for pid in $(pgrep -f "$DEST ddns" 2>/dev/null; pgrep -f "$DEST boot" 2>/dev/null); do
        case " $self_chain " in *" $pid "*) continue ;; esac
        kill "$pid" 2>/dev/null && ok "снят ожидающий прогон синхронизации (pid $pid)"
    done

    if grep -qF "$DEST boot" /etc/rc.local 2>/dev/null; then
        # Файл собираем заново, а НЕ вырезаем строку через sed: в ней есть '&',
        # а в правой части sed-подстановки это «весь совпавший текст». На вставке
        # этой же строки на грабли уже наступали — получался битый rc.local.
        # С вырезанием риск другой, но проверять регуляркой чужой файл дороже,
        # чем не звать sed вовсе.
        grep -vF "$DEST boot" /etc/rc.local \
            | grep -v '^# podkop-watchdog: проверка после загрузки' \
            > /tmp/rc.local.new 2>/dev/null \
            || die "не смог собрать новый /etc/rc.local"
        sh -n /tmp/rc.local.new || die "собранный /etc/rc.local не прошёл проверку синтаксиса, файл не тронут"
        mv /tmp/rc.local.new /etc/rc.local || die "не смог записать /etc/rc.local"
        grep -qF "$DEST boot" /etc/rc.local \
            && die "строка в /etc/rc.local осталась — сними её руками"
        ok "убрано из /etc/rc.local"
    else
        ok "в /etc/rc.local нечего убирать"
    fi

    # --- 3. вернуть podkop, если мы его гасили ---------------------------
    #
    # Делать это надо ЗДЕСЬ, пока скрипт ещё на месте и пока мы под локом:
    # после удаления поднимать podkop будет некому, и дом останется на прямом
    # интернете навсегда — без прокси и без единой подсказки почему.
    say ""
    say "3. Проверяю состояние podkop"
    if [ "$mode" = "degraded" ]; then
        warn "watchdog держал podkop погашенным, поднимаю обратно"
        # Через ограничитель и с закрытым fd 9 по той же причине, что и рестарт
        # ниже: подвисший init-скрипт иначе повесит деинсталляцию навсегда, уже
        # сняв cron, а демоны podkop унаследуют наш лок.
        run_bounded 60 /etc/init.d/podkop start \
            || warn "podkop start завершился нештатно или не уложился в 60с"
        waited=0
        while [ "$waited" -lt "$START_WAIT" ]; do
            if nslookup fakeip.podkop.fyi 127.0.0.42 >/dev/null 2>&1; then
                break
            fi
            waited=$((waited + 5))
            sleep 5
        done
        if nslookup fakeip.podkop.fyi 127.0.0.42 >/dev/null 2>&1; then
            ok "podkop поднят за ${waited}с, DNS отвечает"
        else
            warn "podkop не поднялся за ${START_WAIT}с."
            warn "Интернет сейчас идёт НАПРЯМУЮ — это рабочее состояние, но без прокси."
            if [ "$PURGE" = "1" ]; then
                warn "Разбирайся: logread | tail -50   и   /etc/init.d/podkop restart"
            else
                warn "Разбирайся: tail -50 $JOURNAL   и   /etc/init.d/podkop restart"
            fi
        fi
    else
        ok "podkop не был погашен watchdog'ом, трогать его не нужно"
    fi

    # --- 4. вернуть домен в строку подключения ---------------------------
    #
    # Здесь, а не позже: cron уже снят, значит сторож не влезет посреди правки,
    # а файл памяти ещё на месте.
    say ""
    say "4. Возвращаю домен в строку подключения"
    restore_domains

    # --- 5. sysupgrade.conf ----------------------------------------------
    #
    # /etc/sing-box/ НЕ снимаем: cache_path остаётся настроенным на
    # /etc/sing-box/cache.db, и кэш rule-set обязан пережить прошивку. Снимем —
    # вернётся холодный старт, ради ухода от которого кэш туда и переносили.
    say ""
    say "5. Чищу /etc/sysupgrade.conf"
    if [ -f /etc/sysupgrade.conf ]; then
        cp /etc/sysupgrade.conf /etc/sysupgrade.conf.bak
        removed=0
        for f in "$DEST" "$CONF" "$DDNS_CONF" "$DDNS_BAK" "$JOURNAL"; do
            grep -qxF "$f" /etc/sysupgrade.conf 2>/dev/null || continue
            grep -vxF "$f" /etc/sysupgrade.conf > /tmp/sysupgrade.conf.new 2>/dev/null \
                && mv /tmp/sysupgrade.conf.new /etc/sysupgrade.conf \
                && removed=$((removed + 1))
        done
        if [ "$removed" -gt 0 ]; then
            ok "снято путей: $removed (бэкап: /etc/sysupgrade.conf.bak)"
        else
            ok "наших путей там не было"
        fi
        grep -qxF "/etc/sing-box/" /etc/sysupgrade.conf 2>/dev/null \
            && ok "/etc/sing-box/ оставлен: там лежит кэш rule-set"
    else
        ok "файла нет, чистить нечего"
    fi

    # --- 6. файлы ---------------------------------------------------------
    say ""
    say "6. Удаляю файлы"
    rm -f "$DEST" "$DEST.bak" && ok "$DEST удалён"
    # Конфиг удаляем всегда, в отличие от файлов памяти: он весь состоит из
    # значений, которые установщик заведёт заново из умолчаний.
    # .new сносим заодно: он остаётся, если установщику оборвали запись.
    rm -f "$CONF.new"
    [ -f "$CONF" ] && rm -f "$CONF" && ok "$CONF удалён"
    if [ -d "$STATE_DIR" ]; then
        # Лок мы держим на файле внутри этого каталога. Удаление каталога при
        # открытом дескрипторе законно: файл доживёт до выхода из скрипта.
        rm -rf "$STATE_DIR" && ok "каталог состояния $STATE_DIR удалён"
    fi

    domain_note=""
    if [ -f "$DDNS_CONF" ]; then
        domain_note=$(grep -v '^[[:space:]]*#' "$DDNS_CONF" 2>/dev/null \
            | grep -v '^[[:space:]]*$' | awk '{print $2}' | tr '\n' ' ')
    fi

    if [ "$PURGE" = "1" ]; then
        rm -f "$DDNS_CONF" "$DDNS_BAK"
        ok "файлы памяти синхронизации удалены (--purge)"
        [ -n "$domain_note" ] && warn "в них был записан домен: $domain_note"
        rm -f "$JOURNAL" "$JOURNAL.new" && ok "журнал событий удалён (--purge)"
    else
        if [ -f "$DDNS_CONF" ] || [ -f "$DDNS_BAK" ]; then
            ok "файлы памяти синхронизации ОСТАВЛЕНЫ: $DDNS_CONF, $DDNS_BAK"
            [ -n "$domain_note" ] && say "    записанный там домен: $domain_note"
        fi
        # Журнал оставляем по той же логике: снимают сторожа чаще всего после
        # аварии, и история того, что он делал, нужна как раз тогда.
        [ -f "$JOURNAL" ] && ok "журнал событий ОСТАВЛЕН: $JOURNAL"
    fi

    # --- 7. что осталось --------------------------------------------------
    say ""
    say "Готово. Watchdog снят."
    say ""
    say "ОСТАЛОСЬ ИЗМЕНЁННЫМ в настройках podkop — намеренно, это не мусор:"
    say ""
    cur_type=$(uci -q get podkop.settings.dns_type)
    cur_srv=$(uci -q get podkop.settings.dns_server)
    cur_cache=$(uci -q get podkop.settings.cache_path)
    say "  dns_type    $cur_type"
    say "  dns_server  $cur_srv"
    say "  cache_path  $cur_cache"
    say ""
    say "Шифрованный DNS стоит оставить: открытый udp/53 провайдеры режут"
    say "выборочно, и ломается в том числе резолв адреса самого прокси-сервера."
    say "Кэш во флеше избавляет от холодного старта после каждой перезагрузки."
    say ""
    say "Если всё же хочешь вернуть как было у podkop по умолчанию:"
    say ""
    say "  uci set podkop.settings.dns_type='udp'"
    say "  uci set podkop.settings.dns_server='77.88.8.8'"
    say "  uci set podkop.settings.cache_path='/tmp/sing-box/cache.db'"
    say "  uci commit podkop && /etc/init.d/podkop restart"
    say ""
    if [ -n "$LEFT_ON_IP" ]; then
        say "В конфиге podkop остался IP-адрес сервера, а не домен: $LEFT_ON_IP"
        say "Впиши ссылку с доменом обратно через веб-интерфейс podkop, если"
        say "он тебе нужен."
        say ""
    fi
}

main "$@"

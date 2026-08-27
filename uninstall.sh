#!/bin/sh
#
# Снятие podkop-watchdog с роутера.
#
#   sh <(wget -O - https://raw.githubusercontent.com/aligro1/podkop-watchdog/main/uninstall.sh)
#
# Настройки podkop НЕ откатываются: DoH вместо открытого udp/53 и кэш rule-set
# во флеше полезны сами по себе, а возврат на udp/53 — это возврат к резаному
# провайдером резолву, то есть поломка, а не восстановление. Что именно осталось
# изменённым и как вернуть руками, скрипт печатает в конце.
#
# Ключи:
#   --purge        снести и файлы памяти синхронизации (/etc/podkop-ddns.conf и .bak)
#   --keep-files   не трогать файлы памяти и не спрашивать (поведение по умолчанию)
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
DDNS_CONF="/etc/podkop-ddns.conf"
DDNS_BAK="/etc/podkop-ddns.bak"
LOCK_WAIT=180     # сек ожидания чужого прогона watchdog
START_WAIT=90     # сек ожидания подъёма podkop из degraded

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ✓ %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*"; }
die()  { printf '\nОШИБКА: %s\n' "$*" >&2; exit 2; }

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

    while [ $# -gt 0 ]; do
        case "$1" in
            --purge)      PURGE=1; shift ;;
            --keep-files) PURGE=0; shift ;;
            *) die "неизвестный ключ: $1" ;;
        esac
    done

    say "Снятие podkop-watchdog"
    say ""

    [ "$(id -u)" = "0" ] || die "запускать надо от root"

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
        warn "watchdog держал podkop погашенным — поднимаю обратно"
        /etc/init.d/podkop start >/dev/null 2>&1
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
            warn "Разбирайся: logread | tail -50   и   /etc/init.d/podkop restart"
        fi
    else
        ok "podkop не был погашен watchdog'ом, трогать его не нужно"
    fi

    # --- 4. sysupgrade.conf ----------------------------------------------
    #
    # /etc/sing-box/ НЕ снимаем: cache_path остаётся настроенным на
    # /etc/sing-box/cache.db, и кэш rule-set обязан пережить прошивку. Снимем —
    # вернётся холодный старт, ради ухода от которого кэш туда и переносили.
    say ""
    say "4. Чищу /etc/sysupgrade.conf"
    if [ -f /etc/sysupgrade.conf ]; then
        cp /etc/sysupgrade.conf /etc/sysupgrade.conf.bak
        removed=0
        for f in "$DEST" "$DDNS_CONF" "$DDNS_BAK"; do
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

    # --- 5. файлы ---------------------------------------------------------
    say ""
    say "5. Удаляю файлы"
    rm -f "$DEST" "$DEST.bak" && ok "$DEST удалён"
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
    else
        if [ -f "$DDNS_CONF" ] || [ -f "$DDNS_BAK" ]; then
            ok "файлы памяти синхронизации ОСТАВЛЕНЫ: $DDNS_CONF, $DDNS_BAK"
            [ -n "$domain_note" ] && say "    записанный там домен: $domain_note"
        fi
    fi

    # --- 6. что осталось --------------------------------------------------
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
    if [ -n "$domain_note" ] && [ "$PURGE" = "1" ]; then
        say "В LuCI сейчас стоит IP-адрес сервера, а не домен. Домен был: $domain_note"
        say "Впиши ссылку с доменом обратно, если он тебе нужен."
        say ""
    fi
}

main "$@"

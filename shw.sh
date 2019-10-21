#!/bin/bash

###################################################
#  Logging Script used for Eternal Shell History  #
#                                                 #
#  Is hooked into ZSH shell using special         #
#  'preexec' function.                            #
###################################################

HOSTNAME="$(hostname)"
LOGFILE="${SHV_SHELL_HISTORY_ROOT}/${HOSTNAME}/$(date +%Y/%m).log"
LOGDIR="$(dirname "$LOGFILE")"
[ -d "$LOGDIR" ] || mkdir -p "$LOGDIR"

if [[ -z "$1" ]]; then
    echo "usage $(basename "$0") COMMAND"
    exit 2
fi

CMD="$(echo "$1" | sed -E ':a;N;$!ba;s/\r{0,1}\n/\\n/g')"; shift
printf "%s:%s:%s:%s:%s\n" "$HOSTNAME" "$(whoami)" "$(date '+%Y%m%d%H%M%S')" "$(pwd)" "$CMD" >> "$LOGFILE";

#!/bin/bash
# Designed to be executed via svg-term from the fd root directory:
# svg-term --command="bash doc/screencast.sh" --out doc/screencast.svg --padding=10
# Then run this (workaround for #1003):
# sed -i '' 's/<text/<text font-size="1.67"/g' doc/screencast.svg
set -e
set -u

PROMPT="▶"

enter() {
    INPUT=$1
    DELAY=1

    prompt
    sleep "$DELAY"
    type "$INPUT"
    sleep 0.5
    printf '%b' "\\n"
    eval "$INPUT"
    type "\\n"
}

prompt() {
    printf '%b ' "$PROMPT" | pv -q
}

type() {
    printf '%b' "$1" | pv -qL $((10+(-2 + RANDOM%5)))
}

main() {
    IFS='%'

    enter "lurk ls"

    enter "lurk --failed-only pwd"

    enter "lurk --expr trace=%file ls"

    enter "lurk --json ls | jq"

    enter "lurk --summary-only ls"

    prompt

    sleep 3

    echo ""

    unset IFS
}

main
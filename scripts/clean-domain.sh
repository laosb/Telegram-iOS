#!/usr/bin/env bash
# Git clean filter: applied when staging files.
# Reverses the smudge so that what gets committed matches upstream "t.me".
# Takes the same "bare" mode argument as the smudge — see smudge-domain.sh.
ROOT="$(git rev-parse --show-toplevel)"
DOMAIN="$(cat "$ROOT/.telegram-domain")"
# Escape dots in the domain for use as a sed regex pattern.
ESCAPED="$(printf '%s\n' "$DOMAIN" | sed 's/\./\\./g')"
if [ "$1" = "bare" ]; then
  exec sed -E \
    -e "s#${ESCAPED}#t.me#g"
fi
exec sed -E \
  -e "s#(\"|//)${ESCAPED}([/\"\\])#\\1t.me\\2#g"

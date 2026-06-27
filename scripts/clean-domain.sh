#!/usr/bin/env bash
# Git clean filter: applied when staging files.
# Reverses the smudge so that what gets committed matches upstream "t.me".
ROOT="$(git rev-parse --show-toplevel)"
DOMAIN="$(cat "$ROOT/.telegram-domain")"
# Escape dots in the domain for use as a sed regex pattern.
ESCAPED="$(printf '%s\n' "$DOMAIN" | sed 's/\./\\./g')"
exec sed \
  -e "s|\"https://${ESCAPED}/|\"https://t.me/|g" \
  -e "s|\"https://${ESCAPED}\\\\(|\"https://t.me\\\\(|g" \
  -e "s|\"${ESCAPED}/|\"t.me/|g" \
  -e "s|\"${ESCAPED}\"|\"t.me\"|g"

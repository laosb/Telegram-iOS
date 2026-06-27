#!/usr/bin/env bash
# Git smudge filter: applied when checking out files.
# Reads the target domain from .telegram-domain at the repo root.
ROOT="$(git rev-parse --show-toplevel)"
DOMAIN="$(cat "$ROOT/.telegram-domain")"
exec sed \
  -e "s|\"https://t\\.me/|\"https://${DOMAIN}/|g" \
  -e "s|\"https://t\\.me\\\\(|\"https://${DOMAIN}\\\\(|g" \
  -e "s|\"t\\.me/|\"${DOMAIN}/|g" \
  -e "s|\"t\\.me\"|\"${DOMAIN}\"|g"

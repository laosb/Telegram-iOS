#!/usr/bin/env bash
# Git smudge filter: applied when checking out files.
# Reads the target domain from .telegram-domain at the repo root.
# Rewrites the "t.me" host to the custom domain wherever it appears as a URL
# host: preceded by a string-opening quote or by "//" (any scheme, including
# interpolated ones like "\(scheme)://t.me/..."), and followed by "/", a
# closing quote, or a "\" (the start of a "\(...)" interpolation). Anchoring on
# both boundaries catches every host form while leaving identifiers such as
# "result.messages" untouched.
ROOT="$(git rev-parse --show-toplevel)"
DOMAIN="$(cat "$ROOT/.telegram-domain")"
exec sed -E \
  -e "s#(\"|//)t\\.me([/\"\\])#\\1${DOMAIN}\\2#g"

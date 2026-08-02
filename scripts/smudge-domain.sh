#!/usr/bin/env bash
# Git smudge filter: applied when checking out files.
# Reads the target domain from .telegram-domain at the repo root.
#
# Two modes, registered as two filter drivers (see .gitattributes):
#
# Default (source code) — rewrites "t.me" only where it appears as a URL host:
# preceded by a string-opening quote or by "//" (any scheme, including
# interpolated ones like "\(scheme)://t.me/..."), and followed by "/", a
# closing quote, or a "\" (the start of a "\(...)" interpolation). Anchoring on
# both boundaries catches every host form while leaving identifiers such as
# "result.messages" untouched.
#
# "bare" — rewrites every "t.me". For .strings catalogs, where the host also
# appears unquoted mid-sentence ("Link: t.me/%@", "[t.me/name]()") and there
# are no identifiers to protect.
ROOT="$(git rev-parse --show-toplevel)"
DOMAIN="$(cat "$ROOT/.telegram-domain")"
if [ "$1" = "bare" ]; then
  exec sed -E \
    -e "s#t\\.me#${DOMAIN}#g"
fi
exec sed -E \
  -e "s#(\"|//)t\\.me([/\"\\])#\\1${DOMAIN}\\2#g"

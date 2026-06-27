#!/usr/bin/env bash
# Activate (or reconfigure) the git smudge/clean filter.
#
# Usage:
#   ./scripts/setup-domain-filter.sh              # use domain already in .telegram-domain
#   ./scripts/setup-domain-filter.sh newdomain.com # switch to a new domain
#
# After setup, checking out any filtered Swift file transparently replaces
# stored "t.me" with the configured domain. Staging reverses it, so commits
# remain compatible with upstream Telegram iOS.
set -e
ROOT="$(git rev-parse --show-toplevel)"

if [ -n "$1" ]; then
    printf '%s' "$1" > "$ROOT/.telegram-domain"
fi

DOMAIN="$(cat "$ROOT/.telegram-domain")"
chmod +x "$ROOT/scripts/smudge-domain.sh" "$ROOT/scripts/clean-domain.sh"
git config filter.telegram-domain.smudge "$ROOT/scripts/smudge-domain.sh"
git config filter.telegram-domain.clean  "$ROOT/scripts/clean-domain.sh"
git config filter.telegram-domain.required true

# Force smudge filter re-application: git checkout-index skips files whose
# working-tree stat matches the index, so we must delete them first.
cd "$ROOT"
git ls-files -z -- '*.swift' | xargs -0 rm -f
git ls-files -z -- '*.swift' | xargs -0 git checkout-index --force --
echo "Domain filter configured for: ${DOMAIN}"

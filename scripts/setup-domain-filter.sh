#!/usr/bin/env bash
# Activate (or reconfigure) the git smudge/clean filter.
#
# Usage:
#   ./scripts/setup-domain-filter.sh              # use domain already in .telegram-domain
#   ./scripts/setup-domain-filter.sh newdomain.com # switch to a new domain
#
# After setup, checking out any filtered file transparently replaces stored
# "t.me" with the configured domain. Staging reverses it, so commits remain
# compatible with upstream Telegram iOS. Which paths are filtered — and with
# which of the two drivers — is declared in .gitattributes.
set -e
ROOT="$(git rev-parse --show-toplevel)"

# The domain currently in the working tree, needed to spot stale files below.
PREVIOUS="$(cat "$ROOT/.telegram-domain" 2>/dev/null || true)"
if [ -n "$1" ]; then
    printf '%s' "$1" > "$ROOT/.telegram-domain"
fi

DOMAIN="$(cat "$ROOT/.telegram-domain")"
chmod +x "$ROOT/scripts/smudge-domain.sh" "$ROOT/scripts/clean-domain.sh"
git config filter.telegram-domain.smudge "scripts/smudge-domain.sh"
git config filter.telegram-domain.clean  "scripts/clean-domain.sh"
git config filter.telegram-domain.required true
git config filter.telegram-domain-strings.smudge "scripts/smudge-domain.sh bare"
git config filter.telegram-domain-strings.clean  "scripts/clean-domain.sh bare"
git config filter.telegram-domain-strings.required true

cd "$ROOT"

# Content the smudge should have rewritten but hasn't: the stored "t.me", plus
# the previous domain when switching. The target domain is excluded, so files
# that are already correct stay untouched.
STALE_HOST='t\.me'
if [ -n "$PREVIOUS" ] && [ "$PREVIOUS" != "$DOMAIN" ]; then
    STALE_HOST="${STALE_HOST}|$(printf '%s\n' "$PREVIOUS" | sed 's/\./\\./g')"
fi

# Re-smudge only the files that need it: re-checking out every filtered file
# would bump ~15k mtimes and force a full rebuild.
reapply() {
    # $1: ERE matching content the smudge would rewrite. $2...: pathspecs.
    local pattern="$1"; shift
    local stale
    stale="$(git ls-files -- "$@" | tr '\n' '\0' | xargs -0 grep -lE "$pattern" 2>/dev/null)" || true
    if [ -z "$stale" ]; then
        echo 0
        return 0
    fi
    # Delete first: checkout skips paths whose working-tree stat matches the
    # index, so files still in place would never be re-smudged. Use `git
    # checkout`, not `git checkout-index` — only the former records the smudged
    # file's stat in the index, and without that the length difference between
    # "t.me" and the domain leaves every filtered file reported as modified.
    printf '%s\n' "$stale" | tr '\n' '\0' | xargs -0 rm -f
    printf '%s\n' "$stale" | tr '\n' '\0' | xargs -0 git checkout --
    printf '%s\n' "$stale" | wc -l | tr -d ' '
}

SOURCE_COUNT="$(reapply "(\"|//)(${STALE_HOST})([/\"\\])" '*.swift' '*.m')"
STRINGS_COUNT="$(reapply "${STALE_HOST}" '*.strings')"
echo "Domain filter configured for: ${DOMAIN}"
echo "Re-smudged ${SOURCE_COUNT} source file(s), ${STRINGS_COUNT} strings file(s)."

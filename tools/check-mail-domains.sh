#!/bin/sh
# check-mail-domains.sh — re-verify the DNS posture recorded in tools/mail-domains.tsv.
#
# This is the OTHER half of tools/check-contact-addresses.sh.
#   That check is static: it fails a build when an address is published on a domain not in the table.
#   This check is live: it fails when the world has changed under the table.
#
# Why both: a dated allowlist entry is a promise that expires, and nothing in a static check notices.
# If rcommerce.app loses its MX, the static check keeps green-lighting addresses on a dead domain —
# the exact failure the allowlist exists to prevent, reintroduced by its own configuration.
#
# Deliberately NOT wired into preflight or CI: a check that needs the network fails for unrelated
# reasons, and checks that fail for unrelated reasons get disabled. Run it on a schedule instead
# (weekly, alongside the docs audit) and treat drift as a finding to report, never as a deploy gate.
#
# Usage: check-mail-domains.sh [tsv]
# Exit:  0 all rows match · 1 drift found · 2 usage/setup error
#
# Queries used to populate a row:
#   dig +short MX <domain>
#   dig +short TXT <domain> | grep -i 'v=spf1'
#   dig +short TXT _dmarc.<domain> | grep -i 'v=DMARC1'

set -u

tsv=${1:-$(dirname "$0")/mail-domains.tsv}
[ -r "$tsv" ] || { echo "ERROR: cannot read $tsv" >&2; exit 2; }
command -v dig >/dev/null 2>&1 || { echo "ERROR: dig not found" >&2; exit 2; }

drift=0
checked=0

# header: domain mx_host spf dmarc_policy verified
while IFS="$(printf '\t')" read -r domain want_mx want_spf want_dmarc verified; do
  case "$domain" in ''|'#'*|domain) continue ;; esac
  checked=$((checked + 1))

  got_mx=$(dig +short MX "$domain" 2>/dev/null | awk '{print $2}' | head -1 | sed 's/\.$//')
  [ -n "$got_mx" ] || got_mx=NONE

  got_spf=$(dig +short TXT "$domain" 2>/dev/null | tr -d '"' | grep -i '^v=spf1' | head -1)
  [ -n "$got_spf" ] || got_spf=NONE

  got_dmarc=$(dig +short TXT "_dmarc.$domain" 2>/dev/null | tr -d '"' | grep -i '^v=DMARC1' | head -1)
  if [ -n "$got_dmarc" ]; then
    got_policy=$(printf '%s' "$got_dmarc" | tr ';' '\n' | sed -n 's/.*p=\([a-z]*\).*/\1/p' | head -1)
    [ -n "$got_policy" ] || got_policy=NONE
  else
    got_policy=NONE
  fi

  row_drift=0
  [ "$got_mx" = "$want_mx" ]     || { printf '  DRIFT  %s: MX is "%s", table says "%s"\n' "$domain" "$got_mx" "$want_mx"; row_drift=1; }
  [ "$got_spf" = "$want_spf" ]   || { printf '  DRIFT  %s: SPF is "%s", table says "%s"\n' "$domain" "$got_spf" "$want_spf"; row_drift=1; }
  [ "$got_policy" = "$want_dmarc" ] || { printf '  DRIFT  %s: DMARC p= is "%s", table says "%s"\n' "$domain" "$got_policy" "$want_dmarc"; row_drift=1; }

  if [ "$row_drift" -eq 0 ]; then
    printf '  ok     %-16s %s  (table verified %s)\n' "$domain" "$want_mx / $want_dmarc" "$verified"
  else
    drift=$((drift + 1))
  fi
done < "$tsv"

if [ "$checked" -eq 0 ]; then
  echo "ERROR: no rows read from $tsv" >&2
  exit 2
fi

if [ "$drift" -gt 0 ]; then
  cat >&2 <<'EOF'

  The world disagrees with tools/mail-domains.tsv. Two directions, both matter:
    - a MAIL domain lost MX/SPF/DMARC  -> published addresses on it are now broken; fix the domain.
    - a NO-MAIL domain gained them     -> it now accepts mail, so "never publish an address there"
                                          is out of date; update the table and the checker together.
  Re-run the three queries, then update the row and its verified date.
EOF
  echo "MAIL DOMAINS: $drift of $checked row(s) drifted." >&2
  exit 1
fi

echo "  PASS  $checked domain(s) match the recorded posture"
exit 0

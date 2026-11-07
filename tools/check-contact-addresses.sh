#!/bin/sh
# check-contact-addresses.sh — every published contact address must be on a domain that accepts mail.
#
# Why: rvpn-core published security@rvpn.org while rvpn.org had no MX, no SPF and no DMARC. Mail to it is
# refused at SMTP (the A record is a web proxy on :25) and bounces back to the reporter after several days
# of retries — so a vulnerability report looks delivered to the sender and never arrives. The same edit is
# one "branding consistency" change away from happening again on any of our domains.
#
# Usage: check-contact-addresses.sh <dir> [more dirs...]
# Exit:  0 all addresses fine · 1 offender(s) found · 2 usage/scan error
#
# Rule: an address is acceptable if its domain is reserved for documentation — RFC 2606
# (.test/.example/.invalid/.localhost plus the three example second-level domains) or `.local`
# via RFC 6762 (mDNS, IANA Special-Use registry per RFC 6761) — or is
# listed in MAIL_DOMAINS below. Anything else must be added deliberately, after confirming the domain has
# an MX record — see the note printed on failure.

set -u

# Allowlist comes from tools/mail-domains.tsv, the same file the scheduled re-verifier reads — one source
# of truth, so the static check and the DNS check can never disagree about which domains count as mail-capable.
# Domains whose posture is NONE there are, by definition, not allowed to carry a published address.
tsv=$(dirname "$0")/mail-domains.tsv
[ -r "$tsv" ] || { echo "ERROR: cannot read $tsv" >&2; exit 2; }
MAIL_DOMAINS=$(awk -F'\t' '!/^#/ && $1!="domain" && NF>=2 && $2!="NONE" { print $1 }' "$tsv" | tr '\n' ' ')
[ -n "$MAIL_DOMAINS" ] || { echo "ERROR: no mail-capable domains in $tsv" >&2; exit 2; }

[ $# -ge 1 ] || { echo "usage: $0 <dir> [more dirs...]" >&2; exit 2; }

is_reserved() {
  case "$1" in
    example.com|example.net|example.org|*.example|*.test|*.invalid|*.local|*.localhost|localhost)
      return 0 ;;
  esac
  return 1
}

on_allowlist() {
  for d in $MAIL_DOMAINS; do [ "$1" = "$d" ] && return 0; done
  return 1
}

tmp=$(mktemp) || exit 2
trap 'rm -f "$tmp"' EXIT
scanned=0

for dir in "$@"; do
  [ -d "$dir" ] || { echo "ERROR: not a directory: $dir" >&2; exit 2; }
  # text files we publish, INCLUDING *.py: the site generator (site/gen.py) and its emitted HTML must
  # both be clean, or a hand-edited page ships an address the template no longer contains.
  # Skip binaries, lockfiles and vendored trees.
  find "$dir" -type f \
    \( -name '*.md' -o -name '*.html' -o -name '*.py' -o -name '*.toml' -o -name '*.yml' -o -name '*.yaml' -o -name '*.txt' -o -name '*.json' \) \
    ! -path '*/node_modules/*' ! -path '*/.git/*' ! -name 'package-lock.json' 2>/dev/null \
  | while IFS= read -r f; do
      grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$f" 2>/dev/null \
        | sed "s|^|$f\t|"
    done >> "$tmp"
  scanned=$((scanned + 1))
done

[ -s "$tmp" ] || { echo "ERROR: no addresses found across $scanned dir(s) — wrong path?" >&2; exit 2; }

fails=0
while IFS="$(printf '\t')" read -r file addr; do
  domain=${addr##*@}
  lc=$(printf '%s' "$domain" | tr 'A-Z' 'a-z')
  if is_reserved "$lc" || on_allowlist "$lc"; then
    continue
  fi
  printf '  FAIL  %s: %s — domain "%s" is not a verified mail domain\n' "$file" "$addr" "$lc"
  fails=$((fails + 1))
done < "$tmp"

if [ "$fails" -gt 0 ]; then
  cat >&2 <<'EOF'

  Published contact addresses must live on a domain that actually accepts mail. Before adding one,
  confirm the domain has an MX record AND that it publishes SPF and DMARC — otherwise reports are
  refused at SMTP and bounce back to the sender days later, which reads as "sent" to whoever sent it.

      dig +short MX <domain>
      dig +short TXT <domain> | grep spf
      dig +short TXT _dmarc.<domain>

  Add the domain to tools/mail-domains.tsv once verified (MX, SPF, DMARC, today's date).
EOF
  echo "CONTACT ADDRESSES: $fails unacceptable address(es)." >&2
  exit 1
fi

echo "  PASS  every published contact address is on a verified mail domain"
exit 0

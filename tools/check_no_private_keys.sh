#!/usr/bin/env bash
# CI guard for the f-secrets-keymgmt invariant: no private key material is
# ever committed. Backstop only — see docs/KEY_CEREMONY.md for the actual
# control (the private key is generated and kept on an offline machine).
set -euo pipefail

self="tools/check_no_private_keys.sh"
fail=0

header_pattern='-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'
while IFS= read -r -d '' f; do
  [ "$f" = "$self" ] && continue
  if grep -Eqa -e "$header_pattern" -- "$f" 2>/dev/null; then
    echo "✗ private key header found in tracked file: $f" >&2
    fail=1
  fi
done < <(git ls-files -z)

# Flag risky extensions, allowlisting the ceremony's public-key artifact.
while IFS= read -r -d '' f; do
  case "$f" in
    keys/release-key.pub.pem) ;; # the one PEM we expect to commit
    *.pem|*.key|*.p12|*.pfx)
      echo "✗ private-key-shaped file tracked: $f" >&2
      fail=1
      ;;
  esac
done < <(git ls-files -z)

if [ "$fail" -eq 0 ]; then
  echo "✓ no private key material found in tracked files"
fi
exit "$fail"

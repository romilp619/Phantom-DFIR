#!/usr/bin/env bash
# Diagnose why the HF token reads as empty through command substitution.
# Never prints the token value - only lengths and byte classes.
set -u

TOK=/mnt/c/Users/Owner/.huggingface/token

echo "=== file stats ==="
wc -c < "$TOK"
ls -la "$TOK"

echo
echo "=== raw byte inspection (hex, safe: token is a bearer string) ==="
od -c "$TOK" | head -4

echo
echo "=== direct cat into a variable ==="
T1=$(cat "$TOK")
echo "T1 len=${#T1}"

echo
echo "=== with CR stripped ==="
T2=$(cat "$TOK" | tr -d '\r\n')
echo "T2 len=${#T2}"

echo
echo "=== read builtin ==="
IFS= read -r T3 < "$TOK"
echo "T3 len=${#T3}"

echo
echo "=== python read ==="
python3 -c "
p='/mnt/c/Users/Owner/.huggingface/token'
d=open(p,'rb').read()
print('bytes:',len(d),'hex_head:',d[:3].hex(),'has_cr:',b'\r' in d,'has_lf:',b'\n' in d)
"

echo
echo "=== export test then curl ==="
export HF_TOKEN="$T2"
echo "exported len=${#HF_TOKEN}"
if [ -n "$HF_TOKEN" ]; then
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $HF_TOKEN" \
    https://huggingface.co/CohereLabs/tiny-aya-global)
  echo "gated model HTTP: $code"
else
  echo "token empty, skipping curl"
fi
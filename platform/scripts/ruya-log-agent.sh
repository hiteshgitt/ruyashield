#!/usr/bin/env bash
# RuyaShield log agent: forwards new access-log lines (nginx/Apache "combined" format) to RuyaShield for
# attack-origin monitoring. Install on the server that hosts the verified site. Read-only on the log; changes nothing.
#
#   RUYA_URL=https://ruya.example.com  RUYA_INGEST_TOKEN=rs_...  ./ruya-log-agent.sh /var/log/nginx/access.log
#
# Keep the token in an env file readable only by the agent's user (chmod 600), never on the command line.
# The server keeps only suspicious requests (path without query string, IP, user agent) for 90 days.
set -euo pipefail
LOG="${1:?usage: ruya-log-agent.sh /path/to/access.log}"
: "${RUYA_URL:?set RUYA_URL}"; : "${RUYA_INGEST_TOKEN:?set RUYA_INGEST_TOKEN}"
case "$RUYA_URL" in https://*|http://localhost*|http://127.0.0.1*) ;; *) echo "RUYA_URL must be https" >&2; exit 2;; esac
BATCH_LINES="${BATCH_LINES:-2000}"; FLUSH_SECS="${FLUSH_SECS:-10}"
BUF="$(mktemp)"; trap 'rm -f "$BUF"' EXIT
CURL_CFG="$(mktemp)"; trap 'rm -f "$BUF" "$CURL_CFG"' EXIT
chmod 600 "$CURL_CFG"
printf 'header = "Authorization: Bearer %s"\n' "$RUYA_INGEST_TOKEN" > "$CURL_CFG"   # keeps the token out of `ps`

send() {
  [ -s "$BUF" ] || return 0
  local code
  for attempt in 1 2 3 4 5; do
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 -K "$CURL_CFG" \
      -H 'Content-Type: text/plain; charset=utf-8' --data-binary @"$BUF" "$RUYA_URL/v1/attacks/ingest" || echo 000)
    case "$code" in
      202) : > "$BUF"; return 0;;
      401|403) echo "ruya-log-agent: token rejected or asset not verified ($code); stopping" >&2; exit 1;;
      413|415|422) echo "ruya-log-agent: batch refused ($code); dropping it" >&2; : > "$BUF"; return 0;;
      *) sleep $((attempt * 5));;
    esac
  done
  echo "ruya-log-agent: could not deliver batch (last status $code); dropping it" >&2; : > "$BUF"
}

last=$(date +%s); n=0
# -F follows log rotation; -n0 starts at the end (no backfill).
tail -n0 -F "$LOG" 2>/dev/null | while true; do
  if IFS= read -r -t "$FLUSH_SECS" line; then
    printf '%s\n' "$line" >> "$BUF"; n=$((n + 1))
  fi
  now=$(date +%s)
  if [ "$n" -ge "$BATCH_LINES" ] || { [ "$n" -gt 0 ] && [ $((now - last)) -ge "$FLUSH_SECS" ]; }; then
    send; n=0; last=$now
  fi
done

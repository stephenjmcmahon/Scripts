#!/bin/bash

# IMPORTANT: Don't forget to give the script "execute" permission by running 'chmod +x dns_monitor.sh'

RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")

SITES=(
  mail.google.com
  apple.com
)

OUT="dns_results.csv"

echo "timestamp,resolver,hostname,latency_ms,status" > "$OUT"

echo "DNS monitoring started (Ctrl-C to stop)"
echo "Resolvers: ${RESOLVERS[*]}"
echo "Output: $OUT"

while true; do
  TS=$(date +"%Y-%m-%d %H:%M:%S")
  for DNS in "${RESOLVERS[@]}"; do
    for SITE in "${SITES[@]}"; do
      RESULT=$(dig @"$DNS" "$SITE" +time=1 +tries=1 +noall +stats 2>/dev/null)
      LAT=$(echo "$RESULT" | awk '/Query time/ {print $4}')

      if [[ -z "$LAT" ]]; then
        echo "$TS,$DNS,$SITE,,FAIL" >> "$OUT"
      else
        echo "$TS,$DNS,$SITE,$LAT,OK" >> "$OUT"
      fi
    done
  done
  sleep 5
done

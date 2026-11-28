#!/bin/bash
# mb.sh VARIANT DIR FLOWS [SECS]: one benchmark run on the macOS client, printed as one JSON line.
# VARIANT is a version staged as flextunnel-VARIANT, "none" (no tunnel) or "tailscale".
# hosts.env (written by bench/stage.py) gives SERVER4 and SERVER_TS4.
set -u
export PATH=/opt/homebrew/bin:$PATH
V=$1; DIR=$2; FLOWS=$3; SECS=${4:-6}
B=$HOME/codes/staging-area/flextunnel-bench
. "$B/hosts.env"
R=""; [ "$DIR" = down ] && R="-R"

run_iperf() {  # host port -> "Mbit/s received, retransmits"
  local out
  for attempt in 1 2 3; do
    out=$(iperf3 -J -t "$SECS" -O 1 -P "$FLOWS" -c "$1" -p "$2" $R 2>&1)
    if echo "$out" | grep -q '"sum_received"'; then
      local bps retr
      bps=$(echo "$out" | /usr/bin/plutil -extract end.sum_received.bits_per_second raw -o - -)
      retr=$(echo "$out" | /usr/bin/plutil -extract end.sum_sent.retransmits raw -o - - 2>/dev/null || echo null)
      echo "$bps $retr" | awk '{printf "\"mbps\":%.1f,\"retr\":%s", $1/1e6, $2}'
      return 0
    fi
    sleep 2
  done
  echo "iperf3 failed: $out" >&2; return 1
}
cpu_secs() {  # cumulative CPU seconds of a pid, from ps's [[dd-]hh:]mm:ss.cc
  ps -o time= -p "$1" | awk '{ n=split($1,a,":"); s=0; for(i=1;i<=n;i++) s=s*60+a[i]; printf "%.2f", s }'
}
last_path() { grep -o 'Connection: .*' "$B/client.log" 2>/dev/null | tail -1 | sed 's/^Connection: //'; }

head="\"variant\":\"$V\",\"dir\":\"$DIR\",\"flows\":$FLOWS"
if [ "$V" = none ]; then
  m=$(run_iperf "$SERVER4" 5201) || exit 1
  echo "{$head,$m}"
  exit 0
fi
if [ "$V" = tailscale ]; then
  m=$(run_iperf "$SERVER_TS4" 5201) || exit 1
  p=$(/Applications/Tailscale.app/Contents/MacOS/Tailscale ping -c 1 --timeout 5s "$SERVER_TS4" 2>&1 | tail -1)
  echo "{$head,$m,\"path_after\":\"$p\"}"
  exit 0
fi

pkill -x "flextunnel-$V" 2>/dev/null
: > "$B/client.log"
RUST_LOG='info,iroh=warn,tracing=warn,flextunnel_core::transport::paths=debug' \
  "$B/flextunnel-$V" client start -c "$B/client.toml" >> "$B/client.log" 2>&1 &
pid=$!
stop_client() {
  # SIGTERM, and again if the client is still there after 5 s (noted in term-retries.log), then SIGKILL.
  local i
  kill $pid 2>/dev/null
  for i in $(seq 50); do kill -0 $pid 2>/dev/null || return 0; sleep 0.1; done
  echo "$(date -u +%FT%TZ) $V $DIR: still running 5 s after SIGTERM" >> "$B/term-retries.log"
  kill $pid 2>/dev/null
  for i in $(seq 50); do kill -0 $pid 2>/dev/null || return 0; sleep 0.1; done
  kill -9 $pid 2>/dev/null
}
trap stop_client EXIT
i=0
until grep -q 'listening on 127.0.0.1:5301' "$B/client.log"; do
  sleep 0.1; i=$((i+1)); [ $i -ge 200 ] && { echo "client not up" >&2; tail -5 "$B/client.log" >&2; exit 1; }
done
# Connect the destination without sending bulk: read sshd's banner through a second forward.
nc -w 15 127.0.0.1 5322 </dev/null | head -c 4 >/dev/null
i=0
until case "$(last_path)" in Direct*) true ;; *) false ;; esac; do
  sleep 0.2; i=$((i+1)); [ $i -ge 100 ] && { echo "no direct path: $(last_path)" >&2; exit 1; }
done
sleep 1
path=$(last_path)
c0=$(cpu_secs $pid); t0=$(perl -MTime::HiRes=time -e 'printf "%.3f", time')
m=$(run_iperf 127.0.0.1 5301) || exit 1
c1=$(cpu_secs $pid); t1=$(perl -MTime::HiRes=time -e 'printf "%.3f", time')
cpu=$(echo "$c0 $c1 $t0 $t1" | awk '{printf "%.2f", ($2-$1)/($4-$3)}')
ver=$(grep -m1 -o 'flextunnel-cli v[0-9.]*' "$B/client.log")
echo "{$head,$m,\"cpu_client\":$cpu,\"path\":\"$path\",\"path_after\":\"$(last_path)\",\"version\":\"$ver\"}"

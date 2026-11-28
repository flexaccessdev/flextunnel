#!/bin/bash
# nc.sh VERSION up|down: on the client VM, time 1500 MiB through `flextunnel client nc`
# against a listener on the server. That version's client must be running
# (ftb.sh client VERSION). Prints Mbit/s.
set -u
B=$HOME/codes/staging-area/flextunnel-bench
BIN=$B/bin/$1/flextunnel
N=$((1500*1024*1024))
H=t1.localhost.flextunnel.internal
t0=$(date +%s.%N)
if [ "$2" = up ]; then
  head -c 1500M /dev/zero | "$BIN" client nc -c "$B/client.toml" $H 5202
else
  # The far listener stops sending once it sees a half-close, so stdin is held open.
  rm -f "$B/ncfifo"; mkfifo "$B/ncfifo"
  sleep 600 > "$B/ncfifo" & holder=$!
  got=$(head -c 1500M < <("$BIN" client nc -c "$B/client.toml" $H 5203 < "$B/ncfifo") | wc -c)
  t1=$(date +%s.%N)
  kill $holder 2>/dev/null
  [ "$got" = "$N" ] || { echo "ERR got $got bytes"; exit 1; }
  echo "$t0 $t1" | awk -v n=$N '{printf "%.1f\n", n*8/($2-$1)/1e6}'
  exit 0
fi
t1=$(date +%s.%N)
echo "$t0 $t1" | awk -v n=$N '{printf "%.1f\n", n*8/($2-$1)/1e6}'

#!/bin/bash
# ftb.sh: the benchmark helpers on the Linux server and client VMs, run over ssh by
# bench/run.py. Everything lives in the staging dir that bench/stage.py fills.
set -u
export PATH=$PATH:/usr/sbin
B=$HOME/codes/staging-area/flextunnel-bench
LOGENV='RUST_LOG=info,iroh=warn,tracing=warn,flextunnel_core::transport::paths=debug'

stat() {
  # UDP receives refused for want of socket buffer (v4 + v6), and the flextunnel process's CPU ticks.
  local e4 e6 pid cpu=0
  e4=$(awk '/^Udp:/{ if (!h) { for (i=1;i<=NF;i++) if ($i=="RcvbufErrors") c=i; h=1 } else print $c }' /proc/net/snmp)
  e6=$(awk '$1=="Udp6RcvbufErrors"{print $2}' /proc/net/snmp6)
  pid=$(pgrep -x flextunnel | head -1)
  [ -n "$pid" ] && cpu=$(awk '{print $14+$15}' /proc/$pid/stat 2>/dev/null)
  echo "STAT drops=$((e4+e6)) cpu=${cpu:-0} t=$(date +%s.%N)"
}

stop() {  # stop <unit>...
  local u i=0
  for u in "$@"; do
    sudo systemctl stop "ftb-$u" 2>/dev/null
    sudo systemctl reset-failed "ftb-$u" 2>/dev/null
  done
  while pgrep -x flextunnel >/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
  pgrep -x flextunnel >/dev/null && { echo "ERR flextunnel still running"; return 1; }
  return 0
}

launch() {  # launch <unit> <log> <version> <args...>
  local unit=$1 log=$2 v=$3; shift 3
  : > "$log"
  sudo systemd-run -q --unit="ftb-$unit" --uid="$(id -u)" --gid="$(id -g)" \
    -p StandardOutput=append:"$log" -p StandardError=append:"$log" \
    -E "$LOGENV" ${FTB_WORKERS:+-E TOKIO_WORKER_THREADS=$FTB_WORKERS} \
    "$B/bin/$v/flextunnel" "$@" || { echo "ERR systemd-run"; return 1; }
}

waitlog() {  # waitlog <log> <pattern> <tenths>
  local i=0
  while ! grep -q "$2" "$1" 2>/dev/null; do
    sleep 0.1; i=$((i+1)); [ $i -ge "$3" ] && return 1
  done
  return 0
}

case "$1" in
  stat) stat ;;
  stop) stop server client ;;
  iperf3)  # iperf3 on|off: the iperf3 server the runs connect to, on all addresses
    sudo systemctl stop ftb-iperf3 2>/dev/null; sudo systemctl reset-failed ftb-iperf3 2>/dev/null
    [ "$2" = on ] && sudo systemd-run -q --unit=ftb-iperf3 --uid="$(id -u)" -p StandardOutput=null iperf3 -s
    true
    ;;
  server)
    stop server || exit 1
    launch server "$B/server.log" "$2" server start -c "$B/server.toml" || exit 1
    waitlog "$B/server.log" "Node ID" 200 || { echo "ERR server not up"; tail -5 "$B/server.log"; exit 1; }
    grep -m1 -o 'flextunnel-cli v[0-9.]*' "$B/server.log"
    ;;
  client)
    stop client || exit 1
    launch client "$B/client.log" "$2" client start -c "$B/client.toml" || exit 1
    waitlog "$B/client.log" "listening on 127.0.0.1:5301" 200 || { echo "ERR client not up"; tail -5 "$B/client.log"; exit 1; }
    # Connect the destination without sending bulk: read sshd's banner through a second forward.
    timeout 15 bash -c 'exec 3<>/dev/tcp/127.0.0.1/5322; head -c 4 <&3 >/dev/null' || { echo "ERR warm-up connect"; tail -5 "$B/client.log"; exit 1; }
    i=0
    while :; do
      last=$(grep -o 'Connection: .*' "$B/client.log" | tail -1)
      case "$last" in "Connection: Direct"*) break ;; esac
      sleep 0.2; i=$((i+1)); [ $i -ge 100 ] && { echo "ERR no direct path: $last"; exit 1; }
    done
    sleep 1
    grep -m1 -o 'flextunnel-cli v[0-9.]*' "$B/client.log"
    echo "PATH $(grep -o 'Connection: .*' "$B/client.log" | tail -1)"
    ;;
  run)  # run <up|down> <seconds> <flows> <host> <port>
    dir=$2; t=$3; flows=$4; host=$5; port=$6
    r=""; [ "$dir" = down ] && r="-R"
    for attempt in 1 2 3; do
      stat
      out=$(iperf3 -J -t "$t" -O 1 -P "$flows" -c "$host" -p "$port" $r 2>&1)
      stat
      if echo "$out" | grep -q '"sum_received"'; then echo "$out"; exit 0; fi
      echo "RETRY $(echo "$out" | grep -o '"error":.*' | head -1)"
      sleep 2
    done
    echo "ERR iperf3 failed"; exit 1
    ;;
  tspath)  # tspath <tailscale ip>: how Tailscale reaches that peer (direct address or relay)
    tailscale ping -c 1 --timeout 5s "$2" 2>&1 | tail -1
    ;;
  listen)  # listen sink|zeros|source|off: a listener on the server's loopback, detached from this session
    case "$2" in
      sink)   setsid nohup nc -l -d 127.0.0.1 5202 </dev/null >/dev/null 2>&1 & ;;
      zeros)  setsid nohup sh -c 'head -c 1500M /dev/zero | nc -l -N 127.0.0.1 5203' </dev/null >/dev/null 2>&1 & ;;
      source) setsid nohup "$HOME/.local/bin/uv" run --python 3.13 "$B/source.py" 5210 </dev/null >"$B/source.log" 2>&1 &
              echo $! > "$B/source.pid" ;;
      off)    pkill -x nc; pkill -x head
              [ -f "$B/source.pid" ] && { pkill -g "$(cat "$B/source.pid")" 2>/dev/null; kill "$(cat "$B/source.pid")" 2>/dev/null; rm -f "$B/source.pid"; }
              true ;;
    esac
    sleep 0.5
    ;;
  lastpath) echo "PATH $(grep -o 'Connection: .*' "$B/client.log" | tail -1)" ;;
  *) echo "usage: ftb.sh stat|stop|iperf3 on|off|server V|client V|run DIR SECS FLOWS HOST PORT|tspath IP|listen KIND|lastpath"; exit 2 ;;
esac

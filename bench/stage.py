#!/usr/bin/env python3
"""stage.py LABEL --version NAME=DIR [--version NAME=DIR ...] [--mac] [--win] [--reboot]

Prepares a benchmark session from nothing on the hosts: they are wiped between sessions,
so everything a session needs is made here and copied out. Run it with uv:
    uv run --python 3.13 bench/stage.py r115-vs-r114 --version r114=target/bench/bin/r114 ...

Each version DIR holds that version's release binaries under their release names
(flextunnel-linux-amd64, and flextunnel-macos-arm64 / flextunnel-windows-amd64.exe for
--mac / --win). --win also needs iperf3 for Windows (iperf3.exe and cygwin1.dll, from
ar51an/iperf3-win-builds) in target/bench/tools/iperf3-win. The VMs need passwordless
sudo, and Tailscale for the control rows. The session's keys, configs, addresses and results go to
target/bench/LABEL (session.json). Host addresses are read off the machines, never stored
in the repo. Hosts are the ssh aliases test1 (server), test2 (client), macvm and
windows-ci-build; FTB_SERVER / FTB_CLIENT / FTB_MAC / FTB_WIN override them."""
import argparse, json, os, re, shlex, subprocess, sys, time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.join(REPO, "bench")
SERVER = os.environ.get("FTB_SERVER", "test1")
CLIENT = os.environ.get("FTB_CLIENT", "test2")
MAC = os.environ.get("FTB_MAC", "macvm")
WIN = os.environ.get("FTB_WIN", "windows-ci-build")
VM_DIR = "codes/staging-area/flextunnel-bench"  # under the VM user's home
MAC_DIR = "codes/staging-area/flextunnel-bench"
WIN_DIR = r"C:\ci-workspaces\flextunnel-bench"
IPERF3_WIN = os.path.join(REPO, "target/bench/tools/iperf3-win")  # iperf3.exe + cygwin1.dll

FORWARDS = """
# iperf3 on the server machine
[[forwards]]
local_port = 5301
remote_host = "t1.localhost.flextunnel.internal"
remote_port = 5201

# sshd's banner, read once to connect the destination before a run
[[forwards]]
local_port = 5322
remote_host = "t1.localhost.flextunnel.internal"
remote_port = 22

# the source that writes for as long as it is taken (memory rows)
[[forwards]]
local_port = 5302
remote_host = "t1.localhost.flextunnel.internal"
remote_port = 5210
"""


def sh(cmd, **kw):
    p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if p.returncode:
        raise SystemExit(f"failed ({p.returncode}): {cmd}\n{p.stdout}{p.stderr}")
    return p.stdout


def ssh(host, cmd, timeout=600):
    return sh(["ssh", "-o", "BatchMode=yes", host, cmd], timeout=timeout)


def pwsh(script, timeout=600):
    return sh(["pwsh", "-NoLogo", "-NoProfile", "-Command", script], timeout=timeout)


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def reboot(hosts):
    for h in hosts:
        subprocess.run(["ssh", "-o", "BatchMode=yes", h, "sudo systemctl reboot"], capture_output=True, timeout=30)
    time.sleep(20)
    for h in hosts:
        for _ in range(60):
            if subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", h, "true"],
                              capture_output=True).returncode == 0:
                break
            time.sleep(5)
        else:
            raise SystemExit(f"{h} did not come back after the reboot")
        log(f"{h} up: {ssh(h, 'uptime').strip()}")


def addresses():
    a4 = ssh(SERVER, "ip -4 -o addr show dev eth0 scope global | awk '{print $4}' | cut -d/ -f1").split()
    a6 = ssh(SERVER, "ip -6 -o addr show dev eth0 scope global | awk '{print $4}' | cut -d/ -f1").split()
    ts4 = ssh(SERVER, "tailscale ip -4 2>/dev/null || true").split()
    if len(a4) != 1:
        raise SystemExit(f"expected one IPv4 address on {SERVER}'s eth0: {a4}")
    return a4[0], a6, (ts4[0] if ts4 else None)


def keys(out, linux_bin):
    k = os.path.join(out, "keys")
    os.makedirs(k, exist_ok=True)
    sk, ck = os.path.join(k, "server.key"), os.path.join(k, "client.key")
    if not os.path.exists(sk):
        sh([linux_bin, "generate-iroh-key", "-o", sk])
    if not os.path.exists(ck):
        sh(["flexaccess-keys", "generate-auth-key", "bench", "-o", ck])
    node = re.search(r"\b[0-9a-f]{64}\b", sh([linux_bin, "show-iroh-id", "--secret-file", sk]))[0]
    pub = re.search(r"ed25519-pub:\S+", sh(["flexaccess-keys", "show-auth-key", "--private-key-file", ck]))[0]
    with open(os.path.join(k, "authorized_keys"), "w") as f:
        f.write(f"{pub} bench\n")
    return k, node


def client_toml(key_path, node):
    return (f'auth_key_file = "{key_path}"\nidle_timeout_secs = 0\n\n'
            f'[[destinations]]\nname = "t1"\nserver_node_id = "{node}"\n' + FORWARDS)


def stage_vms(out, k, node, versions):
    home = ssh(SERVER, "echo $HOME").strip()
    b = f"{home}/{VM_DIR}"
    with open(os.path.join(out, "server.toml"), "w") as f:
        f.write(f'secret_file = "{b}/server.key"\nauthorized_keys_file = "{b}/authorized_keys"\n')
    with open(os.path.join(out, "client.toml"), "w") as f:
        f.write(client_toml(f"{b}/client.key", node))
    for h in (SERVER, CLIENT):
        if ssh(h, "echo $HOME").strip() != home:
            raise SystemExit("the two VMs' users need the same home directory")
        ssh(h, f"mkdir -p {VM_DIR}/bin && chmod 700 {VM_DIR}")
        # iperf3 and the uv-managed Python the readers and the source run on.
        ssh(h, "command -v iperf3 >/dev/null || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q iperf3", timeout=900)
        ssh(h, "[ -x ~/.local/bin/uv ] || curl -LsSf https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh; "
               "~/.local/bin/uv python install 3.13 >/dev/null 2>&1", timeout=900)
        files = [os.path.join(HERE, "vm", n) for n in ("ftb.sh", "nc.sh", "readers.py", "source.py")]
        if h == SERVER:
            files += [os.path.join(out, "server.toml"), os.path.join(k, "server.key"), os.path.join(k, "authorized_keys")]
        else:
            files += [os.path.join(out, "client.toml"), os.path.join(k, "client.key")]
        sh(["rsync", "-a", "--chmod=F600,Fu+x", *files, f"{h}:{VM_DIR}/"])
        ssh(h, f"chmod 700 {VM_DIR}/*.sh")
        for name, d in versions.items():
            ssh(h, f"mkdir -p {VM_DIR}/bin/{name}")
            sh(["rsync", "-a", "--chmod=F755", os.path.join(d, "flextunnel-linux-amd64"), f"{h}:{VM_DIR}/bin/{name}/flextunnel"])
            log(f"{h} {name}: {ssh(h, f'{VM_DIR}/bin/{name}/flextunnel --version').strip()}")
    ssh(SERVER, f"{VM_DIR}/ftb.sh iperf3 on")


def stage_mac(out, k, node, versions, server4, ts4):
    home = ssh(MAC, "echo $HOME").strip()
    b = f"{home}/{MAC_DIR}"
    with open(os.path.join(out, "client-mac.toml"), "w") as f:
        f.write(client_toml(f"{b}/client.key", node))
    with open(os.path.join(out, "hosts.env"), "w") as f:
        f.write(f"SERVER4={server4}\nSERVER_TS4={ts4 or ''}\n")
    ssh(MAC, f"mkdir -p {MAC_DIR} && chmod 700 {MAC_DIR}")
    sh(["rsync", "-a", "--chmod=F600", os.path.join(k, "client.key"), os.path.join(out, "hosts.env"), f"{MAC}:{MAC_DIR}/"])
    sh(["rsync", "-a", "--chmod=F600", os.path.join(out, "client-mac.toml"), f"{MAC}:{MAC_DIR}/client.toml"])
    sh(["rsync", "-a", "--chmod=F755", os.path.join(HERE, "mac", "mb.sh"), f"{MAC}:{MAC_DIR}/"])
    for name, d in versions.items():
        sh(["rsync", "-a", "--chmod=F755", os.path.join(d, "flextunnel-macos-arm64"), f"{MAC}:{MAC_DIR}/flextunnel-{name}"])
        log(f"{MAC} {name}: {ssh(MAC, f'{MAC_DIR}/flextunnel-{name} --version').strip()}")


def stage_win(out, k, node, versions, server4):
    with open(os.path.join(out, "client-win.toml"), "w") as f:
        f.write(client_toml(WIN_DIR.replace("\\", "/") + "/client.key", node))
    with open(os.path.join(out, "hosts.json"), "w") as f:
        json.dump({"server4": server4}, f)
    copies = [(os.path.join(k, "client.key"), "client.key"), (os.path.join(out, "client-win.toml"), "client.toml"),
              (os.path.join(out, "hosts.json"), "hosts.json"),
              (os.path.join(IPERF3_WIN, "iperf3.exe"), r"iperf3\iperf3.exe"),
              (os.path.join(IPERF3_WIN, "cygwin1.dll"), r"iperf3\cygwin1.dll")]
    copies += [(os.path.join(d, "flextunnel-windows-amd64.exe"), f"flextunnel-{n}.exe") for n, d in versions.items()]
    lines = [f"$s = New-PSSession -HostName {WIN} -SSHTransport",
             f"Invoke-Command -Session $s -ScriptBlock {{ New-Item -ItemType Directory -Force '{WIN_DIR}\\iperf3' | Out-Null }}"]
    lines += [f"Copy-Item -ToSession $s -Path {shlex.quote(src)} -Destination '{WIN_DIR}\\{dst}'" for src, dst in copies]
    lines += [f"Invoke-Command -Session $s -ScriptBlock {{ & '{WIN_DIR}\\flextunnel-{n}.exe' --version }}" for n in versions]
    lines += ["Remove-PSSession $s"]
    log(f"{WIN}: {' / '.join(pwsh('; '.join(lines)).split())}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("label")
    ap.add_argument("--version", action="append", required=True, metavar="NAME=DIR")
    ap.add_argument("--mac", action="store_true")
    ap.add_argument("--win", action="store_true")
    ap.add_argument("--reboot", action="store_true", help="reboot the two VMs first")
    a = ap.parse_args()
    versions = dict(v.split("=", 1) for v in a.version)
    versions = {n: os.path.abspath(d) for n, d in versions.items()}
    out = os.path.join(REPO, "target/bench", a.label)
    os.makedirs(out, exist_ok=True)
    if a.reboot:
        reboot([SERVER, CLIENT])
    server4, server6, ts4 = addresses()
    log(f"{SERVER}: {server4} {server6} tailscale {ts4}")
    k, node = keys(out, os.path.join(next(iter(versions.values())), "flextunnel-linux-amd64"))
    stage_vms(out, k, node, versions)
    if a.mac:
        stage_mac(out, k, node, versions, server4, ts4)
    if a.win:
        stage_win(out, k, node, versions, server4)
    session = {"label": a.label, "versions": list(versions), "server4": server4, "server6": server6,
               "tailscale4": ts4, "node_id": node, "hosts": {"server": SERVER, "client": CLIENT, "mac": MAC, "win": WIN},
               "staged": time.time()}
    with open(os.path.join(out, "session.json"), "w") as f:
        json.dump(session, f, indent=1)
    log(f"staged: {out}/session.json")


if __name__ == "__main__":
    main()

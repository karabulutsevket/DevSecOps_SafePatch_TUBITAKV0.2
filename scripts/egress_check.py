"""Week 10 egress test: does any SafePatch process reach beyond this machine (docs/OLCUM_EGRESS.md)?

The whole product works once while three instruments watch, each proven by a deliberate control:
- a kernel ETW trace of the Windows host (scripts/egress_trace.ps1, started elevated by the
  operator): every TCP/UDP event with its process id, every process start with its parent, every
  DNS query;
- a probe inside WSL, where Semgrep and Docker run, reading /proc/net every 50 ms;
- the controls: on each side a process resolves an .invalid name and sends to 192.0.2.1
  (TEST-NET-1, reserved for documentation, never routed); the instruments must see them.

Steps: `users` (test identities for this run only), the operator starts the trace, `probe` (inside
WSL, in the background), restart Ollama and the services with USERS_FILE and a fresh DATABASE_URL,
`run` (controls; one synthetic job through review, memory and staging; a second job from memory;
rollback; a quiet minute; then it ends the trace), `analyze`. Only SafePatch's own process tree
reaches the evidence; the machine's other traffic stays in .runtime and is only counted.
"""
import argparse
from collections import defaultdict
from datetime import datetime
import ipaddress
import itertools
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / ".runtime" / "egress"
CONTROL_ADDRESS, CONTROL_PORT = "192.0.2.1", 9   # TEST-NET-1 (RFC 5737)
KERNEL_PROCESS, KERNEL_NETWORK, DNS_CLIENT = "Microsoft-Windows-Kernel-Process", "Microsoft-Windows-Kernel-Network", "Microsoft-Windows-DNS-Client"
TCP_EVENTS, UDP_EVENTS = set(range(10, 19)) | set(range(26, 35)), set(range(42, 50)) | set(range(58, 66))
TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
              "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}
# Run by each control process: a DNS name nobody owns, a TCP attempt and a connected UDP datagram
# to an address that is never routed. The UDP socket stays open briefly so a sampling probe sees it.
CONTROL = """
import socket, sys, time
try:
    socket.getaddrinfo(sys.argv[1], 443)
except OSError:
    pass
tcp = socket.socket()
tcp.settimeout(float(sys.argv[2]))
try:
    tcp.connect(("192.0.2.1", 9))
except OSError:
    pass
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.connect(("192.0.2.1", 9))
udp.send(b"safepatch-egress-control")
time.sleep(0.5)
"""


# --- inside WSL (standard library only) ---

def endpoint(text):
    """'0100007F:1F90' or a 32-digit IPv6 address from /proc/net, as (address, port)."""
    host, port = text.split(":")
    raw = bytes.fromhex(host)
    if len(raw) == 4:
        address = ipaddress.IPv4Address(raw[::-1])
    else:
        address = ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    return str(address), int(port, 16)


def remote_sockets(text, proto):
    """Sockets of one /proc/net table with a peer beyond this machine: not listening, not loopback."""
    found = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4:
            continue
        (laddr, lport), (raddr, rport), state = endpoint(fields[1]), endpoint(fields[2]), fields[3]
        peer = ipaddress.ip_address(raddr)
        peer = getattr(peer, "ipv4_mapped", None) or peer
        if rport == 0 or peer.is_unspecified or peer.is_loopback:
            continue
        found.append({"proto": proto, "local": f"{laddr}:{lport}", "remote": f"{raddr}:{rport}",
                      "state": TCP_STATES.get(state, state) if proto == "tcp" else state,
                      "uid": int(fields[7]) if len(fields) > 9 else None, "inode": fields[9] if len(fields) > 9 else None})
    return found


def owner(inode):
    """The process holding a socket inode, if this account may read its descriptors."""
    if not inode or inode == "0":
        return None
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            for fd in (proc / "fd").iterdir():
                if os.readlink(fd) == f"socket:[{inode}]":
                    return {"pid": int(proc.name), "comm": (proc / "comm").read_text().strip()}
        except OSError:
            continue
    return None


def probe(out, stop, interval=0.05, limit=7200):
    seen, samples, start = {}, 0, time.time()
    tables = [("/proc/net/" + name, name.rstrip("6")) for name in ("tcp", "tcp6", "udp", "udp6")]
    while time.time() - start < limit:
        for path, proto in tables:
            try:
                text = Path(path).read_text()
            except OSError:
                continue
            for s in remote_sockets(text, proto):
                key = (s["proto"], s["local"], s["remote"])
                if key not in seen:
                    seen[key] = {**s, "process": owner(s["inode"]), "first": time.time(), "seen": 0}
                entry = seen[key]
                entry.update(last=time.time(), state=s["state"])
                entry["seen"] += 1
        samples += 1
        if samples % 20 == 0 and Path(stop).exists():
            break
        time.sleep(interval)
    Path(out).write_text(json.dumps({"started": start, "stopped": time.time(), "samples": samples, "interval": interval,
                                     "sockets": sorted(seen.values(), key=lambda e: e["first"])}, indent=2))


# --- the run on Windows ---

def users():
    sys.path.insert(0, str(ROOT))
    from safepatch.common import digest
    FOLDER.mkdir(parents=True, exist_ok=True)
    roles = {"developer": "submit", "reviewer": "review", "deployer": "deploy"}
    tokens = {role: secrets.token_hex(32) for role in roles}
    (FOLDER / "users.json").write_text(json.dumps([{"subject": "SIMULATED-egress-" + role, "roles": [permission], "token_sha256": digest(tokens[role]),
                                                    "projects": ["owned-java-demo"]} for role, permission in roles.items()]), encoding="utf-8")
    (FOLDER / "tokens.json").write_text(json.dumps(tokens), encoding="utf-8")
    print("test identities:", FOLDER / "users.json", "- tokens stay in", FOLDER / "tokens.json", "and are never printed")


def local_addresses():
    out = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-NetIPAddress | ForEach-Object IPAddress"],
                         capture_output=True, text=True, check=True).stdout
    return sorted({line.strip().split("%")[0] for line in out.splitlines() if line.strip()})


def workload(tokens, record):
    """One synthetic job through review, memory and staging, a second job from memory, a rollback.
    Every human decision is SIMULATED by the test identities of `users`."""
    from safepatch.common import request
    base = os.environ.get("SAFEPATCH_URL", "http://127.0.0.1:8100")
    steps = record.setdefault("steps", [])

    def call(name, method, path, role, body=None, timeout=60):
        started = time.time()
        try:
            result = request(base + path, method, token=tokens[role], body=body, timeout=timeout)
            steps.append({"step": name, "ok": True, "seconds": round(time.time() - started, 1)})
            return result
        except Exception as exc:   # recorded; the egress observation stays valid either way
            steps.append({"step": name, "ok": False, "error": type(exc).__name__ + ": " + str(exc)[:200]})
            return None

    def job(name):
        j = call(name + ".create", "POST", "/v1/jobs", "developer", {"case_id": "sql-01", "scanner": "semgrep", "max_attempts": 3,
                                                                       "memory_mode": "guarded", "idempotency_key": uuid.uuid4().hex})
        deadline = time.monotonic() + 1500
        while j and j["status"] in ("queued", "scanning", "patching", "verifying") and time.monotonic() < deadline:
            time.sleep(3)
            try:
                j = request(base + "/v1/jobs/" + j["id"], token=tokens["developer"])
            except Exception:   # a slow answer while the model works; ask again
                continue
        if j:
            steps.append({"step": name + ".result", "ok": j["status"] == "awaiting_review", "job": j["id"], "status": j["status"],
                          "reason": j.get("reason"), "memory_ids": j.get("memory_ids", []),
                          "candidate": {k: j.get("candidate", {}).get(k) for k in ("evidence_sha256", "artifact_sha256", "origin")} if j.get("candidate") else None})
        return j if j and j["status"] == "awaiting_review" else None

    def approve_and_deploy(name, j, promote):
        c = j["candidate"]
        if not call(name + ".approve", "POST", f'/v1/jobs/{j["id"]}/approval', "reviewer", {"candidate_commit": c["commit"], "artifact_sha256": c["artifact_sha256"],
                    "policy_version": c["policy_version"], "decision": "approve", "comment": "SIMULATED egress test approval"}):
            return False
        if promote:
            call(name + ".promote", "POST", "/v1/memory/promote", "reviewer", {"job_id": j["id"], "reason": "SIMULATED egress test promotion"})
        return bool(call(name + ".deploy", "POST", f'/v1/jobs/{j["id"]}/deploy', "deployer", timeout=180))

    deployed = 0
    first = job("first")
    if first:
        deployed += approve_and_deploy("first", first, promote=True)
    second = job("second")
    if second:
        deployed += approve_and_deploy("second", second, promote=False)
    if deployed == 2:
        call("rollback", "POST", "/v1/staging/rollback", "deployer", timeout=180)


def run(quiet=60):
    sys.path.insert(0, str(ROOT))
    if not (FOLDER / "trace.started").exists() or (FOLDER / "trace.stopped").exists():
        raise SystemExit("the ETW trace is not running (scripts/egress_trace.ps1, elevated)")
    tokens = json.loads((FOLDER / "tokens.json").read_text(encoding="utf-8"))
    record = {"run_pid": os.getpid(), "started": time.time(), "local_addresses": local_addresses(),
              "services": json.loads((ROOT / ".runtime" / "services.json").read_text(encoding="utf-8-sig")),
              "ollama_pid": int((ROOT / ".runtime" / "ollama.pid").read_text(encoding="utf-8-sig").strip()),
              "control_target": f"{CONTROL_ADDRESS}:{CONTROL_PORT}"}
    try:
        controls = {}
        for side, command, timeout in (("host", [sys.executable, "-c", CONTROL], "1"),
                                       ("wsl", ["wsl.exe", "-d", os.environ.get("WSL_DISTRO", "Debian"), "--exec", "python3", "-c", CONTROL], "3")):
            name = f"{side}-egress-control-{uuid.uuid4().hex[:12]}.invalid"
            started = time.time()
            process = subprocess.Popen([*command, name, timeout])
            process.wait(90)
            controls[side] = {"pid": process.pid, "name": name, "started": started, "finished": time.time()}
        record["controls"] = controls
        workload(tokens, record)
        record["workload_finished"] = time.time()
        time.sleep(quiet)   # background activity after the work: none expected
    finally:
        record["finished"] = time.time()
        (FOLDER / "run.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        (FOLDER / "stop").write_text("stop", encoding="utf-8")   # ends the trace and the probe
    print(json.dumps({"steps": record.get("steps"), "controls": list(record.get("controls", {}))}, indent=1))


# --- the analysis ---

def epoch(text, offset=True):
    """An ETW time (up to 100 ns digits) as seconds since the epoch. offset=False reads the clock
    as written: tracerpt writes event times in local time with a wrong offset (+02:59 for +03:00
    here), so those are corrected later against the processes' own UTC times (`clock_shift`)."""
    clock, zone = text[:19], text[19:]
    fraction = "".join(itertools.takewhile(str.isdigit, zone[1:])) if zone.startswith(".") else ""
    zone = zone[1 + len(fraction):] if fraction else zone
    zone = zone.replace("Z", "+00:00") if offset and zone else "+00:00"
    return datetime.fromisoformat(clock + ("." + fraction[:6].ljust(6, "0") if fraction else "") + zone).timestamp()


KEPT = {"ProcessID", "ParentProcessID", "ImageName", "CreateTime", "ExitTime", "PID", "daddr", "saddr", "dport", "sport", "QueryName",
        "EventsLost", "BuffersLost"}


def read_events(path):
    """The events of a tracerpt XML file, streamed: provider, id, time, header process id and the
    few data fields the analysis uses (a trace of the whole machine is large)."""
    root = None
    for kind, element in ET.iterparse(path, events=("start", "end")):
        if root is None:
            root = element
        if kind != "end" or element.tag.rsplit("}", 1)[-1] != "Event":
            continue
        system = next((child for child in element if child.tag.endswith("System")), None)
        data = next((child for child in element if child.tag.endswith("EventData")), None)
        if system is not None:
            fields = {child.tag.rsplit("}", 1)[-1]: child for child in system}
            provider, execution = fields.get("Provider"), fields.get("Execution")
            yield {"provider": provider.get("Name") if provider is not None else None,
                   "id": int(fields["EventID"].text) if "EventID" in fields else None,
                   "time": epoch(fields["TimeCreated"].get("SystemTime"), offset=False) if "TimeCreated" in fields else None,
                   "pid": int(execution.get("ProcessID")) if execution is not None and execution.get("ProcessID") else None,
                   "data": {d.get("Name"): (d.text or "").strip() for d in data if d.get("Name") in KEPT} if data is not None else {}}
        root.clear()   # the events already read are not kept


def clock_shift(events):
    """Seconds to subtract from the trace's event times: the median gap between a process event's
    time and the UTC create or exit time it carries (0 when the trace has none)."""
    gaps = sorted(e["time"] - epoch(e["data"].get("CreateTime") or e["data"]["ExitTime"]) for e in events
                  if e["provider"] == KERNEL_PROCESS and (e["data"].get("CreateTime") or e["data"].get("ExitTime")) and e["time"] is not None)
    return round(gaps[len(gaps) // 2], 3) if gaps else 0.0


class Processes:
    """Process instances from the trace (a process id is reused, so an instance is pid + start)."""
    def __init__(self, events, shift=0.0):
        self.starts, self.stops = defaultdict(list), defaultdict(list)
        for e in events:
            if e["provider"] == KERNEL_PROCESS and e["id"] == 1:
                t = epoch(e["data"]["CreateTime"]) if e["data"].get("CreateTime") else e["time"] - shift
                self.starts[int(e["data"]["ProcessID"])].append((t, int(e["data"].get("ParentProcessID") or 0), Path(e["data"].get("ImageName", "").replace("\\", "/")).name))
            elif e["provider"] == KERNEL_PROCESS and e["id"] == 2:
                self.stops[int(e["data"]["ProcessID"])].append(epoch(e["data"]["ExitTime"]) if e["data"].get("ExitTime") else e["time"] - shift)
        for items in self.starts.values():
            items.sort()

    def at(self, pid, t):
        """The instance (pid, start) alive at time t; start is None for a process older than the trace."""
        begun = [s for s in self.starts[pid] if s[0] <= t]
        start = begun[-1][0] if begun else None
        if any((start is None or s > start) and s <= t for s in self.stops[pid]):
            return None
        return (pid, start)

    def started(self):
        return sorted((s[0], pid, s[1], s[2]) for pid, items in self.starts.items() for s in items)


def tree(processes, roots):
    """Label every instance descended from a root instance: {instance: (label, image)}."""
    members = {}
    for label, pid, t in roots:
        instance = processes.at(pid, t)
        if instance:
            image = next((s[2] for s in processes.starts[pid] if s[0] == instance[1]), None)
            members[instance] = (label, image)
    for start, pid, parent, image in processes.started():
        source = processes.at(parent, start)
        if source in members and (pid, start) not in members:
            members[(pid, start)] = (members[source][0], image)
    return members


def beyond(address, local):
    """Neither loopback, unspecified nor one of this machine's own addresses; unreadable counts as beyond."""
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
    except ValueError:
        return bool(address)
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return not (ip.is_loopback or ip.is_unspecified or str(ip) in local)


def assess(events, network, run, wsl):
    """events: process and DNS events (a list); network: the Kernel-Network events (any iterable)."""
    shift = clock_shift(events)
    processes = Processes(events, shift)
    at_run = run["started"]
    roots = [(s["service"], int(s["pid"]), at_run) for s in run["services"]] + [("ollama", run["ollama_pid"], at_run), ("run", run["run_pid"], at_run)]
    roots += [("control-" + side, c["pid"], c["started"] + 0.5) for side, c in run.get("controls", {}).items()]
    members = tree(processes, roots)
    local = set(run["local_addresses"])
    flows, counts = defaultdict(lambda: {"events": 0}), defaultdict(int)
    for e in network:
        if e["provider"] != KERNEL_NETWORK or "daddr" not in e["data"]:
            continue
        pid, t = int(e["data"].get("PID") or e["pid"] or 0), e["time"] - shift
        member = members.get(processes.at(pid, t))
        remote = [(a, e["data"].get(p)) for a, p in ((e["data"].get("daddr"), "dport"), (e["data"].get("saddr"), "sport")) if a and beyond(a, local)]
        side = "member" if member else "other"
        counts[side + "_events"] += 1
        if not remote:
            continue
        counts[side + "_beyond_events"] += 1
        if member:
            for address, port in remote:
                flow = flows[(member[0], member[1], address, port, "tcp" if e["id"] in TCP_EVENTS else "udp" if e["id"] in UDP_EVENTS else str(e["id"]))]
                flow["events"] += 1
                flow["first"] = min(flow.get("first", t), t)
                flow["last"] = max(flow.get("last", t), t)
    flows = [{"label": k[0], "image": k[1], "remote": k[2], "port": k[3], "proto": k[4], **v} for k, v in sorted(flows.items(), key=lambda i: i[1]["first"])]
    controls = run.get("controls", {})
    control_name = lambda name: any(c["name"] in name for c in controls.values())
    # WSL resolves through the host (DNS tunnelling): the process that asked (event 3006, logged in
    # the caller) for the WSL control's name is the proxy, and its other questions during the run
    # are the WSL processes' questions. The DNS cache service logs the same name in its own events
    # too; it answers for the whole machine and must never be taken for the proxy.
    proxy = {e["pid"] for e in events if e["provider"] == DNS_CLIENT and e["id"] == 3006
             and controls.get("wsl", {}).get("name", "?") in (e["data"].get("QueryName") or "")}
    queries, other = defaultdict(lambda: {"events": 0}), 0
    for e in events:
        name = e["data"].get("QueryName") if e["provider"] == DNS_CLIENT else None
        if not name:
            continue
        t = e["time"] - shift
        member = members.get(processes.at(e["pid"], t)) if e["pid"] else None
        source = member[0] if member else None
        if not member and e["pid"] in proxy and t <= run["finished"]:
            source = "wsl-dns-proxy" if t >= run["started"] else "wsl-dns-proxy-before-run"
        if source or control_name(name):
            entry = queries[(name, source)]
            entry["events"] += 1
            entry["first"] = min(entry.get("first", t), t)
        else:
            other += 1
    dns = [{"name": k[0], "source": k[1], **v} for k, v in sorted(queries.items(), key=lambda i: i[1]["first"])]
    # localhost never leaves the machine; a name counts when SafePatch or WSL asked for it.
    asked = [d for d in dns if not control_name(d["name"]) and d["name"].lower() != "localhost" and d["source"]
             and not d["source"].startswith("control-") and d["source"] != "wsl-dns-proxy-before-run"]
    wsl_before = [d for d in dns if d["source"] == "wsl-dns-proxy-before-run" and not control_name(d["name"])]
    safepatch = [f for f in flows if not f["label"].startswith("control-")]
    seen = lambda side, proto: any(f["label"] == "control-" + side and f["remote"] == CONTROL_ADDRESS and f["proto"] == proto for f in flows)
    owners = {s["process"]["pid"] for s in wsl["sockets"] if s["remote"].split(":")[0] == CONTROL_ADDRESS and s.get("process")}
    is_control = lambda s: s["remote"].split(":")[0] == CONTROL_ADDRESS or (s.get("process") or {}).get("pid") in owners
    wsl_control = [s for s in wsl["sockets"] if is_control(s)]
    before = [s for s in wsl["sockets"] if not is_control(s) and s["first"] < run["started"]]
    during = [s for s in wsl["sockets"] if not is_control(s) and s["first"] >= run["started"]]
    header = next((e["data"] for e in events if "EventsLost" in e["data"]), {})
    return {
        "trace": {"clock_shift_seconds": shift, "events_lost": int(header["EventsLost"]) if "EventsLost" in header else None,
                  "buffers_lost": int(header["BuffersLost"]) if "BuffersLost" in header else None},
        "verdict": {"safepatch_flows_beyond_host": len(safepatch), "dns_names_asked_beyond_host": len(asked),
                    "wsl_sockets_beyond_host_during_run": len(during), "wsl_sockets_beyond_host_before_run": len(before),
                    "wsl_dns_names_before_run": len(wsl_before),
                    "instruments_proven": {"host_tcp": seen("host", "tcp"), "host_udp": seen("host", "udp"),
                                           "host_dns": any(d["source"] == "control-host" for d in dns),
                                           "wsl_tcp": any(s["proto"] == "tcp" and s["remote"].startswith(CONTROL_ADDRESS + ":") for s in wsl_control),
                                           "wsl_udp": any(s["proto"] == "udp" and s["remote"].startswith(CONTROL_ADDRESS + ":") for s in wsl_control),
                                           "wsl_dns_on_host": bool(proxy)}},
        "tree": {"instances": len(members), "by_label": {label: sorted({m[1] for m in members.values() if m[0] == label and m[1]}) for label in sorted({m[0] for m in members.values()})}},
        "safepatch_flows": safepatch, "control_flows": [f for f in flows if f["label"].startswith("control-")],
        "dns": {"asked_beyond_host": asked, "wsl_before_run": wsl_before,
                "local_or_control": [d for d in dns if d not in asked and d not in wsl_before], "other_queries_counted_only": other},
        "network_events": {**counts, "other_remote_addresses_counted_only": True},
        "wsl": {"samples": wsl["samples"], "interval_seconds": wsl["interval"], "control_sockets": wsl_control,
                "before_run": before, "during_run": during},
    }


def analyze():
    sys.path.insert(0, str(ROOT))
    from safepatch.common import digest, evidence
    run_record = json.loads((FOLDER / "run.json").read_text(encoding="utf-8"))
    xml = FOLDER / "trace.xml"
    if not xml.exists():
        subprocess.run(["tracerpt", str(FOLDER / "trace.etl"), "-o", str(xml), "-of", "XML", "-y"], check=True, capture_output=True)
    wsl = json.loads((FOLDER / "wsl.json").read_text(encoding="utf-8"))
    events = [e for e in read_events(xml) if e["provider"] != KERNEL_NETWORK]
    network = (e for e in read_events(xml) if e["provider"] == KERNEL_NETWORK)
    result = assess(events, network, run_record, wsl)
    out = evidence("olcum")
    if (out / "result.json").exists():
        raise SystemExit("evidence is never overwritten; use a fresh EVIDENCE_DIR")
    out.mkdir(parents=True, exist_ok=True)
    stamp = lambda name: (FOLDER / name).read_text(encoding="utf-8-sig").strip()
    protocol = {"schema": 1, "trace_started": stamp("trace.started"), "trace_stopped": stamp("trace.stopped"),
                "providers": (FOLDER / "providers.txt").read_text(encoding="ascii").splitlines(),
                "raw_sha256": {name: digest((FOLDER / name).read_bytes()) for name in ("trace.etl", "trace.xml", "wsl.json", "run.json")},
                "raw_location": ".runtime/egress (not in Git: the trace holds this machine's other traffic)",
                "control_target": run_record["control_target"], "services": run_record["services"], "ollama_pid": run_record["ollama_pid"],
                "run_pid": run_record["run_pid"], "run_started": run_record["started"], "run_finished": run_record["finished"],
                "human_decisions": "SIMULATED (test identities of this run only)"}
    (out / "protocol.json").write_text(json.dumps(protocol, indent=2) + "\n", encoding="utf-8")
    (out / "workload.json").write_text(json.dumps({"steps": run_record.get("steps", [])}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result["verdict"], indent=1), "\nwritten:", out)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("users")
    child = sub.add_parser("probe")
    child.add_argument("out")
    child.add_argument("stop")
    sub.add_parser("run").add_argument("--quiet", type=int, default=60)
    sub.add_parser("analyze")
    args = parser.parse_args(argv)
    if args.action == "probe":
        probe(args.out, args.stop)
    elif args.action == "users":
        users()
    elif args.action == "run":
        run(args.quiet)
    else:
        analyze()


if __name__ == "__main__":
    main()

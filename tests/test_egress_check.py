import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import egress_check as egress
from egress_check import DNS_CLIENT, KERNEL_NETWORK, KERNEL_PROCESS


def start(t, pid, parent, image):
    return {"provider": KERNEL_PROCESS, "id": 1, "time": t, "pid": parent, "data": {"ProcessID": str(pid), "ParentProcessID": str(parent), "ImageName": "\\Device\\HarddiskVolume3\\x\\" + image}}


def stop(t, pid):
    return {"provider": KERNEL_PROCESS, "id": 2, "time": t, "pid": pid, "data": {"ProcessID": str(pid)}}


def net(t, pid, daddr, dport, saddr="192.168.1.10", event=12):
    return {"provider": KERNEL_NETWORK, "id": event, "time": t, "pid": pid, "data": {"PID": str(pid), "daddr": daddr, "dport": str(dport), "saddr": saddr, "sport": "50000"}}


def dns(t, pid, name, event=3006):
    return {"provider": DNS_CLIENT, "id": event, "time": t, "pid": pid, "data": {"QueryName": name}}


RUN = {"started": 50.0, "finished": 200.0, "run_pid": 400, "ollama_pid": 300, "local_addresses": ["192.168.1.10", "fe80::1"],
       "services": [{"service": "runner", "pid": 100, "started": "x"}],
       "controls": {"host": {"pid": 600, "name": "host-egress-control-abc.invalid", "started": 60.0, "finished": 62.0},
                    "wsl": {"pid": 700, "name": "wsl-egress-control-def.invalid", "started": 63.0, "finished": 66.0}}}
WSL = {"samples": 100, "interval": 0.05, "sockets": [{"proto": "tcp", "local": "172.23.8.121:40000", "remote": "192.0.2.1:9", "state": "SYN_SENT",
                                                     "process": {"pid": 445, "comm": "python3"}, "first": 64.0}]}


def processes():
    return [start(10, 100, 1, "python.exe"), start(10.1, 101, 100, "python.exe"),   # venv launcher and the runner itself
            start(20, 300, 1, "ollama.exe"), start(45, 400, 1, "python.exe"),
            start(70, 102, 101, "java.exe"), stop(90, 102), start(95, 102, 999, "java.exe"),   # pid 102 reused by an unrelated process
            start(60, 600, 400, "python.exe"), start(60.1, 601, 600, "python.exe"), start(63, 700, 400, "wsl.exe"),
            start(5, 500, 1, "browser.exe")]


def test_only_the_safepatch_tree_is_attributed_and_listed():
    network = [net(80, 102, "203.0.113.5", 443),            # a build child of the runner reaches out: listed
               net(81, 101, "127.0.0.1", 8102, saddr="127.0.0.1", event=10),   # loopback between services: counted only
               net(96, 102, "198.51.100.7", 80),            # the reused pid belongs to someone else now
               net(97, 500, "8.8.8.8", 53, event=42),        # the rest of the machine: counted, never listed
               net(61, 601, "192.0.2.1", 9), net(61.5, 601, "192.0.2.1", 9, event=42)]
    queries = [dns(61, 601, "host-egress-control-abc.invalid"), dns(82, 101, "repo.example.org"), dns(83, 300, "localhost"),
               dns(98, 500, "private-site.example")]
    result = egress.assess(processes() + queries, network, RUN, WSL)
    assert [(f["label"], f["image"], f["remote"], f["port"], f["proto"]) for f in result["safepatch_flows"]] == [("runner", "java.exe", "203.0.113.5", "443", "tcp")]
    assert result["verdict"]["safepatch_flows_beyond_host"] == 1
    assert [(d["name"], d["source"]) for d in result["dns"]["asked_beyond_host"]] == [("repo.example.org", "runner")]   # localhost stays local
    assert result["verdict"]["instruments_proven"] == {"host_tcp": True, "host_udp": True, "host_dns": True, "wsl_tcp": True, "wsl_udp": False, "wsl_dns_on_host": False}
    assert result["network_events"]["member_events"] == 4 and result["network_events"]["other_beyond_events"] == 2
    assert result["dns"]["other_queries_counted_only"] == 1
    text = json.dumps(result)
    assert "8.8.8.8" not in text and "198.51.100.7" not in text and "private-site.example" not in text
    assert result["tree"]["by_label"]["runner"] == ["java.exe", "python.exe"]


def test_wsl_sockets_and_names_are_split_into_controls_before_and_during_the_run():
    sockets = [{"proto": "tcp", "local": "172.23.8.121:40000", "remote": "192.0.2.1:9", "state": "SYN_SENT", "process": {"pid": 445, "comm": "python3"}, "first": 64.0},
               {"proto": "udp", "local": "10.255.255.254:5000", "remote": "10.255.255.254:53", "state": "01", "process": {"pid": 445, "comm": "python3"}, "first": 63.9},
               {"proto": "tcp", "local": "172.23.8.121:39796", "remote": "2.16.168.61:80", "state": "TIME_WAIT", "process": None, "first": 21.0},
               {"proto": "tcp", "local": "172.23.8.121:39800", "remote": "203.0.113.9:443", "state": "ESTABLISHED", "process": {"pid": 900, "comm": "semgrep-core"}, "first": 120.0}]
    queries = [dns(63.5, 7220, "wsl-egress-control-def.invalid"), dns(119, 7220, "semgrep.example.dev"), dns(30, 7220, "boot.example.com"),
               # the DNS cache service logs every name, the WSL control's too; its other names are the machine's
               dns(63.6, 1500, "wsl-egress-control-def.invalid", event=3016), dns(110, 1500, "game.example.net", event=3016)]
    result = egress.assess(processes() + queries, [], RUN, {**WSL, "sockets": sockets})
    assert [s["remote"] for s in result["wsl"]["control_sockets"]] == ["192.0.2.1:9", "10.255.255.254:53"]
    assert [s["remote"] for s in result["wsl"]["before_run"]] == ["2.16.168.61:80"]
    assert [s["remote"] for s in result["wsl"]["during_run"]] == ["203.0.113.9:443"]
    assert [(d["name"], d["source"]) for d in result["dns"]["asked_beyond_host"]] == [("semgrep.example.dev", "wsl-dns-proxy")]
    assert result["verdict"]["instruments_proven"]["wsl_dns_on_host"] and result["verdict"]["wsl_sockets_beyond_host_during_run"] == 1
    assert [d["name"] for d in result["dns"]["wsl_before_run"]] == ["boot.example.com"]   # WSL starting up, listed apart
    assert "game.example.net" not in json.dumps(result) and result["dns"]["other_queries_counted_only"] == 1


def test_a_quiet_run_with_working_instruments_has_nothing_to_list():
    network = [net(61, 601, "192.0.2.1", 9), net(61.5, 601, "192.0.2.1", 9, event=42), net(81, 101, "127.0.0.1", 8102, saddr="127.0.0.1")]
    sockets = WSL["sockets"] + [{**WSL["sockets"][0], "proto": "udp", "state": "01"}]
    result = egress.assess(processes() + [dns(61, 601, "host-egress-control-abc.invalid"), dns(63.5, 7220, "wsl-egress-control-def.invalid")],
                           network, RUN, {**WSL, "sockets": sockets})
    verdict = result["verdict"]
    assert verdict["safepatch_flows_beyond_host"] == verdict["dns_names_asked_beyond_host"] == verdict["wsl_sockets_beyond_host_during_run"] == 0
    assert all(verdict["instruments_proven"].values())


def test_an_instrument_that_saw_nothing_is_reported_as_not_proven():
    result = egress.assess(processes(), [], RUN, {**WSL, "sockets": []})
    assert not any(result["verdict"]["instruments_proven"].values())


def test_trace_times_are_set_right_by_the_processes_own_utc_times():
    late = {**start(10, 100, 1, "python.exe"), "time": 10 + 10800}
    late["data"]["CreateTime"] = "1970-01-01T00:00:10Z"
    assert egress.clock_shift([late]) == 10800 and egress.clock_shift([]) == 0


def test_the_wsl_probe_reads_proc_net():
    table = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
             "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1\n"   # listening
             "   1: 0100007F:9C40 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 2\n"   # loopback
             "   2: 790817AC:9C41 010200C0:0009 02 00000000:00000000 00:00000000 00000000  1000        0 3\n")  # SYN to 192.0.2.1:9
    assert egress.remote_sockets(table, "tcp") == [{"proto": "tcp", "local": "172.23.8.121:40001", "remote": "192.0.2.1:9", "state": "SYN_SENT", "uid": 1000, "inode": "3"}]
    assert egress.endpoint("0000000000000000FFFF00000100007F:0050") == ("::ffff:127.0.0.1", 80)
    v6 = "   0: 00000000000000000000000000000000:9C40 0000000000000000FFFF00000100007F:1F90 01 0 0 0 0 0 1\n"
    assert egress.remote_sockets("header\n" + v6, "tcp") == []   # an IPv4-mapped loopback peer is still loopback


def test_tracerpt_xml_is_read_as_a_stream(tmp_path):
    xml = tmp_path / "trace.xml"
    xml.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Network" Guid="{7dd42a49-5329-4832-8dfd-43d979153a88}"/><EventID>12</EventID>
<TimeCreated SystemTime="2026-10-30T12:00:00.123456700Z"/><Execution ProcessID="4242" ThreadID="1"/></System>
<EventData><Data Name="PID">4242</Data><Data Name="size">0</Data><Data Name="daddr">192.0.2.1</Data><Data Name="saddr">192.168.1.10</Data><Data Name="dport">9</Data><Data Name="sport">50000</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-DNS-Client"/><EventID>3006</EventID>
<TimeCreated SystemTime="2026-10-30T12:00:01Z"/><Execution ProcessID="4242" ThreadID="1"/></System>
<EventData><Data Name="QueryName">host-egress-control-abc.invalid</Data><Data Name="QueryType">1</Data></EventData></Event>
</Events>""", encoding="utf-8")
    events = list(egress.read_events(str(xml)))
    assert [(e["provider"], e["id"], e["pid"]) for e in events] == [(KERNEL_NETWORK, 12, 4242), (DNS_CLIENT, 3006, 4242)]
    assert events[0]["data"] == {"PID": "4242", "daddr": "192.0.2.1", "saddr": "192.168.1.10", "dport": "9", "sport": "50000"}
    assert events[1]["data"] == {"QueryName": "host-egress-control-abc.invalid"}
    assert events[0]["time"] == egress.epoch("2026-10-30T12:00:00.123456Z")

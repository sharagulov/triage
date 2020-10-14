#!/usr/bin/env python3
"""
server-triage-toolkit — USE-method host triage for Linux (stdlib only).

Utilization, Saturation, and Errors signals for CPU, memory, and TCP.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Sequence


class Severity(str, Enum):
    OK = "OK"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class DetailLine:
    """One metric row; ``metric_severity`` drives highlight when the value is abnormal."""

    label: str
    value: str
    metric_severity: Severity = Severity.OK
    hint: str = ""


@dataclass(frozen=True)
class CheckResult:
    name: str
    severity: Severity
    summary: str
    details: tuple[DetailLine, ...] = ()
    recommendations: tuple[str, ...] = ()


@dataclass(frozen=True)
class LoadAvgSnapshot:
    load_1: float
    load_5: float
    load_15: float
    runnable: int
    total_tasks: int


@dataclass(frozen=True)
class MemInfoSnapshot:
    mem_total_kb: int
    mem_free_kb: int
    mem_available_kb: int
    buffers_kb: int
    cached_kb: int
    swap_total_kb: int
    swap_free_kb: int

    @property
    def page_cache_kb(self) -> int:
        return self.buffers_kb + self.cached_kb

    @property
    def reclaimable_pressure_kb(self) -> int:
        """Approximate bytes the kernel could still reclaim before hard pressure."""
        return max(0, self.mem_available_kb - self.mem_free_kb)


@dataclass(frozen=True)
class TcpSnapshot:
    time_wait: int
    established: int
    listen: int
    other: int
    high_send_q: int
    high_recv_q: int
    send_q_threshold: int
    recv_q_threshold: int
    source: str


PROC_ROOT = Path(os.environ.get("TRIAGE_PROC_ROOT", "/proc"))

# /proc/net/tcp state field (hex): 06 = TIME_WAIT
TCP_STATE_TIME_WAIT = "06"
TCP_STATE_ESTABLISHED = "01"
TCP_STATE_LISTEN = "0A"

DEFAULT_SEND_Q_THRESHOLD = 1024 * 1024  # 1 MiB in bytes (hex fields are bytes)
DEFAULT_RECV_Q_THRESHOLD = 1024 * 1024


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


class Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"


def colorize(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{code}{text}{Ansi.RESET}"


def severity_style(severity: Severity, enabled: bool) -> str:
    mapping = {
        Severity.OK: (Ansi.GREEN, "✓"),
        Severity.WARNING: (Ansi.YELLOW, "!"),
        Severity.CRITICAL: (Ansi.RED, "✗"),
    }
    code, glyph = mapping[severity]
    label = colorize(f"{glyph} {severity.value}", code + Ansi.BOLD, enabled)
    return label


def _metric_color(severity: Severity) -> str:
    if severity == Severity.CRITICAL:
        return Ansi.RED + Ansi.BOLD
    if severity == Severity.WARNING:
        return Ansi.YELLOW + Ansi.BOLD
    return Ansi.DIM


def format_detail_line(line: DetailLine, use_color: bool) -> str:
    prefix = f"    • {line.label}: "
    if line.metric_severity == Severity.OK:
        body = f"{line.value}"
        if line.hint:
            body = f"{body} ({line.hint})"
        return colorize(f"{prefix}{body}", Ansi.DIM, use_color)

    value_text = colorize(line.value, _metric_color(line.metric_severity), use_color)
    tag = colorize(f" [{line.metric_severity.value}]", _metric_color(line.metric_severity), use_color)
    hint = ""
    if line.hint:
        hint = colorize(f" — {line.hint}", Ansi.DIM, use_color)
    label_part = colorize(prefix, Ansi.BOLD, use_color) if use_color else prefix
    return f"{label_part}{value_text}{tag}{hint}"


def format_recommendation(index: int, text: str, use_color: bool) -> str:
    step = colorize(f"    [{index}]", Ansi.CYAN + Ansi.BOLD, use_color)
    return f"{step} {text}"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def parse_loadavg(content: str) -> LoadAvgSnapshot:
    parts = content.split()
    if len(parts) < 5:
        raise ValueError(f"unexpected loadavg format: {content!r}")
    runnable_total = parts[3].split("/")
    if len(runnable_total) != 2:
        raise ValueError(f"unexpected loadavg tasks field: {parts[3]!r}")
    return LoadAvgSnapshot(
        load_1=float(parts[0]),
        load_5=float(parts[1]),
        load_15=float(parts[2]),
        runnable=int(runnable_total[0]),
        total_tasks=int(runnable_total[1]),
    )


def cpu_core_count(proc_root: Path = PROC_ROOT) -> int:
    online = proc_root / "sys" / "devices" / "system" / "cpu" / "online"
    if online.is_file():
        match = re.search(r"(\d+)-(\d+)", read_text(online).strip())
        if match:
            return int(match.group(2)) - int(match.group(1)) + 1
    count = 0
    for entry in proc_root.glob("cpu[0-9]*"):
        if entry.name.startswith("cpu") and entry.name[3:].isdigit():
            count += 1
    return max(count, 1)


def parse_meminfo(content: str) -> MemInfoSnapshot:
    values: dict[str, int] = {}
    for line in content.splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        parts = rest.strip().split()
        if not parts:
            continue
        values[key.strip()] = int(parts[0])

    required = ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached")
    missing = [k for k in required if k not in values]
    if missing:
        raise ValueError(f"meminfo missing keys: {', '.join(missing)}")

    return MemInfoSnapshot(
        mem_total_kb=values["MemTotal"],
        mem_free_kb=values["MemFree"],
        mem_available_kb=values["MemAvailable"],
        buffers_kb=values["Buffers"],
        cached_kb=values["Cached"],
        swap_total_kb=values.get("SwapTotal", 0),
        swap_free_kb=values.get("SwapFree", 0),
    )


def _parse_hex_queue(value: str) -> int:
    if not value or value == "0":
        return 0
    return int(value, 16)


def parse_proc_net_tcp(
    content: str,
    send_q_threshold: int = DEFAULT_SEND_Q_THRESHOLD,
    recv_q_threshold: int = DEFAULT_RECV_Q_THRESHOLD,
) -> TcpSnapshot:
    time_wait = established = listen = other = 0
    high_send_q = high_recv_q = 0

    lines = content.splitlines()
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 5:
            continue
        state = fields[3].upper()
        tx_q, rx_q = fields[4].split(":")
        send_q = _parse_hex_queue(tx_q)
        recv_q = _parse_hex_queue(rx_q)

        if state == TCP_STATE_TIME_WAIT:
            time_wait += 1
        elif state == TCP_STATE_ESTABLISHED:
            established += 1
        elif state == TCP_STATE_LISTEN:
            listen += 1
        else:
            other += 1

        if send_q >= send_q_threshold:
            high_send_q += 1
        if recv_q >= recv_q_threshold:
            high_recv_q += 1

    return TcpSnapshot(
        time_wait=time_wait,
        established=established,
        listen=listen,
        other=other,
        high_send_q=high_send_q,
        high_recv_q=high_recv_q,
        send_q_threshold=send_q_threshold,
        recv_q_threshold=recv_q_threshold,
        source="/proc/net/tcp",
    )


def parse_ss_tan(
    content: str,
    send_q_threshold: int = DEFAULT_SEND_Q_THRESHOLD,
    recv_q_threshold: int = DEFAULT_RECV_Q_THRESHOLD,
) -> TcpSnapshot:
    time_wait = established = listen = other = 0
    high_send_q = high_recv_q = 0

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("State"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[0]
        try:
            recv_q = int(parts[1])
            send_q = int(parts[2])
        except ValueError:
            continue

        if state == "TIME-WAIT":
            time_wait += 1
        elif state == "ESTAB":
            established += 1
        elif state == "LISTEN":
            listen += 1
        else:
            other += 1

        if send_q >= send_q_threshold:
            high_send_q += 1
        if recv_q >= recv_q_threshold:
            high_recv_q += 1

    return TcpSnapshot(
        time_wait=time_wait,
        established=established,
        listen=listen,
        other=other,
        high_send_q=high_send_q,
        high_recv_q=high_recv_q,
        send_q_threshold=send_q_threshold,
        recv_q_threshold=recv_q_threshold,
        source="ss",
    )


def collect_tcp_snapshot(
    proc_root: Path = PROC_ROOT,
    send_q_threshold: int = DEFAULT_SEND_Q_THRESHOLD,
    recv_q_threshold: int = DEFAULT_RECV_Q_THRESHOLD,
) -> TcpSnapshot:
    tcp_path = proc_root / "net" / "tcp"
    if tcp_path.is_file():
        return parse_proc_net_tcp(
            read_text(tcp_path),
            send_q_threshold=send_q_threshold,
            recv_q_threshold=recv_q_threshold,
        )

    ss_bin = shutil.which("ss")
    if ss_bin:
        completed = subprocess.run(
            [ss_bin, "-tan"],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            return parse_ss_tan(
                completed.stdout,
                send_q_threshold=send_q_threshold,
                recv_q_threshold=recv_q_threshold,
            )

    raise FileNotFoundError("neither /proc/net/tcp nor `ss` output is available")


def _load_metric_severity(per_core: float) -> Severity:
    if per_core >= 2.0:
        return Severity.CRITICAL
    if per_core >= 1.0:
        return Severity.WARNING
    return Severity.OK


def evaluate_cpu(load: LoadAvgSnapshot, cores: int) -> CheckResult:
    per_core_1 = load.load_1 / cores
    per_core_5 = load.load_5 / cores
    per_core_15 = load.load_15 / cores
    sev_1 = _load_metric_severity(per_core_1)
    sev_5 = _load_metric_severity(per_core_5)
    sev_15 = _load_metric_severity(per_core_15)
    runnable_sev = Severity.WARNING if load.runnable > cores * 2 else Severity.OK
    if load.runnable > cores * 4:
        runnable_sev = Severity.CRITICAL

    details = (
        DetailLine("Logical CPUs", str(cores)),
        DetailLine(
            "Load average (1m / 5m / 15m)",
            f"{load.load_1:.2f} / {load.load_5:.2f} / {load.load_15:.2f}",
            hint="raw from /proc/loadavg",
        ),
        DetailLine(
            "Per-core load 1m",
            f"{per_core_1:.2f}",
            metric_severity=sev_1,
            hint="normal < 1.00; above 1.00 = threads waiting for CPU",
        ),
        DetailLine(
            "Per-core load 5m",
            f"{per_core_5:.2f}",
            metric_severity=sev_5,
            hint="normal < 1.00",
        ),
        DetailLine(
            "Per-core load 15m",
            f"{per_core_15:.2f}",
            metric_severity=sev_15,
            hint="normal < 1.00",
        ),
        DetailLine(
            "Runnable / total tasks",
            f"{load.runnable} / {load.total_tasks}",
            metric_severity=runnable_sev,
            hint="runnable = threads ready to run now",
        ),
    )

    if per_core_1 >= 2.0 or per_core_5 >= 1.5:
        return CheckResult(
            name="CPU Saturation",
            severity=Severity.CRITICAL,
            summary=(
                f"CPU run queue is overloaded: per-core 1m load is {per_core_1:.2f} "
                f"on {cores} CPU(s) (need < 1.00)."
            ),
            details=details,
            recommendations=(
                f"Top CPU right now: run `ps -eo pid,comm,pcpu --sort=-pcpu | head -15` "
                f"— kill or cgroup-limit the top offender if it is not expected.",
                f"Per-CPU breakdown: `mpstat -P ALL 1 5` — if one CPU is 100% while others idle, "
                f"check pinning/locks; if all high, you need more cores or less work.",
                f"Load {load.load_1:.2f} with {cores} CPUs ⇒ {per_core_1:.2f} runnable threads per core; "
                f"stop batch/cron jobs until 5m per-core load drops below 1.00 (now {per_core_5:.2f}).",
            ),
        )
    if per_core_1 >= 1.0 or per_core_5 >= 0.85:
        return CheckResult(
            name="CPU Saturation",
            severity=Severity.WARNING,
            summary=(
                f"Per-core 1m load {per_core_1:.2f} is at or above 1.00 — CPU may be the bottleneck."
            ),
            details=details,
            recommendations=(
                f"Snapshot consumers: `pidstat -u 1 5` — note PIDs with %CPU > 50.",
                f"If 5m load keeps rising ({per_core_5:.2f} per core now), check disk stalls: "
                f"`iostat -xz 1 3` — %util near 100% on a disk often inflates load.",
            ),
        )
    return CheckResult(
        name="CPU Saturation",
        severity=Severity.OK,
        summary=f"Per-core 1m load {per_core_1:.2f} is below 1.00 — no run-queue saturation.",
        details=details,
        recommendations=(),
    )


def _kb_to_human(kb: int) -> str:
    units = ("KiB", "MiB", "GiB", "TiB")
    size = float(kb)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{kb} KiB"


def evaluate_memory(mem: MemInfoSnapshot) -> CheckResult:
    total = mem.mem_total_kb
    avail_pct = (mem.mem_available_kb / total * 100) if total else 0.0
    free_pct = (mem.mem_free_kb / total * 100) if total else 0.0
    cache_pct = (mem.page_cache_kb / total * 100) if total else 0.0
    swap_used_pct = (
        ((mem.swap_total_kb - mem.swap_free_kb) / mem.swap_total_kb * 100)
        if mem.swap_total_kb
        else 0.0
    )

    avail_sev = Severity.OK
    if avail_pct < 5.0:
        avail_sev = Severity.CRITICAL
    elif avail_pct < 10.0:
        avail_sev = Severity.WARNING

    free_sev = Severity.OK
    if free_pct < 3.0 and avail_pct < 15.0:
        free_sev = Severity.WARNING

    swap_sev = Severity.OK
    if mem.swap_total_kb and swap_used_pct > 50.0:
        swap_sev = Severity.WARNING
    if mem.swap_total_kb and swap_used_pct > 80.0:
        swap_sev = Severity.CRITICAL

    details = (
        DetailLine("MemTotal", _kb_to_human(mem.mem_total_kb)),
        DetailLine(
            "MemFree (unused physical)",
            f"{_kb_to_human(mem.mem_free_kb)} ({free_pct:.1f}%)",
            metric_severity=free_sev,
            hint="low alone is OK if MemAvailable is high (cache)",
        ),
        DetailLine(
            "Buffers + Cached (page cache)",
            f"{_kb_to_human(mem.page_cache_kb)} ({cache_pct:.1f}%)",
            hint="kernel can drop this under pressure",
        ),
        DetailLine(
            "MemAvailable",
            f"{_kb_to_human(mem.mem_available_kb)} ({avail_pct:.1f}%)",
            metric_severity=avail_sev,
            hint="use this for OOM risk; alert if < 10%, critical if < 5%",
        ),
        DetailLine(
            "Reclaimable above MemFree",
            _kb_to_human(mem.reclaimable_pressure_kb),
            hint="≈ cache+slab the kernel could free before failing allocations",
        ),
        DetailLine(
            "Swap used",
            f"{_kb_to_human(mem.swap_total_kb - mem.swap_free_kb)} / "
            f"{_kb_to_human(mem.swap_total_kb)} ({swap_used_pct:.1f}%)",
            metric_severity=swap_sev,
            hint="heavy swap + low MemAvailable ⇒ slow host",
        ),
    )

    low_available = avail_pct < 10.0
    very_low_available = avail_pct < 5.0
    mostly_cache = mem.page_cache_kb > mem.mem_free_kb * 3 and avail_pct >= 15.0

    if very_low_available or (low_available and swap_used_pct > 50.0):
        return CheckResult(
            name="Memory Pressure",
            severity=Severity.CRITICAL,
            summary=(
                f"MemAvailable is {avail_pct:.1f}% ({_kb_to_human(mem.mem_available_kb)}) — "
                f"real RAM shortage, not just low MemFree ({free_pct:.1f}%)."
            ),
            details=details,
            recommendations=(
                f"OOM history on this host: `sudo ./scripts/oom_investigator.sh -n 5` "
                f"— if events exist, the killer already removed a process.",
                f"Largest RAM users: `ps -eo pid,comm,rss --sort=-rss | head -20` "
                f"(RSS column is KiB per process; focus on top 3 PIDs).",
                f"You have {cache_pct:.1f}% in page cache but only {avail_pct:.1f}% MemAvailable — "
                f"stop or restart the heaviest service above, or add RAM; "
                f"swap is {swap_used_pct:.1f}% used.",
            ),
        )
    if low_available:
        return CheckResult(
            name="Memory Pressure",
            severity=Severity.WARNING,
            summary=(
                f"MemAvailable {avail_pct:.1f}% is below 10% — a traffic spike can trigger OOM soon."
            ),
            details=details,
            recommendations=(
                f"Compare anon vs cache: `grep -E '^(AnonPages|Cached|Slab|SUnreclaim):' /proc/meminfo` "
                f"— rising AnonPages/SUnreclaim with MemAvailable {avail_pct:.1f}% means app leak or growth.",
                f"Watch live: `watch -n2 grep MemAvailable /proc/meminfo` — if it drops under 5%, "
                f"run `ps -eo pid,comm,rss --sort=-rss | head -10` immediately.",
            ),
        )
    if mostly_cache:
        return CheckResult(
            name="Memory Pressure",
            severity=Severity.OK,
            summary=(
                f"MemAvailable {avail_pct:.1f}% is healthy; "
                f"low MemFree ({free_pct:.1f}%) is mostly page cache ({cache_pct:.1f}%)."
            ),
            details=details,
            recommendations=(),
        )
    return CheckResult(
        name="Memory Pressure",
        severity=Severity.OK,
        summary=f"MemAvailable {avail_pct:.1f}% — sufficient headroom.",
        details=details,
        recommendations=(),
    )


def evaluate_tcp(tcp: TcpSnapshot, cores: int) -> CheckResult:
    time_wait_per_core = tcp.time_wait / max(cores, 1)
    q_human = _kb_to_human(tcp.send_q_threshold // 1024)
    tw_sev = Severity.OK
    if tcp.time_wait > cores * 2000:
        tw_sev = Severity.CRITICAL
    elif tcp.time_wait > cores * 500:
        tw_sev = Severity.WARNING

    send_sev = Severity.CRITICAL if tcp.high_send_q > 0 else Severity.OK
    recv_sev = Severity.OK
    if tcp.high_recv_q > 5:
        recv_sev = Severity.CRITICAL
    elif tcp.high_recv_q > 0:
        recv_sev = Severity.WARNING

    details = (
        DetailLine("Data source", tcp.source),
        DetailLine("ESTABLISHED sockets", str(tcp.established)),
        DetailLine(
            "TIME-WAIT sockets",
            str(tcp.time_wait),
            metric_severity=tw_sev,
            hint=f"{time_wait_per_core:.1f} per CPU; high ⇒ many short TCP connections",
        ),
        DetailLine("LISTEN sockets", str(tcp.listen)),
        DetailLine("Other states", str(tcp.other)),
        DetailLine(
            f"Sockets with Send-Q ≥ {q_human}",
            str(tcp.high_send_q),
            metric_severity=send_sev,
            hint=">0 ⇒ peer not reading fast enough or app write backlog",
        ),
        DetailLine(
            f"Sockets with Recv-Q ≥ {q_human}",
            str(tcp.high_recv_q),
            metric_severity=recv_sev,
            hint=">0 ⇒ app not reading from socket (slow handler)",
        ),
    )

    critical_queues = tcp.high_send_q > 0 or tcp.high_recv_q > 5
    warn_time_wait = tcp.time_wait > cores * 500
    crit_time_wait = tcp.time_wait > cores * 2000
    thresh = tcp.send_q_threshold

    if critical_queues:
        return CheckResult(
            name="TCP / Network",
            severity=Severity.CRITICAL,
            summary=(
                f"{tcp.high_send_q} socket(s) with Send-Q ≥ {q_human}, "
                f"{tcp.high_recv_q} with Recv-Q ≥ {q_human} — data stuck in kernel queues."
            ),
            details=details,
            recommendations=(
                f"List exact connections: `ss -tan state established "
                f"'( recv-q >= {thresh} or send-q >= {thresh} )'` "
                f"— note Local:Port and Peer:Port of each line.",
                f"For high Recv-Q ({tcp.high_recv_q} sockets): on that port's service, "
                f"check slow requests/logs; find PID via `ss -tanp` (needs root).",
                f"For high Send-Q ({tcp.high_send_q} sockets): client or upstream is not ACKing; "
                f"check retransmits: `ss -ti | grep -i retrans` on affected rows.",
            ),
        )
    if crit_time_wait:
        return CheckResult(
            name="TCP / Network",
            severity=Severity.CRITICAL,
            summary=(
                f"TIME-WAIT count {tcp.time_wait} ({time_wait_per_core:.0f}/CPU) — "
                f"risk of ephemeral port exhaustion on busy outbound clients."
            ),
            details=details,
            recommendations=(
                f"See who opens most connections: `ss -tan state time-wait | awk '{{print $4}}' "
                f"| sort | uniq -c | sort -nr | head` — top local ports point to the service.",
                f"Ephemeral range: `sysctl net.ipv4.ip_local_port_range` — with {tcp.time_wait} "
                f"TIME-WAIT sockets, widen range or enable HTTP keep-alive / connection pooling.",
                f"Fix at the client: reuse TCP connections instead of opening a new socket per request "
                f"(pool size / keep-alive timeout).",
            ),
        )
    if warn_time_wait or tcp.high_recv_q > 0:
        return CheckResult(
            name="TCP / Network",
            severity=Severity.WARNING,
            summary=(
                f"TIME-WAIT={tcp.time_wait} or Recv-Q backlog ({tcp.high_recv_q} sockets "
                f"≥ {q_human}) — watch latency."
            ),
            details=details,
            recommendations=(
                f"Non-zero queues: `ss -tan | awk 'NR==1 || $2>0 || $3>0'` "
                f"— Recv-Q/Send-Q are bytes waiting in kernel.",
                f"TIME-WAIT {tcp.time_wait}: if this spikes during deploys, enable keep-alive on "
                f"load balancers/clients hitting this host.",
            ),
        )
    return CheckResult(
        name="TCP / Network",
        severity=Severity.OK,
        summary=(
            f"No queue backlogs; TIME-WAIT {tcp.time_wait} within normal range for {cores} CPU(s)."
        ),
        details=details,
        recommendations=(),
    )


def overall_severity(results: Sequence[CheckResult]) -> Severity:
    order = {Severity.OK: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}
    worst = Severity.OK
    for result in results:
        if order[result.severity] > order[worst]:
            worst = result.severity
    return worst


def format_report(results: Iterable[CheckResult], host: str, use_color: bool) -> str:
    lines: list[str] = []
    title = colorize("server-triage-toolkit — USE snapshot", Ansi.CYAN + Ansi.BOLD, use_color)
    lines.append(title)
    lines.append(colorize(f"Host: {host}", Ansi.DIM, use_color))
    lines.append("")

    for result in results:
        lines.append(f"{severity_style(result.severity, use_color)}  {colorize(result.name, Ansi.BOLD, use_color)}")
        summary_color = Ansi.DIM
        if result.severity == Severity.WARNING:
            summary_color = Ansi.YELLOW
        elif result.severity == Severity.CRITICAL:
            summary_color = Ansi.RED
        lines.append(colorize(f"  {result.summary}", summary_color, use_color))
        for detail in result.details:
            lines.append(format_detail_line(detail, use_color))
        if result.recommendations:
            lines.append(colorize("    What to do next:", Ansi.CYAN + Ansi.BOLD, use_color))
            for idx, rec in enumerate(result.recommendations, start=1):
                lines.append(format_recommendation(idx, rec, use_color))
        lines.append("")

    worst = overall_severity(tuple(results))
    footer = f"Overall: {severity_style(worst, use_color)}"
    lines.append(footer)
    return "\n".join(lines)


def run_triage(
    proc_root: Path = PROC_ROOT,
    send_q_threshold: int = DEFAULT_SEND_Q_THRESHOLD,
    recv_q_threshold: int = DEFAULT_RECV_Q_THRESHOLD,
) -> tuple[list[CheckResult], int]:
    load = parse_loadavg(read_text(proc_root / "loadavg"))
    cores = cpu_core_count(proc_root)
    mem = parse_meminfo(read_text(proc_root / "meminfo"))
    tcp = collect_tcp_snapshot(
        proc_root=proc_root,
        send_q_threshold=send_q_threshold,
        recv_q_threshold=recv_q_threshold,
    )

    results = [
        evaluate_cpu(load, cores),
        evaluate_memory(mem),
        evaluate_tcp(tcp, cores),
    ]
    exit_code = 0 if overall_severity(results) == Severity.OK else (
        1 if overall_severity(results) == Severity.WARNING else 2
    )
    return results, exit_code


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Linux host triage using USE (Utilization, Saturation, Errors) signals.",
    )
    parser.add_argument(
        "--proc-root",
        type=Path,
        default=PROC_ROOT,
        help="Path to procfs (default: /proc, or TRIAGE_PROC_ROOT env).",
    )
    parser.add_argument(
        "--send-q-threshold",
        type=int,
        default=DEFAULT_SEND_Q_THRESHOLD,
        help="Flag Send-Q at or above this many bytes (default: 1 MiB).",
    )
    parser.add_argument(
        "--recv-q-threshold",
        type=int,
        default=DEFAULT_RECV_Q_THRESHOLD,
        help="Flag Recv-Q at or above this many bytes (default: 1 MiB).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors (also respects NO_COLOR).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    use_color = _supports_color() and not args.no_color
    host = os.uname().nodename if hasattr(os, "uname") else "localhost"

    try:
        results, exit_code = run_triage(
            proc_root=args.proc_root,
            send_q_threshold=args.send_q_threshold,
            recv_q_threshold=args.recv_q_threshold,
        )
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    except (OSError, ValueError) as exc:
        print(f"ERROR: failed to collect metrics: {exc}", file=sys.stderr)
        return 3

    print(format_report(results, host=host, use_color=use_color))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

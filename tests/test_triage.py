"""Unit tests for triage parsers and evaluators (no live /proc required)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import triage  # noqa: E402


SAMPLE_LOADAVG = "2.40 1.80 1.20 4/512 99999\n"

SAMPLE_MEMINFO = """
MemTotal:       16384000 kB
MemFree:          120000 kB
MemAvailable:    8000000 kB
Buffers:          400000 kB
Cached:          7200000 kB
SwapTotal:       8388608 kB
SwapFree:        8388608 kB
""".strip()

SAMPLE_PROC_NET_TCP = """
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0050 0100007F:C000 01 00000000:00000000 00:00000000 00000000   100        0 23456 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:0050 0100007F:C001 06 00000000:00000000 00:00000000 00000000   100        0 23457 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:0050 0100007F:C002 01 00100000:00000000 00:00000000 00000000   100        0 23458 1 0000000000000000 20 4 30 10 -1
""".strip()

SAMPLE_SS = """
State      Recv-Q Send-Q Local Address:Port  Peer Address:Port
LISTEN     0      128    127.0.0.1:22          0.0.0.0:*
ESTAB      0      0      127.0.0.1:443         127.0.0.1:50000
TIME-WAIT  0      0      127.0.0.1:443         127.0.0.1:50001
ESTAB      2097152  0      127.0.0.1:8080        127.0.0.1:50002
""".strip()


class ParseLoadavgTests(unittest.TestCase):
    def test_parse_loadavg(self) -> None:
        snap = triage.parse_loadavg(SAMPLE_LOADAVG)
        self.assertAlmostEqual(snap.load_1, 2.40)
        self.assertEqual(snap.runnable, 4)
        self.assertEqual(snap.total_tasks, 512)


class ParseMeminfoTests(unittest.TestCase):
    def test_parse_meminfo(self) -> None:
        snap = triage.parse_meminfo(SAMPLE_MEMINFO)
        self.assertEqual(snap.mem_total_kb, 16384000)
        self.assertEqual(snap.page_cache_kb, 400000 + 7200000)

    def test_evaluate_memory_ok_with_cache(self) -> None:
        snap = triage.parse_meminfo(SAMPLE_MEMINFO)
        result = triage.evaluate_memory(snap)
        self.assertEqual(result.severity, triage.Severity.OK)


class ParseTcpTests(unittest.TestCase):
    def test_parse_proc_net_tcp(self) -> None:
        snap = triage.parse_proc_net_tcp(SAMPLE_PROC_NET_TCP, send_q_threshold=65536)
        self.assertEqual(snap.time_wait, 1)
        self.assertEqual(snap.established, 2)
        self.assertEqual(snap.listen, 1)
        self.assertEqual(snap.high_send_q, 1)

    def test_parse_ss_tan(self) -> None:
        snap = triage.parse_ss_tan(SAMPLE_SS, send_q_threshold=1048576, recv_q_threshold=1048576)
        self.assertEqual(snap.time_wait, 1)
        self.assertEqual(snap.high_recv_q, 1)


class EvaluateCpuTests(unittest.TestCase):
    def test_critical_saturation(self) -> None:
        load = triage.parse_loadavg("4.00 3.00 2.00 8/100 1\n")
        result = triage.evaluate_cpu(load, cores=2)
        self.assertEqual(result.severity, triage.Severity.CRITICAL)

    def test_ok_low_load(self) -> None:
        load = triage.parse_loadavg("0.20 0.30 0.40 1/100 1\n")
        result = triage.evaluate_cpu(load, cores=4)
        self.assertEqual(result.severity, triage.Severity.OK)


class ReportTests(unittest.TestCase):
    def test_overall_severity(self) -> None:
        results = [
            triage.CheckResult("A", triage.Severity.OK, "fine"),
            triage.CheckResult("B", triage.Severity.WARNING, "watch"),
        ]
        self.assertEqual(triage.overall_severity(results), triage.Severity.WARNING)

    def test_format_report_no_color(self) -> None:
        results = [
            triage.CheckResult(
                "CPU Saturation",
                triage.Severity.OK,
                "healthy",
                details=(triage.DetailLine("Per-core load 1m", "0.25"),),
            )
        ]
        text = triage.format_report(results, host="testhost", use_color=False)
        self.assertIn("testhost", text)
        self.assertIn("CPU Saturation", text)
        self.assertIn("0.25", text)

    def test_format_detail_highlights_abnormal(self) -> None:
        line = triage.DetailLine(
            "MemAvailable",
            "3.2%",
            metric_severity=triage.Severity.CRITICAL,
            hint="below 5%",
        )
        text = triage.format_detail_line(line, use_color=False)
        self.assertIn("[CRITICAL]", text)
        self.assertIn("3.2%", text)


if __name__ == "__main__":
    unittest.main()

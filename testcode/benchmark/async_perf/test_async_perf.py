#!/usr/bin/env python3
# This file is part of the openHiTLS project.
# Licensed under the Mulan PSL v2: http://license.coscl.org.cn/MulanPSL2
"""Black-box regression tests for openhitls_async_benchmark."""

import csv
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
BINARY = Path(os.environ.get("ASYNC_PERF_BINARY", ROOT / "build/testcode/benchmark/async_perf/openhitls_async_benchmark"))


class BenchmarkTest(unittest.TestCase):
    def run_benchmark(self, *args):
        tmp = tempfile.TemporaryDirectory(prefix="async-perf-test-")
        self.addCleanup(tmp.cleanup)
        proc = subprocess.run(
            [str(BINARY), "--out", tmp.name, "--cert-dir",
             str(ROOT / "testcode/testdata/tls/certificate/der"), *args],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60,
        )
        files = list(Path(tmp.name).glob("*/results.csv"))
        rows = []
        if files:
            with files[0].open() as stream:
                rows = list(csv.DictReader(stream))
        return proc, rows, files[0].parent if files else None

    def test_sync_profiles(self):
        for mode in ("inline", "worker"):
            with self.subTest(mode=mode):
                proc, rows, _ = self.run_benchmark(
                    "-a", "hs-sync-*", "--repeat", "2", "-c", "4",
                    "--device-mode", mode, "-w", "4",
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertEqual(len(rows), 10)
                for row in rows:
                    self.assertEqual(row["status"], "OK", row)
                    self.assertEqual(row["handshakes"], "4", row)
                    self.assertEqual(row["pauses"], "0", row)
                    self.assertEqual(row["failures"], "0", row)
                    self.assertGreater(int(row["batch_ns"]), 0)

    def test_async_profiles(self):
        supported = os.environ.get("ASYNC_PERF_EXPECT_ASYNC", "1") == "1"
        for mode in ("inline", "worker"):
            with self.subTest(mode=mode):
                proc, rows, _ = self.run_benchmark(
                    "-a", "hs-on-*", "--repeat", "2", "-c", "10",
                    "--device-mode", mode, "-w", "4",
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertEqual(len(rows), 20)
                for row in rows:
                    self.assertEqual(row["status"], "OK" if supported else "UNSUPPORTED", row)
                    if not supported:
                        continue
                    self.assertEqual(row["handshakes"], "10", row)
                    self.assertEqual(row["failures"], "0", row)
                    self.assertGreater(int(row["batch_ns"]), 0)
                    if row["scenario"].endswith("tls13-psk"):
                        self.assertEqual(int(row["submits"]), 0)
                        self.assertEqual(int(row["pauses"]), 0)
                    else:
                        self.assertGreater(int(row["submits"]), 0)
                        self.assertGreaterEqual(int(row["pauses"]), int(row["submits"]))

    def test_metadata(self):
        proc, _, directory = self.run_benchmark("-a", "hs-sync-tls13-psk", "--repeat", "1", "--tag", 'quote"tag')
        self.assertEqual(proc.returncode, 0, proc.stdout)
        meta = json.loads((directory / "meta.json").read_text())
        for key in ("cpu_model", "cpu_count", "hostname", "kernel", "governor", "affinity"):
            self.assertIn(key, meta["environment"])
        self.assertIn("compiler", meta)
        self.assertTrue(meta["build_macros"]["HITLS_CRYPTO_PROVIDER"])

    def test_reject_default_provider_fallback(self):
        forms = ("sync", "on-fd", "on-cb") if os.environ.get("ASYNC_PERF_EXPECT_ASYNC", "1") == "1" else ("sync",)
        for form in forms:
            with self.subTest(form=form):
                proc, rows, _ = self.run_benchmark("-a", f"hs-{form}-tls13-ecdhe-ecdsa", "--repeat", "1",
                                                 "--provider-attr", "provider=default")
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
                self.assertFalse(any(row["status"] == "OK" for row in rows))

    def test_default_matrix(self):
        proc = subprocess.run([str(BINARY), "--list"], text=True, capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertEqual(len(proc.stdout.splitlines()) - 1, 12)
        self.assertIn("16", proc.stdout)

    def test_invalid_options(self):
        for option, value in (("-c", "4294967297"), ("--repeat", "-1"), ("--preset", "unknown")):
            proc = subprocess.run([str(BINARY), "--list", option, value], text=True, capture_output=True, timeout=10)
            self.assertEqual(proc.returncode, 2, proc.stdout)

    def test_auto_affinity_option(self):
        proc = subprocess.run([str(BINARY), "--list", "--pin-cpu", "auto"],
                              text=True, capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stdout)

    @unittest.skipUnless(hasattr(os, "sched_getaffinity"), "Linux affinity required")
    def test_auto_affinity_insufficient_cores(self):
        cpu = min(os.sched_getaffinity(0))
        with tempfile.TemporaryDirectory(prefix="async-affinity-test-") as directory:
            proc = subprocess.run(
                [str(BINARY), "-a", "hs-sync-tls13-psk", "--device-mode", "worker",
                 "-w", "4", "--pin-cpu", "auto", "--repeat", "1", "--out", directory],
                preexec_fn=lambda: os.sched_setaffinity(0, {cpu}),
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        self.assertNotEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("idle physical cores", proc.stdout)

    @unittest.skipUnless(hasattr(os, "sched_getaffinity"), "Linux affinity required")
    def test_auto_affinity_threads(self):
        with tempfile.TemporaryDirectory(prefix="async-affinity-test-") as directory:
            snapshots = []
            with tempfile.TemporaryFile(mode="w+") as log:
                proc = subprocess.Popen(
                    [str(BINARY), "-a", "hs-sync-tls13-psk", "--device-mode", "worker",
                     "-w", "2", "--pin-cpu", "auto", "-s", "1", "--out", directory],
                    stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 15
                    while proc.poll() is None and time.monotonic() < deadline:
                        try:
                            masks = {int(p.name): sorted(os.sched_getaffinity(int(p.name)))
                                     for p in Path(f"/proc/{proc.pid}/task").iterdir()}
                            if len(masks) == 3 and all(len(mask) == 1 for mask in masks.values()):
                                snapshots.append(masks)
                        except (FileNotFoundError, ProcessLookupError):
                            pass
                        time.sleep(0.02)
                    proc.wait(timeout=1)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
                log.seek(0)
                output = log.read()
            if proc.returncode != 0 and "cannot bind idle physical cores" in output:
                self.skipTest("three idle physical cores unavailable")
            self.assertEqual(proc.returncode, 0, output)
            meta = json.loads(next(Path(directory).glob("*/meta.json")).read_text())
            binding = meta["cpu_binding"]
            self.assertTrue(binding["enabled"])
            cpus = [binding["dispatcher_cpu"], *binding["worker_cpus"]]
            self.assertEqual(len(cpus), 3)
            self.assertTrue(all(value <= 10 for value in binding["sample_busy_percent"]))
            cores = set()
            for cpu in cpus:
                topology = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
                cores.add(tuple((topology / field).read_text().strip()
                                for field in ("physical_package_id", "core_id")))
            self.assertEqual(len(cores), 3)
            self.assertTrue(any(masks.get(proc.pid) == [cpus[0]] and
                                sorted(mask[0] for tid, mask in masks.items() if tid != proc.pid) == sorted(cpus[1:])
                                for masks in snapshots), (binding, snapshots))


class CompareTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="async-compare-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.header = ("scenario,repeat,concurrency,workers,exec_mode,handshakes,batch_ns,p50_ns,p90_ns,"
                       "p99_ns,max_ns,submits,pauses,failures,status\n")

    def dataset(self, name, values, form="sync", mode="inline", statuses=None, cpu="test-cpu"):
        directory = self.root / name
        directory.mkdir(exist_ok=True)
        lines = [self.header]
        for i, value in enumerate(values):
            status = statuses[i] if statuses else "OK"
            lines.append(f"hs-{form}-tls13-ecdhe-ecdsa,{i},8,4,{mode},8,{value},1,1,1,1,0,0,0,{status}\n")
        (directory / "meta.json").write_text(json.dumps({
            "environment": {"cpu_model": cpu, "hostname": "test-host", "cpu_count": 8}, "compiler": "test-cc"}))
        path = directory / "results.csv"
        path.write_text("".join(lines))
        return path

    def compare(self, base, cand, *options):
        return subprocess.run([str(BINARY), "compare", str(base), str(cand), *map(str, options)],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)

    def test_verdicts(self):
        base = self.dataset("base", [100] * 5)
        for value, verdict, code in ((100, "NOISE", 0), (90, "PASS", 0), (120, "FAIL", 1)):
            with self.subTest(verdict=verdict):
                proc = self.compare(base, self.dataset("cand", [value] * 5))
                self.assertEqual(proc.returncode, code, proc.stdout)
                self.assertIn(verdict, proc.stdout)

    def test_noise_uses_repeats(self):
        proc = self.compare(self.dataset("base", [80, 100, 120]), self.dataset("cand", [103] * 3))
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("NOISE", proc.stdout)

    def test_json_thresholds(self):
        thresholds = self.root / "thresholds.json"
        thresholds.write_text(json.dumps({"q1_sync_cross_build": 1.3, "noise_inline": 0.01}))
        proc = self.compare(self.dataset("base", [100] * 5), self.dataset("cand", [120] * 5),
                            "--thresholds", thresholds)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("PASS", proc.stdout)

    def test_cross_form(self):
        base = self.dataset("base", [100] * 5, mode="worker")
        for form in ("on-fd", "on-cb"):
            with self.subTest(form=form):
                proc = self.compare(base, self.dataset("cand", [40] * 5, form=form, mode="worker"),
                                    "--pair", f"{form}:sync")
                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("Q3", proc.stdout)
                self.assertIn("PASS", proc.stdout)

    def test_all_repeats_and_even_median(self):
        proc = self.compare(self.dataset("base", [100] * 64 + [300] * 64),
                            self.dataset("cand", [200] * 128))
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("+0.0%", proc.stdout)

    def test_invalid_repeat_is_not_lost(self):
        proc = self.compare(self.dataset("base", [100, 100], statuses=["INVALID", "OK"]),
                            self.dataset("cand", [100, 100]))
        self.assertIn("SKIP", proc.stdout)
        self.assertNotIn("PASS", proc.stdout)

    def test_environment_mismatch(self):
        proc = self.compare(self.dataset("base", [100] * 5), self.dataset("cand", [1000] * 5, cpu="different"))
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("WARNING", proc.stdout)
        self.assertNotIn("FAIL", proc.stdout)

    def test_bad_inputs(self):
        base = self.dataset("base", [100])
        for content in (self.header, self.header + "malformed\n"):
            (self.root / "bad.csv").write_text(content)
            proc = self.compare(base, self.root / "bad.csv")
            self.assertEqual(proc.returncode, 2, proc.stdout)
        proc = self.compare(base, base, "--thresholds", self.root / "missing.json")
        self.assertEqual(proc.returncode, 2, proc.stdout)


if __name__ == "__main__":
    unittest.main()

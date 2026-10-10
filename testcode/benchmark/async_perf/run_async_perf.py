#!/usr/bin/env python3
# This file is part of the openHiTLS project.
# Licensed under the Mulan PSL v2: http://license.coscl.org.cn/MulanPSL2
"""Start one server, then N independent single-connection client demos."""

import argparse
import csv
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    binary_dir = Path("build/testcode/benchmark/async_perf")
    parser.add_argument("--server", type=Path, default=binary_dir / "openhitls_async_benchmark")
    parser.add_argument("--client", type=Path, default=binary_dir / "openhitls_async_client")
    parser.add_argument("-a", default="*", help="scenario glob")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("-c", "--concurrency", type=positive, default=1)
    parser.add_argument("--repeat", type=positive, default=3)
    parser.add_argument("--port", type=positive, default=44330)
    parser.add_argument("--device-mode", choices=("inline", "worker"), default="inline")
    parser.add_argument("-w", "--workers", type=positive, default=4)
    parser.add_argument("--provider-path")
    parser.add_argument("--cert-dir")
    parser.add_argument("--pin-cpu", help="auto or server dispatcher CPU")
    parser.add_argument("-o", "--out", type=Path, default=Path("testcode/output/async_perf"))
    return parser.parse_args()


def server_command(args):
    command = [str(args.server.resolve()), "-c", str(args.concurrency), "--port", str(args.port),
               "--device-mode", args.device_mode, "-w", str(args.workers)]
    for option in ("provider_path", "cert_dir", "pin_cpu"):
        value = getattr(args, option)
        if value is not None:
            command += ["--" + option.replace("_", "-"), value]
    return command


def wait_ready(server, log):
    deadline = time.monotonic() + 30
    client_cpus = []
    while time.monotonic() < deadline:
        line = log.readline()
        if line:
            binding = re.search(r" clients=([0-9,]+)", line)
            if binding:
                client_cpus = [int(cpu) for cpu in binding[1].split(",")]
                print(line.strip(), flush=True)
            if line.strip() == "LISTENING":
                return client_cpus
            if line.startswith("RESULT,"):
                return None
        elif server.poll() is not None:
            raise RuntimeError("server exited before listening")
        else:
            time.sleep(0.01)
    raise TimeoutError("server startup timed out")


def stop_processes(processes):
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def run_batch(args, scenario):
    processes = []
    error = None
    with tempfile.TemporaryFile(mode="w+") as server_log, tempfile.TemporaryFile(mode="w+") as client_log:
        # Separate read descriptor: a shared file offset would interfere with the server's writes.
        with open(f"/proc/self/fd/{server_log.fileno()}") as reader:
            try:
                server = subprocess.Popen(server_command(args) + ["-a", scenario],
                                          stdout=server_log, stderr=server_log)
                processes.append(server)
                cpus = wait_ready(server, reader)
                if cpus is not None:
                    protocol = "tls12" if "-tls12-" in scenario else "tls13"
                    for index in range(args.concurrency):
                        pin = None
                        if cpus:
                            cpu = cpus[index % len(cpus)]
                            pin = lambda cpu=cpu: os.sched_setaffinity(0, {cpu})
                        processes.append(subprocess.Popen([str(args.client.resolve()), str(args.port), protocol],
                                                          stdout=subprocess.DEVNULL, stderr=client_log,
                                                          preexec_fn=pin))
                deadline = time.monotonic() + 60
                while True:
                    codes = [process.poll() for process in processes]
                    if any(code not in (None, 0) for code in codes):
                        raise RuntimeError("server or client failed")
                    if all(code is not None for code in codes):
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError("batch timed out")
                    time.sleep(0.01)
            except (OSError, RuntimeError, TimeoutError, subprocess.SubprocessError) as exc:
                error = str(exc)
            finally:
                stop_processes(processes)
        server_log.seek(0)
        output = server_log.read()
        client_log.seek(0)
        client_errors = client_log.read()
    result = ["0", "0", "INVALID"]
    for line in output.splitlines():
        if line.startswith("RESULT,"):
            result = line.split(",")[1:]
    if error or result[2] == "INVALID":
        result[2] = "INVALID"
        print(f"{error or 'server failed'}\n{output}{client_errors}", flush=True)
    return result


def main():
    args = arguments()
    listing = subprocess.run(server_command(args) + ["--list", "-a", args.a], text=True, capture_output=True)
    if listing.returncode != 0:
        print(listing.stdout + listing.stderr)
        return 2
    if args.list:
        print(listing.stdout, end="")
        return 0
    scenarios = [line.split()[0] for line in listing.stdout.splitlines() if line.startswith("hs-")]
    if not scenarios:
        print("no scenario selected")
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    result_file = Path(tempfile.mkdtemp(prefix="run_", dir=args.out)) / "results.csv"
    with result_file.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["scenario", "repeat", "concurrency", "workers", "exec_mode", "handshakes", "batch_ns", "status"])
        print(f"results: {result_file}", flush=True)
        for scenario in scenarios:
            for repeat in range(args.repeat):
                count, elapsed, status = run_batch(args, scenario)
                writer.writerow([scenario, repeat, args.concurrency,
                                 args.workers if args.device_mode == "worker" else 0,
                                 args.device_mode, count, elapsed, status])
                stream.flush()
                print(f"{scenario} r{repeat} {status} handshakes={count} batch={int(elapsed) / 1e6:.3f}ms", flush=True)
                if status == "INVALID":
                    return 1
                if status == "UNSUPPORTED":
                    break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

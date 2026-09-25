#!/usr/bin/env python3
"""Low-overhead Linux host sampling during explicitly labelled real workload.

Run on the VM. This does not launch a workload or establish coverage by itself.
It never reads credentials, process arguments, or environment variables.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import time
from urllib.request import ProxyHandler, build_opener


def percentile(values, fraction):
    values = sorted(values)
    return values[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8000')
    parser.add_argument('--duration', type=int, default=120)
    parser.add_argument('--interval', type=float, default=2)
    parser.add_argument('--workload', required=True, help='Actual jobs/run IDs measured, never a planned workload')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.duration <= 1800 or not 1 <= args.interval <= 30:
        parser.error('duration must be 1..1800 seconds; interval 1..30 seconds')
    opener = build_opener(ProxyHandler({}))
    started = time.time()
    deadline = time.monotonic() + args.duration
    samples = []
    while time.monotonic() < deadline:
        tick = time.monotonic()
        mem = {}
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, value = line.split(':', 1)
            mem[key] = int(value.split()[0]) * 1024
        sample = {'at': time.time(), 'availableBytes': mem['MemAvailable'],
                  'swapUsedBytes': mem['SwapTotal'] - mem['SwapFree'],
                  'load1': float(Path('/proc/loadavg').read_text().split()[0]), 'requests': []}
        for route in ('/health', '/api/session', '/'):
            before = time.monotonic()
            result = {'route': route}
            try:
                with opener.open(args.url.rstrip('/') + route, timeout=2) as response:
                    response.read(1024)
                    result['httpStatus'] = response.status
            except Exception as exc:
                result['error'] = type(exc).__name__
            result['latencyMs'] = round((time.monotonic() - before) * 1000, 2)
            sample['requests'].append(result)
        samples.append(sample)
        time.sleep(max(0, min(args.interval - (time.monotonic() - tick), deadline - time.monotonic())))
    requests = [request for sample in samples for request in sample['requests']]
    latencies = [request['latencyMs'] for request in requests]
    failures = sum(request.get('httpStatus') != 200 for request in requests)
    minimum = min(sample['availableBytes'] for sample in samples)
    p95 = percentile(latencies, .95)
    result = {'workload': args.workload, 'startedAt': started, 'endedAt': time.time(),
              'sampleCount': len(samples), 'requestCount': len(requests), 'failedRequests': failures,
              'latencyMs': {'p50': percentile(latencies, .5), 'p95': p95, 'max': max(latencies)},
              'minimumAvailableBytes': minimum,
              'criteria': {'minimumAvailableBytes': 1073741824, 'maximumP95Ms': 500, 'failedRequests': 0},
              'passed': failures == 0 and minimum >= 1073741824 and p95 <= 500,
              'limitations': ['Health, session and static HTTP responsiveness only; authenticated browser interaction needs its own gate.',
                              'Workload identity must be corroborated by actual executor/model event timestamps.'],
              'samples': samples}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('workload', 'sampleCount', 'failedRequests',
                                                'latencyMs', 'minimumAvailableBytes', 'passed')}))
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())

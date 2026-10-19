"""Offline TOOL0 UART / RESET timing from sigrok captures (requires numpy)."""
import argparse
import configparser
import json
import zipfile
from pathlib import Path

import numpy as np


def analyze(path, baud=115200):
    with zipfile.ZipFile(path) as archive:
        config = configparser.ConfigParser()
        config.read_string(archive.read("metadata").decode())
        dev = config["device 1"]
        rate, unit = dev["samplerate"].split()
        rate = float(rate) * {"Hz": 1, "kHz": 1e3, "MHz": 1e6}[unit]
        if int(dev["unitsize"]) != 1:
            raise ValueError("Only one-byte logic samples supported")
        chunks = sorted((n for n in archive.namelist() if n.startswith("logic-1-")),
                        key=lambda n: int(n.rsplit("-", 1)[1]))
        samples = np.frombuffer(b"".join(archive.read(n) for n in chunks), dtype=np.uint8)
    tool = (samples >> 3) & 1
    reset = (samples >> 4) & 1
    edges = np.flatnonzero(tool[1:] != tool[:-1]) + 1
    reset_edges = np.flatnonzero(reset[1:] != reset[:-1]) + 1
    bit = rate / baud
    records = []
    pulses = []
    if tool[0] == 0 and len(edges):
        pulses.append({"start_us": 0, "end_us": int(edges[0]) / rate * 1e6,
                       "duration_us": int(edges[0]) / rate * 1e6,
                       "truncated_at_start": True})
    next_start = 0
    for i, edge in enumerate(edges):
        edge = int(edge)
        if tool[edge] != 0:
            continue
        end = int(edges[i + 1]) if i + 1 < len(edges) else len(tool)
        if end - edge > 12 * bit:
            pulses.append({"start_us": edge / rate * 1e6,
                           "end_us": end / rate * 1e6,
                           "duration_us": (end - edge) / rate * 1e6})
            next_start = end
            continue
        if edge < next_start or edge + 9.5 * bit >= len(tool):
            continue
        # UART 8N1 minimum: sample the stop bit; do not assume direction or
        # distinguish target data from host TX on the shared TOOL0 line.
        stop_ok = bool(tool[round(edge + 9.5 * bit)])
        value = sum(int(tool[round(edge + (1.5 + b) * bit)]) << b for b in range(8))
        records.append({"start_us": edge / rate * 1e6, "byte": value,
                        "stop_ok": stop_ok, "reset": int(reset[edge])})
        next_start = edge + 9.6 * bit
    return {"file": str(path), "sample_rate": rate, "baud": baud,
            "duration_us": len(samples) / rate * 1e6,
            "reset_initial": int(reset[0]),
            "reset_edges": [{"time_us": int(e) / rate * 1e6, "level": int(reset[e])}
                            for e in reset_edges],
            "tool0_low_pulses": pulses, "uart": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--limit", type=int, default=180)
    args = parser.parse_args()
    result = analyze(args.capture)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"{args.capture}: {result['duration_us']/1000:.3f} ms; RESET initial={result['reset_initial']}")
    print(f"RESET edges ({len(result['reset_edges'])} total, first 12):", result["reset_edges"][:12])
    print("TOOL0 long lows:", result["tool0_low_pulses"][:30])
    print(f"UART bytes: {len(result['uart'])}; bad stops: {sum(not r['stop_ok'] for r in result['uart'])}")
    previous = None
    for row in result["uart"][:args.limit]:
        start = row["start_us"]
        delta = start - previous if previous is not None else 0
        print(f"{start/1000:12.6f} ms  +{delta:10.3f} us  {row['byte']:02x}  R={row['reset']}  stop={int(row['stop_ok'])}")
        previous = start


if __name__ == "__main__":
    main()

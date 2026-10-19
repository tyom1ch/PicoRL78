#!/usr/bin/env python3
"""
probe_ocd.py -- Raw diagnostic timeline for the RL78 OCD entry.

Makes NO framing assumptions and NEVER flushes between steps. It just enters a
mode byte and dumps every byte the chip emits at each stage, so we can see:
  - what the monitor sends right after the mode byte (null/init/SYNC?),
  - whether a passive SYNC (0x00) appears before or after Baud-Rate-Set,
  - whether the monitor answers a host-sent 0x00 or PING.

Usage:
  python probe_ocd.py -p COM9                 # OCD mode byte 0xC5
  python probe_ocd.py -p COM9 --mode 0x3a     # programming mode, for comparison
"""
import argparse
import struct
import sys
import time

from rl78bridge import RL78Bridge

CHIP = "R5F10BAG"


def hx(b):
    return b.hex(" ") if b else "(none)"


def raw_read(bridge, n, to_ms, tag):
    """Pure read (txlen=0 -> firmware does NOT flush)."""
    data = bridge.xfer(b"", n, to_ms)
    print(f"    {CHIP}>PROG [{tag}] : {hx(data)}")
    return data


def raw_send_read(bridge, tx, nresp, to_ms, tag):
    rx = bridge.xfer(tx, len(tx) + nresp, to_ms)
    echo, resp = rx[:len(tx)], rx[len(tx):]
    print(f"    PROG>{CHIP} [{tag}] : {hx(tx)}   (echo {hx(echo)})")
    print(f"    {CHIP}>PROG [{tag}] : {hx(resp)}")
    return resp


def build_baud(code=0, voltage=50):
    payload = bytes([0x9A, code, voltage])
    ln = len(payload) & 0xFF
    sm = (-(ln + sum(payload))) & 0xFF
    return bytes([0x01, ln]) + payload + bytes([sm, 0x03])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--port", required=True)
    ap.add_argument("--mode", default="0xc5", help="mode byte (0xc5 OCD, 0x3a 1-wire prog)")
    ap.add_argument("--power-cycle", action="store_true")
    args = ap.parse_args()
    mode = int(args.mode, 0)

    b = RL78Bridge(args.port)
    try:
        maj, minr = b.version()
        print(f"[*] bridge v{maj}.{minr} on {args.port}, mode=0x{mode:02x}")

        if args.power_cycle:
            print("[*] auto power-cycle")
            b.auto_reset(80, 25)

        b.set_baud(115200)

        # Step 1: entry. doEnter sends the mode byte and returns ~40ms of capture.
        init = b.enter(mode)
        print(f"[1] entry init/echo            : {hx(init)}")

        # Step 2: keep listening passively (NO flush) for ~1.2 s -- catch any
        # null/init/SYNC the monitor emits after the mode byte.
        print("[2] passive listen after mode byte (no flush):")
        for i in range(8):
            raw_read(b, 16, 150, f"listen{i}")

        # Step 3: Baud-Rate-Set, show full raw response (no framing parse).
        print("[3] Baud-Rate-Set:")
        raw_send_read(b, build_baud(0, 21), 16, 150, "baud")

        # Step 4: passive listen again for a SYNC after Baud-Rate-Set.
        print("[4] passive listen after Baud-Rate-Set (no flush):")
        for i in range(8):
            raw_read(b, 16, 150, f"postbaud{i}")

        # Step 5: actively send a SYNC(0x00) and see if the monitor answers.
        print("[5] host sends SYNC 0x00:")
        raw_send_read(b, b"\x00", 8, 200, "sync")
        raw_read(b, 16, 300, "after-sync")

        # Step 6: try PING 0x90 directly.
        print("[6] host sends PING 0x90 (expect PONG 03 03):")
        raw_send_read(b, b"\x90", 4, 200, "ping")
        raw_read(b, 16, 300, "after-ping")

        print("\nDone. Paste the full output back.")
    finally:
        b.reset_line(assert_low=False)
        b.close()


if __name__ == "__main__":
    sys.exit(main())

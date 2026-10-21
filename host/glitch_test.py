#!/usr/bin/env python3
"""
glitch_test.py -- Fire bare crowbar pulses for scope/Saleae verification.

No OCD, no UART, no target interaction — just toggles GLITCH_EN + LP/HP MOSFET.
Connect scope/Saleae to GLITCH_EN (GP3), LP (GP13) or HP (GP12) and REGC/VDD.

Examples:
  # Single 200ns pulse on LP MOSFET
  python glitch_test.py -p COM9 --width 200

  # 10 pulses, 500ns each, 1ms apart, HP MOSFET
  python glitch_test.py -p COM9 --width 500 --count 10 --interval 1000 --mosfet hp

  # Sweep widths from 100 to 1000ns in steps of 100, one pulse each
  python glitch_test.py -p COM9 --sweep 100 1000 100

  # Continuous burst (1000 pulses, 100ns, 10us apart) for trigger
  python glitch_test.py -p COM9 --width 100 --count 1000 --interval 10
"""
import argparse
import sys
import time

from rl78bridge import RL78Bridge, BridgeError


def main():
    ap = argparse.ArgumentParser(description="Test crowbar glitch pulses (no OCD).")
    ap.add_argument("-p", "--port", required=True, help="PicoGlitcher COM port")
    ap.add_argument("--width", type=int, default=200, help="pulse width in ns (default 200)")
    ap.add_argument("--mosfet", choices=["lp", "hp"], default="lp", help="LP or HP crowbar")
    ap.add_argument("--count", type=int, default=1, help="number of pulses (default 1)")
    ap.add_argument("--interval", type=int, default=100,
                    help="interval between pulses in us (default 100)")
    ap.add_argument("--sweep", nargs=3, type=int, metavar=("MIN", "MAX", "STEP"),
                    help="sweep width from MIN to MAX with STEP (ns), one pulse per width")
    ap.add_argument("--repeat", type=int, default=1,
                    help="repeat the whole test N times (default 1)")
    ap.add_argument("--pause", type=float, default=0.5,
                    help="pause between repeats in seconds (default 0.5)")
    args = ap.parse_args()

    b = RL78Bridge(args.port)
    try:
        ver = b.version()
        print(f"bridge v{ver[0]}.{ver[1]}", flush=True)
        if ver < (1, 13):
            print(f"ERROR: firmware {ver[0]}.{ver[1]} doesn't support 'T' command (need >= 1.13)")
            return 1

        if args.sweep:
            lo, hi, step = args.sweep
            widths = list(range(lo, hi + 1, step))
            print(f"sweep: {len(widths)} widths from {lo} to {hi} ns, step {step}, mosfet={args.mosfet}")
            for r in range(args.repeat):
                if args.repeat > 1:
                    print(f"--- repeat {r+1}/{args.repeat} ---")
                for w in widths:
                    fired = b.test_glitch(w, args.mosfet, count=1, interval_us=0)
                    print(f"  width={w:5d}ns  fired={fired}", flush=True)
                if r + 1 < args.repeat:
                    time.sleep(args.pause)
        else:
            print(f"glitch: width={args.width}ns, mosfet={args.mosfet}, "
                  f"count={args.count}, interval={args.interval}us", flush=True)
            for r in range(args.repeat):
                if args.repeat > 1:
                    print(f"--- repeat {r+1}/{args.repeat} ---")
                fired = b.test_glitch(args.width, args.mosfet,
                                      count=args.count, interval_us=args.interval)
                print(f"  fired {fired} pulse(s)", flush=True)
                if r + 1 < args.repeat:
                    time.sleep(args.pause)

        print("done.", flush=True)
        return 0
    except BridgeError as e:
        print(f"ERROR: {e}", flush=True)
        return 2
    finally:
        b.close()


if __name__ == "__main__":
    sys.exit(main())

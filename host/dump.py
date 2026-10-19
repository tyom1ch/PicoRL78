#!/usr/bin/env python3
"""
dump.py -- Glitch-scan + auto-dump RL78/F13 flash over OCD.

Randomized fault injection on the ID compare, then reads flash in the same
session. Uses 'Q' (fast, no identify) when fw >= 1.11, falls back to 'G'.

OCD debug primitives (after unlock):
  READ  0x92 + LE16 offset + size      -> size bytes (size 0 => 256)
  WRITE 0x93 + LE16 addr + len + data  -> echoes 0x93
  EXEC  0x94                           -> echoes 0x94

Flash read sequence (kirya-dev/PicoRL78, verified on RL78/F13):
  - DataFlash: direct READ at window offset 0x1000 + page*0x100.
  - CodeFlash: RAM helper at 0xFB00, per-page shellcode at 0x07E0 copies
    code flash into RAM 0xFC00, EXEC, READ 0xFC00.
"""
import argparse
import random
import itertools
import sys
import time

from rl78bridge import RL78Bridge, BridgeError

DEFAULT_OCD_ID = bytes(10)
OCD_VOLTAGE = 50
OCD_CONNECT, OCD_READ, OCD_WRITE, OCD_EXEC = 0x91, 0x92, 0x93, 0x94
NAMES = {0xF0: "UNLOCKED(F0)", 0xF1: "LOCKED(F1)", 0xF2: "UNLOCK-OK(F2)",
         0xF3: "AUTH-FAIL(F3)", 0xF4: "UNLOCK-NG(F4)"}


def log(m): print(m, flush=True)


class Ocd:
    def __init__(self, bridge, timeout_ms=300):
        self.b = bridge
        self.to = timeout_ms

    def _xfer(self, tx, nresp):
        rx = self.b.xfer(bytes(tx), len(tx) + nresp, self.to)
        return rx[len(tx):]

    def connect(self):
        status = self._xfer([OCD_CONNECT], 1)
        if not status or status[0] != 0xF0:
            got = status.hex() if status else "-"
            raise BridgeError(f"OCD CONNECT expected F0, got {got}")

    def write(self, addr, data):
        tx = [OCD_WRITE, addr & 0xFF, (addr >> 8) & 0xFF, len(data) & 0xFF] + list(data)
        ack = self._xfer(tx, 1)
        if not ack or ack[0] != OCD_WRITE:
            raise BridgeError(f"OCD WRITE @0x{addr:04x} bad ack {ack.hex() if ack else '-'}")

    def exec_(self):
        ack = self._xfer([OCD_EXEC], 1)
        if not ack or ack[0] != OCD_EXEC:
            raise BridgeError(f"OCD EXEC bad ack {ack.hex() if ack else '-'}")

    def read(self, offset, size):
        n = 256 if size == 0 else size
        data = self._xfer([OCD_READ, offset & 0xFF, (offset >> 8) & 0xFF, size & 0xFF], n)
        if len(data) != n:
            raise BridgeError(f"OCD READ @0x{offset:04x} short: {len(data)}/{n}")
        return data


def prepare_for_reading(o):
    o.write(0x07E0, [0xCB, 0xF8, 0xE0, 0xFE, 0xEC, 0xC7, 0xFF, 0x0E, 0, 0, 0, 0, 0, 0, 0, 0])
    o.exec_()
    o.write(0x0081, [0x00, 0xFF, 0x00])
    o.write(0x0078, [0x80])
    o.write(0x0090, [0x01])


def dump_dflash(o, pages, path):
    log(f"[DataFlash] {pages} pages ({pages*256} bytes) -> {path}")
    with open(path, "wb") as f:
        for i in range(pages):
            f.write(o.read(((0x10 + i) << 8), 0))
            if i % 4 == 0:
                print(f"\r  page {i+1}/{pages}", end="", flush=True)
    print()


def dump_cflash(o, pages, path):
    log(f"[CodeFlash] {pages} pages ({pages*256} bytes) -> {path}")
    o.write(0xFB00, [0x11, 0x8B, 0x99, 0xA5, 0xA7, 0xB3, 0x13, 0x44, 0x00, 0x00, 0xDF, 0xF4, 0xD7])
    with open(path, "wb") as f:
        for i in range(pages):
            o.write(0x07E0, [0x41, (i >> 8) & 0xFF, 0x36, 0x00, i & 0xFF, 0x34,
                             0x00, 0xFC, 0x32, 0x00, 0x01, 0xEC, 0x00, 0xFB, 0x0F, 0x00])
            o.exec_()
            f.write(o.read(0xFC00, 0))
            if i % 8 == 0:
                print(f"\r  page {i+1}/{pages}", end="", flush=True)
    print()


def verify_unlock(b):
    """Send CONNECT (0x91) to confirm chip is genuinely in OCD mode."""
    try:
        rx = b.xfer(bytes([0x91]), 2, 20)
        return len(rx) >= 2 and rx[1] == 0xF0
    except BridgeError:
        return False


def glitch_scan(b, args, ocd_id, use_fast):
    glitch_fn = b.fast_glitched_ocd if use_fast else b.glitched_ocd
    mode = "Q (fast)" if use_fast else "G"
    total = args.attempts
    log(f"[2] glitch scan: {total} attempts, mosfet={args.mosfet}, "
        f"delay={args.delay[0]}-{args.delay[1]}ns, width={args.width[0]}-{args.width[1]}ns, cmd={mode}")

    start = time.time()
    if args.grid:
        delays = range(args.delay[0], args.delay[1] + 1, args.delay_step)
        widths = range(args.width[0], args.width[1] + 1, args.width_step)
        param_iter = itertools.islice(
            itertools.cycle(itertools.product(delays, widths)), total)
    else:
        param_iter = ((random.randint(args.delay[0], args.delay[1]),
                       random.randint(args.width[0], args.width[1]))
                      for _ in range(total))

    for n, (delay, width) in enumerate(param_iter, 1):
        r = glitch_fn(args.voltage, False, ocd_id, delay, width, args.mosfet)
        idst = r["idst"]
        tag = NAMES.get(idst, f"0x{idst:02x}")
        speed = n / (time.time() - start + 1e-9)
        log(f"[{n:5d}/{total}] d={delay:5d}ns w={width:4d}ns -> {tag} ({speed:.1f}/s)")

        if idst not in (0xF3, 0xF1, 0xEE, 0xE0, 0xE2, 0xE3):
            if verify_unlock(b):
                log(f"    >>> VERIFIED UNLOCK at d={delay}ns w={width}ns (idst=0x{idst:02x}) <<<")
                return True
            else:
                log(f"    (0x{idst:02x} false positive — verify failed)")

    raise BridgeError("no verified unlock in this window — widen --delay / --width or increase --attempts")


def main():
    ap = argparse.ArgumentParser(description="RL78/F13 glitch + flash dump.")
    ap.add_argument("-p", "--port", required=True)
    ap.add_argument("--memory", choices=["dataflash", "codeflash", "both"], required=True)
    ap.add_argument("--auth", choices=["glitch", "session", "bypass"], default="glitch")
    ap.add_argument("--id", help="10-byte OCD ID hex (default ten 00)")
    ap.add_argument("--voltage", type=int, default=OCD_VOLTAGE)
    ap.add_argument("--delay", nargs=2, type=int, default=[0, 100000],
                    help="delay range [min max] ns from checksum byte start (default 0 100000)")
    ap.add_argument("--width", nargs=2, type=int, default=[80, 300],
                    help="width range [min max] ns (default 80 300)")
    ap.add_argument("--attempts", type=int, default=5000,
                    help="max attempts (default 5000)")
    ap.add_argument("--mosfet", choices=["lp", "hp"], default="lp")
    ap.add_argument("--grid", action="store_true",
                    help="systematic grid sweep instead of random")
    ap.add_argument("--delay-step", type=int, default=10,
                    help="delay step for --grid mode (ns, default 10)")
    ap.add_argument("--width-step", type=int, default=10,
                    help="width step for --grid mode (ns, default 10)")
    ap.add_argument("--no-fast", action="store_true",
                    help="use 'G' (full OCD with identify) even if fw supports 'Q'")
    ap.add_argument("--df-pages", type=int, default=16)
    ap.add_argument("--cf-pages", type=int, default=512)
    ap.add_argument("--df-out", default="../dumps/dataflash.bin")
    ap.add_argument("--cf-out", default="../dumps/codeflash.bin")
    args = ap.parse_args()

    ocd_id = bytes.fromhex(args.id.replace("0x", "").replace(",", " ")) if args.id else DEFAULT_OCD_ID
    if len(ocd_id) != 10:
        ap.error("--id must be 10 bytes")

    b = RL78Bridge(args.port)
    try:
        ver = b.version()
        log(f"[1] bridge v{ver[0]}.{ver[1]}")
        use_fast = ver >= (1, 11) and not args.no_fast
        if ver >= (1, 12):
            log("    fw >= 1.12: glitch during checksum byte (delay = ns from byte start)")
        elif ver >= (1, 11):
            log("    WARNING: fw 1.11 — glitch fires after echo, update to 1.12!")
        if use_fast:
            log("    using 'Q' (fast OCD, no identify) — ~2x speed")
        elif ver < (1, 11):
            log("    fw < 1.11, using 'G' (full OCD with identify)")

        need_connect = False
        if args.auth == "glitch":
            glitch_scan(b, args, ocd_id, use_fast)
        elif args.auth == "bypass":
            log("[2] authenticate (atomic OCD bypass)")
            r = b.ocd_bypass(args.voltage, False, ocd_id)
            log(f"    st1=0x{r['st1']:02x} ping={r['ping1']:02x}/{r['ping2']:02x} "
                f"connect=0x{r['connect']:02x} id=0x{r['idst']:02x}")
            if r["idst"] not in (0xF0, 0xF2):
                raise BridgeError(f"not authenticated (idst=0x{r['idst']:02x}, need F0 or F2)")
            need_connect = r["idst"] != 0xF0
        else:
            log("[2] reusing live OCD session; no auth/reset sent")

        o = Ocd(b)
        if need_connect:
            log("[3] confirm OCD CONNECT")
            o.connect()
        elif args.auth == "glitch":
            log("[3] CONNECT verified during scan; chip in OCD mode")
        elif args.auth != "session":
            log("[3] CONNECT returned F0; continuing")

        log("[4] prepare_for_reading")
        prepare_for_reading(o)
        if args.memory in ("dataflash", "both"):
            dump_dflash(o, args.df_pages, args.df_out)
        if args.memory in ("codeflash", "both"):
            dump_cflash(o, args.cf_pages, args.cf_out)
        log("Done.")
        return 0
    except BridgeError as e:
        log(f"ERROR: {e}")
        return 2
    finally:
        try:
            b.reset_line(assert_low=False)
        except Exception:
            pass
        b.close()


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
scan_rom.py -- Search for the Renesas RL78 OCD monitor boot ROM.

Systematically scans the RL78's memory space looking for the mask ROM that
implements the undocumented OCD debug protocol (0x91-0x94, authentication).
Four complementary methods:

  Phase 1: OCD READ window scan (64 KB, physical 0xF0000-0xFFFFF)
  Phase 2: SFR context capture (SP, PSW, stack -> OCD monitor addresses)
  Phase 3: Shellcode scan of 20-bit space (1 MB, multiple SFR configs)
  Phase 4: Targeted full dump of discovered non-FF regions

Requires: known 10-byte OCD ID for clean authentication (no glitching).

Memory model:
  OCD READ  16-bit offset  -> physical 0xF0000 + offset  (RAM/SFR/DataFlash)
  Shellcode ES:[HL]        -> full 20-bit space (1 MB)
  Code flash is NOT visible through OCD READ (needs shellcode copy to RAM).
"""
import argparse
import os
import struct
import sys
import time

from rl78bridge import RL78Bridge, BridgeError

DEFAULT_OCD_ID = bytes(10)
OCD_VOLTAGE = 50
OCD_CONNECT, OCD_READ, OCD_WRITE, OCD_EXEC = 0x91, 0x92, 0x93, 0x94

BLANK_PAGE = b'\xFF' * 256
ZERO_PAGE = b'\x00' * 256

# 13-byte copy loop: ES:[HL] -> [DE], count in BC, then RET (kirya-dev, verified)
COPY_LOOP = bytes([0x11, 0x8B, 0x99, 0xA5, 0xA7, 0xB3, 0x13,
                   0x44, 0x00, 0x00, 0xDF, 0xF4, 0xD7])

# SFR setup shellcode executed by prepare_for_reading (from dump.py)
SFR_SETUP_CODE = bytes([0xCB, 0xF8, 0xE0, 0xFE, 0xEC, 0xC7, 0xFF, 0x0E,
                        0, 0, 0, 0, 0, 0, 0, 0])

OCD_WINDOW_BASE = 0xF0000
RAM_PHY_START   = 0xFDF00
RAM_PHY_END     = 0xFFEFF
SFR_PHY_START   = 0xFFF00
DFLASH_PHY_START = 0xF1000
DFLASH_PHY_END   = 0xF1FFF
CFLASH_END       = 0x1FFFF

MAX_CONSEC_FAIL = 5


def log(m):
    print(m, flush=True)


def hexdump(data, base_addr, prefix="    "):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = ' '.join(f'{b:02X}' for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{prefix}{base_addr + i:05X}  {hx:<48s}  {asc}")
    return lines


# ---------------------------------------------------------------------------
#  OCD primitives (same as dump.py)
# ---------------------------------------------------------------------------
class Ocd:
    def __init__(self, bridge, timeout_ms=500):
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
        tx = ([OCD_WRITE, addr & 0xFF, (addr >> 8) & 0xFF, len(data) & 0xFF]
              + list(data))
        ack = self._xfer(tx, 1)
        if not ack or ack[0] != OCD_WRITE:
            raise BridgeError(
                f"OCD WRITE @0x{addr:04X} bad ack {ack.hex() if ack else '-'}")

    def exec_(self):
        ack = self._xfer([OCD_EXEC], 1)
        if not ack or ack[0] != OCD_EXEC:
            raise BridgeError(
                f"OCD EXEC bad ack {ack.hex() if ack else '-'}")

    def read(self, offset, size):
        n = 256 if size == 0 else size
        data = self._xfer(
            [OCD_READ, offset & 0xFF, (offset >> 8) & 0xFF, size & 0xFF], n)
        if len(data) != n:
            raise BridgeError(
                f"OCD READ @0x{offset:04X} short: {len(data)}/{n}")
        return data


# ---------------------------------------------------------------------------
#  OCD session management
# ---------------------------------------------------------------------------
def enter_ocd(bridge, ocd_id, voltage):
    r = bridge.ocd_bypass(voltage, False, ocd_id)
    idst = r["idst"]
    log(f"  st1=0x{r['st1']:02X} connect=0x{r['connect']:02X} idst=0x{idst:02X}")
    if idst not in (0xF0, 0xF2):
        raise BridgeError(f"OCD auth failed (idst=0x{idst:02X})")
    o = Ocd(bridge)
    if idst == 0xF2:
        o.connect()
    return o


def reenter_ocd(bridge, ocd_id, voltage):
    log("  >> recovering OCD session...")
    bridge.auto_reset(100, 200)
    time.sleep(0.15)
    return enter_ocd(bridge, ocd_id, voltage)


# ---------------------------------------------------------------------------
#  Shellcode helpers
# ---------------------------------------------------------------------------
def install_copy_loop(o):
    o.write(0xFB00, list(COPY_LOOP))


def prepare_for_reading(o):
    o.write(0x07E0, list(SFR_SETUP_CODE))
    o.exec_()
    o.write(0x0081, [0x00, 0xFF, 0x00])
    o.write(0x0078, [0x80])
    o.write(0x0090, [0x01])


def set_flars(o, value):
    o.write(0x0090, [value & 0xFF])


def page_shellcode(page_index):
    """16-byte per-page setup: ES:HL = source (20-bit), DE = 0xFC00, BC = 256."""
    es = (page_index >> 8) & 0xFF
    hl_hi = page_index & 0xFF
    return [0x41, es,
            0x36, 0x00, hl_hi,
            0x34, 0x00, 0xFC,
            0x32, 0x00, 0x01,
            0xEC, 0x00, 0xFB,
            0x0F, 0x00]


def read_page(o, page_index):
    o.write(0x07E0, page_shellcode(page_index))
    o.exec_()
    return o.read(0xFC00, 0)


# ---------------------------------------------------------------------------
#  Phase 1 — OCD READ window scan
# ---------------------------------------------------------------------------
def phase1_ocd_window(o, output_dir, verbose):
    log("\n" + "=" * 60)
    log("Phase 1: OCD READ window (physical 0xF0000-0xFFFFF)")
    log("=" * 60)

    data = bytearray()
    regions = []
    region_start = None

    for page in range(256):
        offset = page << 8
        phy = OCD_WINDOW_BASE + offset
        page_data = o.read(offset, 0)
        data.extend(page_data)

        blank = (page_data == BLANK_PAGE)
        if not blank:
            label = _phy_label(phy)
            log(f"  0x{phy:05X}-0x{phy + 0xFF:05X}  DATA  ({label})  "
                f"{page_data[:16].hex(' ')}")
            if region_start is None:
                region_start = phy
        else:
            if region_start is not None:
                regions.append((region_start, phy - 1))
                region_start = None
            if verbose:
                log(f"  0x{phy:05X}-0x{phy + 0xFF:05X}  FF")

        if page % 64 == 0:
            print(f"\r  scanning... {page}/256", end="", flush=True)

    if region_start is not None:
        regions.append((region_start, OCD_WINDOW_BASE + 0xFFFF))
    print()

    path = os.path.join(output_dir, "ocd_window.bin")
    with open(path, "wb") as f:
        f.write(data)
    log(f"  saved 64 KB -> {path}")

    log("\n  non-FF regions:")
    for s, e in regions:
        log(f"    0x{s:05X}-0x{e:05X}  ({e - s + 1:5d} B)  {_phy_label(s)}")

    return bytes(data), regions


def _phy_label(addr):
    if addr >= SFR_PHY_START:
        return "SFR"
    if addr >= RAM_PHY_START:
        return "RAM"
    if DFLASH_PHY_START <= addr <= DFLASH_PHY_END:
        return "DataFlash"
    if OCD_WINDOW_BASE <= addr < DFLASH_PHY_START:
        return "reserved (F0xxx)"
    return "?"


# ---------------------------------------------------------------------------
#  Phase 2 — SFR context capture
# ---------------------------------------------------------------------------
def phase2_sfr_context(o, output_dir):
    log("\n" + "=" * 60)
    log("Phase 2: SFR context capture")
    log("=" * 60)

    report = []

    def note(line):
        log(line)
        report.append(line)

    # SP at physical 0xFFFF8-0xFFFF9 -> OCD 0xFFF8
    sp_raw = o.read(0xFFF8, 2)
    sp = struct.unpack("<H", sp_raw)[0]
    note(f"  SP  = 0x{sp:04X}  (OCD 0xFFF8, physical 0xFFFF8)")

    # PSW at physical 0xFFFFA -> OCD 0xFFFA
    psw = o.read(0xFFFA, 1)[0]
    note(f"  PSW = 0x{psw:02X}  (OCD 0xFFFA)")

    # ES at physical 0xFFFFC -> OCD 0xFFFC
    es_cs = o.read(0xFFFC, 2)
    note(f"  CS:ES = {es_cs.hex(' ')}  (OCD 0xFFFC-0xFFFD)")

    # Read SFR page (last 256 bytes: OCD 0xFF00-0xFFFF)
    sfr_data = o.read(0xFF00, 0)
    note("\n  SFR dump (0xFFF00-0xFFFFF):")
    for line in hexdump(sfr_data, 0xFFF00):
        note(line)

    # Stack area
    note(f"\n  Stack dump around SP=0x{sp:04X}:")
    # SP value is a 16-bit address in the RAM region.
    # On RL78/F13, RAM is OCD 0xDF00-0xFEFF.
    # Read ±64 bytes around SP.
    stack_lo = max(0xDF00, sp - 64) & 0xFFFE  # align down
    stack_hi = min(0xFEFF, sp + 64)
    stack_size = min(256, stack_hi - stack_lo + 1)
    if stack_size > 0:
        stack_data = o.read(stack_lo, stack_size)
        for line in hexdump(stack_data, OCD_WINDOW_BASE + stack_lo):
            note(line)

        # Look for potential return addresses in stack
        candidates = []
        for i in range(0, len(stack_data) - 1, 2):
            val = struct.unpack("<H", stack_data[i:i + 2])[0]
            if val not in (0x0000, 0xFFFF):
                candidates.append((stack_lo + i, val))
        if candidates:
            note("\n  potential addresses on stack:")
            for ocd_addr, val in candidates:
                note(f"    [{OCD_WINDOW_BASE + ocd_addr:05X}] = 0x{val:04X}")
    else:
        note("  (SP outside readable RAM range)")
        stack_data = b""
        candidates = []

    # Full RAM dump (8 KB) for offline analysis
    note("\n  dumping full RAM (8 KB) for offline analysis...")
    ram_ocd_start = RAM_PHY_START - OCD_WINDOW_BASE  # 0xDF00
    ram_pages = (RAM_PHY_END - RAM_PHY_START + 1 + 255) // 256
    ram_data = bytearray()
    for i in range(ram_pages):
        offset = ram_ocd_start + i * 256
        remaining = RAM_PHY_END - OCD_WINDOW_BASE - offset + 1
        sz = min(256, remaining)
        if sz == 256:
            ram_data.extend(o.read(offset, 0))
        elif sz > 0:
            ram_data.extend(o.read(offset, sz))

    ram_path = os.path.join(output_dir, "ocd_ram.bin")
    with open(ram_path, "wb") as f:
        f.write(ram_data)
    note(f"  saved RAM ({len(ram_data)} B) -> {ram_path}")

    ctx_path = os.path.join(output_dir, "ocd_context.txt")
    with open(ctx_path, "w", encoding="utf-8") as f:
        f.write('\n'.join(report) + '\n')
    note(f"  saved context -> {ctx_path}")

    return sp, candidates


# ---------------------------------------------------------------------------
#  Phase 3 — Shellcode scan engine
# ---------------------------------------------------------------------------
def _scan_pages(o, bridge, ocd_id, voltage, pages, label, need_prepare, verbose):
    """Core scan: returns {page_index: bytes}, updated Ocd."""
    found = {}
    fails = 0

    for n, pi in enumerate(pages):
        addr20 = pi * 0x100
        try:
            pg = read_page(o, pi)
            fails = 0
        except BridgeError as e:
            fails += 1
            log(f"    page {pi} (0x{addr20:05X}): ERROR — {e}")
            if fails > MAX_CONSEC_FAIL:
                log(f"    >> {fails} consecutive failures, aborting {label}")
                break
            try:
                o = reenter_ocd(bridge, ocd_id, voltage)
                install_copy_loop(o)
                if need_prepare:
                    prepare_for_reading(o)
            except BridgeError:
                log("    >> recovery failed, aborting")
                break
            continue

        blank = (pg == BLANK_PAGE)
        if not blank:
            tag = "ZERO" if pg == ZERO_PAGE else "DATA"
            log(f"    page {pi:4d} (0x{addr20:05X}) [{tag}] "
                f"{pg[:16].hex(' ')}")
            found[pi] = pg
        elif verbose:
            log(f"    page {pi:4d} (0x{addr20:05X}) [FF]")

        if n % 20 == 0 and len(pages) > 30:
            print(f"\r    {label}: {n + 1}/{len(pages)}", end="", flush=True)

    if len(pages) > 30:
        print()

    log(f"    {label}: {len(found)} non-FF / {len(pages)} scanned")
    return found, o


def phase3a_raw(o, bridge, ocd_id, voltage, page_list, verbose):
    log("\n" + "=" * 60)
    log("Phase 3a: Shellcode scan — raw (no SFR setup)")
    log("=" * 60)
    install_copy_loop(o)
    return _scan_pages(o, bridge, ocd_id, voltage, page_list,
                       "3a-raw", need_prepare=False, verbose=verbose)


def phase3b_flash(o, bridge, ocd_id, voltage, page_list, compare_path, verbose):
    log("\n" + "=" * 60)
    log("Phase 3b: Shellcode scan — with flash SFR config")
    log("=" * 60)
    install_copy_loop(o)
    prepare_for_reading(o)

    found, o = _scan_pages(o, bridge, ocd_id, voltage, page_list,
                           "3b-flash", need_prepare=True, verbose=verbose)

    if compare_path and os.path.exists(compare_path):
        log(f"\n  comparing code flash pages with {compare_path}...")
        with open(compare_path, "rb") as f:
            cflash = f.read()
        match = mismatch = 0
        for pi, data in sorted(found.items()):
            foff = pi * 256
            if foff + 256 <= len(cflash):
                if data == cflash[foff:foff + 256]:
                    match += 1
                else:
                    mismatch += 1
                    log(f"    MISMATCH page {pi} (0x{pi * 0x100:05X})")
        log(f"    code flash: {match} match, {mismatch} mismatch")
        if mismatch:
            log("    >> MISMATCHES may indicate ROM overlay!")

    return found, o


def phase3c_flars(o, bridge, ocd_id, voltage, page_list, verbose):
    log("\n" + "=" * 60)
    log("Phase 3c: Alternative FLARS values")
    log("=" * 60)

    all_results = {}
    for fv in (0x00, 0x02, 0x03, 0x04):
        log(f"\n  --- FLARS = 0x{fv:02X} ---")
        try:
            install_copy_loop(o)
            prepare_for_reading(o)
            set_flars(o, fv)
        except BridgeError:
            o = reenter_ocd(bridge, ocd_id, voltage)
            install_copy_loop(o)
            prepare_for_reading(o)
            set_flars(o, fv)

        found, o = _scan_pages(o, bridge, ocd_id, voltage, page_list,
                               f"3c-FLARS{fv:02X}", need_prepare=True,
                               verbose=verbose)
        all_results[fv] = found

    return all_results, o


# ---------------------------------------------------------------------------
#  Phase 4 — Targeted full dump
# ---------------------------------------------------------------------------
def _merge_regions(page_set):
    """From a set of page indices, build merged (start_pi, end_pi) runs,
    expanding each by ±16 pages to catch surrounding ROM."""
    if not page_set:
        return []
    pages = sorted(page_set)
    expanded = []
    for p in pages:
        lo = max(0, p - 16)
        hi = min(4095, p + 16)
        expanded.append((lo, hi))
    expanded.sort()
    merged = [expanded[0]]
    for lo, hi in expanded[1:]:
        if lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def phase4_dump(o, bridge, ocd_id, voltage, candidate_pages, output_dir,
                need_prepare, verbose):
    log("\n" + "=" * 60)
    log("Phase 4: Targeted full dump of discovered regions")
    log("=" * 60)

    # Filter out known code flash pages
    unknown = {p for p in candidate_pages if p * 0x100 > CFLASH_END}
    if not unknown:
        log("  no non-codeflash regions to dump")
        return o

    regions = _merge_regions(unknown)
    for s, e in regions:
        a0, a1 = s * 0x100, (e + 1) * 0x100 - 1
        log(f"  region 0x{a0:05X}-0x{a1:05X}  ({(e - s + 1) * 256} B)")

    install_copy_loop(o)
    if need_prepare:
        prepare_for_reading(o)

    for s, e in regions:
        pages = list(range(s, e + 1))
        a0, a1 = s * 0x100, (e + 1) * 0x100 - 1
        log(f"\n  dumping 0x{a0:05X}-0x{a1:05X}...")

        found, o = _scan_pages(o, bridge, ocd_id, voltage, pages,
                               f"dump-{a0:05X}", need_prepare=need_prepare,
                               verbose=verbose)

        buf = bytearray(b'\xFF' * len(pages) * 256)
        for pi, data in found.items():
            off = (pi - s) * 256
            buf[off:off + 256] = data

        fname = f"rom_{a0:05X}_{a1:05X}.bin"
        path = os.path.join(output_dir, fname)
        with open(path, "wb") as f:
            f.write(buf)
        log(f"  saved -> {path}")

    return o


# ---------------------------------------------------------------------------
#  Page-list builders
# ---------------------------------------------------------------------------
def build_page_list(full_sweep, scan_range):
    """Return the list of page indices for phase 3 scans."""
    if scan_range:
        parts = scan_range.split("-")
        lo = int(parts[0], 16)
        hi = int(parts[1], 16) if len(parts) > 1 else lo + 0xFFFF
        start_pi = lo // 0x100
        end_pi = hi // 0x100
        return list(range(start_pi, end_pi + 1))

    # 0x00000-0xEFFFF = pages 0..3839 (skip OCD window, covered by phase 1)
    if full_sweep:
        return list(range(3840))
    # Quick sweep: one page every 16 KB (64 pages)
    return list(range(0, 3840, 64))


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="RL78 boot ROM / OCD monitor extraction.")
    ap.add_argument("-p", "--port", required=True)
    ap.add_argument("--id", help="10-byte OCD ID hex (default: ten 0x00)")
    ap.add_argument("--voltage", type=int, default=OCD_VOLTAGE,
                    help="voltage byte (default 50 = 5.0 V)")
    ap.add_argument("--phase", default="all",
                    help="phases to run: 1,2,3,3a,3b,3c,4 or 'all'")
    ap.add_argument("--output-dir", default="../dumps",
                    help="output directory (default ../dumps)")
    ap.add_argument("--scan-range",
                    help="custom 20-bit hex range for phase 3 (e.g. 20000-2FFFF)")
    ap.add_argument("--full-sweep", action="store_true",
                    help="every page instead of every 64th (slow, ~20 min)")
    ap.add_argument("--compare",
                    help="codeflash.bin path for phase 3b comparison")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    ocd_id = (bytes.fromhex(args.id.replace("0x", "").replace(",", "")
                            .replace(" ", ""))
              if args.id else DEFAULT_OCD_ID)
    if len(ocd_id) != 10:
        ap.error("--id must be 10 bytes")

    os.makedirs(args.output_dir, exist_ok=True)

    phases = set()
    for tok in args.phase.lower().replace(" ", "").split(","):
        phases.add(tok)
    run_all = "all" in phases

    page_list = build_page_list(args.full_sweep, args.scan_range)

    b = RL78Bridge(args.port)
    try:
        ver = b.version()
        log(f"bridge v{ver[0]}.{ver[1]}")
        log("\nOCD entry (clean, known ID)...")
        o = enter_ocd(b, ocd_id, args.voltage)
        log("  session active\n")

        all_found = {}       # page_index -> bytes (from shellcode scans)
        need_prepare = False

        # ---- Phase 1 ----
        if run_all or "1" in phases:
            phase1_ocd_window(o, args.output_dir, args.verbose)

        # ---- Phase 2 ----
        if run_all or "2" in phases:
            phase2_sfr_context(o, args.output_dir)

        # ---- Phase 3a ----
        results_3a = {}
        if run_all or "3" in phases or "3a" in phases:
            results_3a, o = phase3a_raw(
                o, b, ocd_id, args.voltage, page_list, args.verbose)
            all_found.update(results_3a)

        # ---- Phase 3b ----
        results_3b = {}
        if run_all or "3" in phases or "3b" in phases:
            results_3b, o = phase3b_flash(
                o, b, ocd_id, args.voltage, page_list,
                args.compare, args.verbose)
            for pi, data in results_3b.items():
                if pi not in all_found:
                    all_found[pi] = data
                    need_prepare = True
            new_only_b = set(results_3b) - set(results_3a)
            if new_only_b:
                log(f"\n  pages visible ONLY with flash config: "
                    f"{sorted(new_only_b)[:20]}"
                    f"{'...' if len(new_only_b) > 20 else ''}")

        # ---- Phase 3c ----
        if run_all or "3" in phases or "3c" in phases:
            results_3c, o = phase3c_flars(
                o, b, ocd_id, args.voltage, page_list, args.verbose)
            for fv, found in results_3c.items():
                for pi, data in found.items():
                    if pi not in all_found:
                        all_found[pi] = data
                        log(f"    NEW page {pi} (0x{pi * 0x100:05X}) "
                            f"with FLARS=0x{fv:02X}")

        # ---- Phase 4 ----
        if run_all or "4" in phases:
            if all_found:
                o = phase4_dump(o, b, ocd_id, args.voltage, all_found,
                                args.output_dir, need_prepare, args.verbose)
            else:
                log("\n  phase 4: nothing to dump (no non-FF pages found)")

        # ---- Summary ----
        log("\n" + "=" * 60)
        log("SCAN COMPLETE")
        log("=" * 60)
        if all_found:
            cf = [p for p in all_found if p * 0x100 <= CFLASH_END]
            other = [p for p in all_found if p * 0x100 > CFLASH_END]
            log(f"  total non-FF pages: {len(all_found)}")
            if cf:
                log(f"    code flash range : {len(cf)}")
            if other:
                log(f"    outside cflash   : {len(other)}  <- POTENTIAL ROM")
                for p in sorted(other)[:30]:
                    log(f"      0x{p * 0x100:05X}: "
                        f"{all_found[p][:16].hex(' ')}")
        else:
            log("  no non-FF pages found via shellcode")
        log(f"\noutput: {os.path.abspath(args.output_dir)}")
        return 0

    except BridgeError as e:
        log(f"\nERROR: {e}")
        return 2
    finally:
        try:
            b.reset_line(assert_low=False)
        except Exception:
            pass
        b.close()


if __name__ == "__main__":
    sys.exit(main())

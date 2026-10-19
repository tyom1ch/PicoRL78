#!/usr/bin/env python3
"""
enter_ocd.py -- Bring an RL78/F13 R5F10BAG into OCD and confirm it cleanly,
                with ZERO risk to flash.  No glitching; documented path only.

Flow verified against kirya-dev/PicoRL78 (working on RL78/F13 R5F10AGG):
  1. Bridge handshake / version.
  2. OCD connect:
       reset-entry waveform + MODE_OCD(0xC5)          [R20AN6332 1.4 + kirya]
       Baud-Rate-Set(code=0 @115200, 5.0 V=50)        [R01AN0815 Fig 3-3/3-4]
       -> expect ST1=ACK(0x06)
       0x00 ping / send 0x00 / 0x00 ping              [kirya MCU_OCD_bypass]
  3. OCD CONNECT (0x91) -> expect LOCKED (0xF1)        [kirya OCD_CMD_CONNECT]
  4. Send 10-byte ID + checksum -> expect F3 (auth-fail NACK).
       On RL78/F13, F3 (OCD_STS_UNLOCK_ERR) is the normal, non-glitched reply
       and proves: chip is in OCD, framing correct, authentication stage reached.
       (DRIVE2 R5F10AGG: "при обычной попытке получаем ответ F3".)
  5. STOP.  No glitch, no erase, no program.

This device's OCD option byte 000C3H = 0x87 (OCDENSET=1, HPIEN=1, OCDERSD=1):
flash is NOT erased on ID-auth failure (R01UH0368 Fig 29-4). Its 10-byte OCD ID
in the dump is ten 0x00s (sent by default; checksum (sum-1)&0xFF = 0xFF).

Option: --corrupt-sum sends a deliberately wrong checksum (guarantees a NACK,
never a full unlock). --unlock loops until F2 (full unlock) -- off by default.
"""

import argparse
import sys
import time

from rl78bridge import RL78Bridge, BridgeError
from rl78_proto import (
    Link, ProtoA, ProtoOCD,
    MODE_OCD, MODE_A_1WIRE, STX, OCD_SYNC,
    build_command, parse_frame, COM_BAUDRATE_SET, BR_CODE,
    ST_ACK, ST_PROTECT_ERR, ST_NAMES,
    ST_UNLOCK_ALREADY, ST_UNLOCK_LOCKED, ST_UNLOCK_OK, ST_UNLOCK_ERR, ST_UNLOCK_NG,
    OCD_UNLOCK_NAMES, ProtoError,
)

OCD_VOLTAGE = 50   # 5.0 V -> 50 (0x32), as kirya-dev uses for F13

# Real OCD security ID recovered from the same chip's dump (OCDID_*.bin).
DEFAULT_OCD_ID = bytes([0x00] * 10)


def log(msg):
    print(msg, flush=True)


def ocd_connect(bridge, chip="R5F10BAG", trace=True, debug=False):
    link = Link(bridge, chip=chip, trace=trace, default_timeout_ms=200)
    a = ProtoA(link)
    ocd = ProtoOCD(link)

    log("[2] OCD connect (mode 0xC5 + Baud-Rate-Set sent back-to-back)")
    bridge.set_baud(115200)
    baud_frame = build_command(COM_BAUDRATE_SET, bytes([BR_CODE[115200], OCD_VOLTAGE]))
    cap = bridge.enter(MODE_OCD, followup=baud_frame)     # ATOMIC, no gap (fw v1.2)

    echo_len = 1 + len(baud_frame)                        # echo of 0xC5 + baud frame
    echo, resp = cap[:echo_len], cap[echo_len:]
    if trace:
        log(f"    PROG>{chip} : c5 {baud_frame.hex(' ')}  (mode + Baud-Rate-Set)")
        log(f"    {chip}>PROG : {resp.hex(' ') or '(nothing)'}")

    if len(resp) < 4 or resp[0] != STX:
        raise ProtoError("no Baud-Rate-Set response after 0xC5 -- chip did not "
                         f"enter OCD. full capture = {cap.hex(' ')}")
    n = 256 if resp[1] == 0 else resp[1]
    st1 = parse_frame(resp[:2 + n + 2])[0][0]
    tail = resp[2 + n + 2:]                                # bytes AFTER the baud frame
    log(f"    Baud-Rate-Set ST1     : 0x{st1:02x} ({ST_NAMES.get(st1, '?')})")
    log(f"    tail after baud frame : {tail.hex(' ') or '(none)'}")
    if st1 == ST_PROTECT_ERR:
        raise ProtoError("ProtectError (0x10): this unit needs a glitch to bypass "
                         "ProtectError before OCD -- out of scope for clean entry")
    if st1 != ST_ACK:
        raise ProtoError(f"Baud-Rate-Set not ACKed (0x{st1:02x})")

    if OCD_SYNC in tail:
        log("    OCD 0x00 ping present -> monitor is live (we are in OCD).")
    else:
        log("    (no 0x00 ping in tail yet)")
    ping = ocd.sync_pong()                                # send 0x00, read 0x00
    log(f"    OCD 0x00 handshake    : tail={tail.hex(' ') or '-'} ping={ping.hex(' ') or '-'}")
    return a, ocd


def f3_probe(ocd, ocd_id, corrupt_sum=False):
    log("[3] OCD CONNECT (0x91)")
    st = ocd.connect()
    log(f"    CONNECT status        : 0x{st:02x} ({OCD_UNLOCK_NAMES.get(st, '?')})")
    if st == ST_UNLOCK_ALREADY:
        log("    Device already unlocked (F0) -- already in authenticated OCD.")
        return "ALREADY"
    if st != ST_UNLOCK_LOCKED:
        raise ProtoError(f"unexpected CONNECT status 0x{st:02x}")

    tag = "wrong checksum (guaranteed NACK)" if corrupt_sum else "correct checksum"
    log(f"[4] Send 10-byte ID + {tag}")
    st = ocd.send_id(ocd_id, corrupt_sum=corrupt_sum)
    log(f"    ID result             : 0x{st:02x} ({OCD_UNLOCK_NAMES.get(st, '?')})")
    if st == ST_UNLOCK_ERR:
        log("")
        log("    ==> F3 CONFIRMED. Chip is in OCD, framing correct, authentication")
        log("        stage reached, flash intact (OCDERSD=1). Clean stop.")
        return "F3"
    if st == ST_UNLOCK_OK:
        log("    ==> F2: ID accepted -- OCD is fully UNLOCKED (the 10x00 ID matched).")
        return "F2"
    if st == ST_UNLOCK_NG:
        log("    ==> F4 (UNLOCK-NG). No erase here (OCDERSD=1).")
        return "F4"
    raise ProtoError(f"unexpected ID result 0x{st:02x}")


def full_unlock(ocd, ocd_id, tries=30):
    log("[5*] Full unlock (--unlock): sending real ID + correct checksum until F2")
    for _ in range(tries):
        st = ocd.connect()
        if st == ST_UNLOCK_ALREADY:
            log("     Already unlocked (F0)."); return True
        if st != ST_UNLOCK_LOCKED:
            raise ProtoError(f"unexpected CONNECT status 0x{st:02x}")
        st = ocd.send_id(ocd_id, corrupt_sum=False)
        log(f"     ID result            : 0x{st:02x} ({OCD_UNLOCK_NAMES.get(st, '?')})")
        if st == ST_UNLOCK_OK:
            log("     ==> F2: OCD fully unlocked."); return True
        # F3/F4 -> without a glitch this won't advance; stop after one real try
        break
    log("     Not unlocked without a glitch (expected if the ID is not all-zero).")
    return False


def run_atomic(bridge, chip, ocd_id, voltage, corrupt):
    """Primary path: whole OCD handshake runs on the Pico (no USB-gap jitter)."""
    log("[2] On-MCU OCD handshake (v1.9: capture-derived timing, no USB gaps)")
    r = bridge.ocd_bypass(voltage, corrupt, ocd_id)
    special = {0xE0: "missing/malformed baud frame", 0xE2: "TX echo mismatch",
               0xE3: "identify phase failed", 0xEE: "not-reached",
               0xFE: "UART receive error", 0xFF: "timeout"}

    def nm(table, v):
        return table.get(v, special.get(v, "?"))

    log(f"    Baud-Rate-Set ST1 : 0x{r['st1']:02x} ({nm(ST_NAMES, r['st1'])})")
    log(f"    0x00 ping1 / ping2: 0x{r['ping1']:02x} / 0x{r['ping2']:02x}  (00=ok, ff=timeout)")
    log(f"    CONNECT (0x91)    : 0x{r['connect']:02x} ({nm(OCD_UNLOCK_NAMES, r['connect'])})")
    log(f"    ID result         : 0x{r['idst']:02x} ({nm(OCD_UNLOCK_NAMES, r['idst'])})")

    st = r["idst"]
    if st == ST_UNLOCK_OK:
        log("\n    ==> F2: ID ACCEPTED -- OCD AUTHENTICATED (the 10-byte password,")
        log("        all 0x00 on this chip, matched). This is the clean legitimate entry.")
        return "F2"
    if st in (ST_UNLOCK_ALREADY,) or r["connect"] == ST_UNLOCK_ALREADY:
        log("\n    ==> F0: already unlocked / authenticated.")
        return "ALREADY"
    if st == ST_UNLOCK_ERR:
        log("\n    ==> F3: authentication rejected (NACK). In OCD, framing correct,")
        log("        flash intact (OCDERSD=1). Expected only if the real ID is NOT all-zero,")
        log("        or with --corrupt-sum. Pass the real --id to reach F2.")
        return "F3"
    if st == ST_UNLOCK_NG:
        log("\n    ==> F4 (UNLOCK-NG). No erase here (OCDERSD=1).")
        return "F4"

    # Diagnose where it stalled.
    if r["st1"] == 0xE3:
        raise ProtoError("Programming-mode identify failed before OCD entry; "
                         "capture TOOL0 + RESET to locate the failed frame.")
    if r["st1"] != ST_ACK:
        raise ProtoError(f"Baud-Rate-Set not ACKed (ST1=0x{r['st1']:02x}); "
                         "chip not responding to the serial handshake.")
    if r["ping1"] == 0xFF:
        raise ProtoError("No 0x00 ping from the monitor after Baud-Rate-Set ACK: "
                         "chip did not advance into the OCD monitor. Try --power-cycle, "
                         "verify VTARGET matches --voltage, and re-capture TOOL0.")
    if r["ping1"] != 0x00 or r["ping2"] != 0x00:
        raise ProtoError(f"OCD sync failed: ping1=0x{r['ping1']:02x}, "
                         f"ping2=0x{r['ping2']:02x}; sequence stopped.")
    if r["connect"] in (0xFF, 0xEE):
        raise ProtoError(f"No CONNECT(0x91) response (ping1=0x{r['ping1']:02x}, "
                         f"ping2=0x{r['ping2']:02x}); OCD handshake stalled before CONNECT.")
    raise ProtoError(f"Unexpected OCD result: {r}")


def sig_check(bridge, chip="R5F10BAG", trace=True):
    """Independent physical-layer sanity check in programming mode (0x3A).
    Reads the silicon signature -- fully documented and non-destructive."""
    log("[sig] Programming-mode physical-layer check (mode 0x3A)")
    link = Link(bridge, chip=chip, trace=trace, default_timeout_ms=300)
    a = ProtoA(link)
    bridge.set_baud(115200)
    init = bridge.enter(MODE_A_1WIRE)
    log(f"      entry init/echo     : {init.hex(' ') or '(none)'}")
    st = a.set_baudrate(115200, voltage=OCD_VOLTAGE)   # 5.0 V like kirya identify
    log(f"      Baud-Rate-Set       : 0x{st:02x} ({ST_NAMES.get(st, '?')})")
    time.sleep(0.02)
    rst = a.reset()
    log(f"      Reset cmd status    : 0x{rst:02x} ({ST_NAMES.get(rst, '?')})")
    st, sig = a.silicon_signature()
    log(f"      Silicon-Sig status  : 0x{st:02x} ({ST_NAMES.get(st, '?')})")
    log(f"      Signature bytes     : {sig.hex(' ') or '(none)'}")


def main():
    ap = argparse.ArgumentParser(description="RL78 clean OCD entry (F3 confirm).")
    ap.add_argument("-p", "--port", required=True, help="Pico CDC port, e.g. COM7 or /dev/ttyACM0")
    ap.add_argument("--id", help="10-byte OCD ID as hex (default: ten 00 from dump)")
    ap.add_argument("--unlock", action="store_true", help="also try full unlock (F2) with correct checksum")
    ap.add_argument("--corrupt-sum", action="store_true",
                    help="send a deliberately wrong checksum (guarantees a NACK, never unlocks)")
    ap.add_argument("--sig", action="store_true", help="run programming-mode silicon-signature check first")
    ap.add_argument("--power-cycle", action="store_true",
                    help="cold power-cycle the target (VTARGET) before entry, held in reset")
    ap.add_argument("--voltage", type=int, default=OCD_VOLTAGE,
                    help="Baud-Rate-Set voltage byte (V*10): 50=5.0V (default), 33=3.3V")
    ap.add_argument("--slow", action="store_true",
                    help="use the host-stepped path instead of the on-MCU atomic bypass (diagnostic)")
    ap.add_argument("--chip", default="R5F10BAG", help="chip name shown in the packet trace")
    ap.add_argument("--no-trace", action="store_true", help="hide the PROG<->chip packet trace")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    if args.id:
        raw = bytes.fromhex(args.id.replace("0x", "").replace(",", " "))
        if len(raw) != 10:
            ap.error("--id must be exactly 10 bytes")
        ocd_id = raw
    else:
        ocd_id = DEFAULT_OCD_ID

    bridge = RL78Bridge(args.port, debug=args.debug)
    try:
        ver = bridge.version()
        log(f"[1] Bridge firmware v{ver[0]}.{ver[1]} on {args.port}")

        if args.power_cycle:
            log("    auto power-cycle (VTARGET off/on, held in reset)")
            bridge.auto_reset(off_ms=80, on_settle_ms=25)

        trace = not args.no_trace
        if args.sig:
            try:
                sig_check(bridge, chip=args.chip, trace=trace)
            except (ProtoError, BridgeError) as e:
                log(f"    [sig] failed: {e}")
            log("")

        if args.slow:
            _a, ocd = ocd_connect(bridge, chip=args.chip, trace=trace, debug=args.debug)
            result = f3_probe(ocd=ocd, ocd_id=ocd_id, corrupt_sum=args.corrupt_sum)
        else:
            result = run_atomic(bridge, chip=args.chip, ocd_id=ocd_id,
                                voltage=args.voltage, corrupt=args.corrupt_sum)

        log("")
        log("Done. Reached the OCD authentication stage (no glitch, no erase, no program).")
        return 0 if result in ("F3", "F2", "ALREADY") else 1
    except (ProtoError, BridgeError) as e:
        log(f"ERROR: {e}")
        log("Hint: re-run with --sig to isolate whether it's the physical layer or OCD.")
        return 2
    finally:
        bridge.reset_line(assert_low=False)   # leave /RESET released
        bridge.close()


if __name__ == "__main__":
    sys.exit(main())

"""
rl78bridge.py -- Host-side transport to the Pico TOOL0 bridge firmware.

Speaks the tiny binary control protocol implemented in firmware/tool0_bridge.c.
Knows nothing about RL78 protocol semantics; it just moves bytes with
deterministic on-wire timing (the Pico owns the timing via PIO).

Firmware control protocol (host -> Pico), little-endian:
    'V'                                           -> 'V' verMaj verMin
    'B' u32 baud                                  -> 'B' 'K'
    'R' u8 level (1=assert /RESET low, 0=release) -> 'R' 'K'
    'E' u8 mode_byte                              -> 'E' u8 n  n*init_bytes
    'X' u16 txlen tx[txlen] u16 rxlen u16 to_ms   -> 'X' u16 n  n*rx_bytes
    'F'                                           -> 'F' 'K'
"""

import struct
import time

import serial  # pyserial


class BridgeError(Exception):
    pass


class RL78Bridge:
    def __init__(self, port, control_baud=115200, debug=False):
        # The USB-CDC "baud" is irrelevant to USB; kept for pyserial's API.
        self.ser = serial.Serial(port, control_baud, timeout=2.0)
        self.debug = debug
        time.sleep(0.05)
        self.ser.reset_input_buffer()

    # ---- low-level framing to the firmware --------------------------------
    def _w(self, data: bytes):
        self.ser.write(data)
        self.ser.flush()

    def _r(self, n: int) -> bytes:
        buf = self.ser.read(n)
        if len(buf) != n:
            raise BridgeError(f"short read from bridge: wanted {n}, got {len(buf)}")
        return buf

    def _expect(self, b: bytes):
        got = self._r(len(b))
        if got != b:
            raise BridgeError(f"bridge: expected {b!r}, got {got!r}")

    # ---- commands ---------------------------------------------------------
    def version(self):
        self._w(b"V")
        self._expect(b"V")
        maj, minr = self._r(2)
        return (maj, minr)

    def set_ocd_profile(self, profile: str):
        """Firmware >= 1.15: select reference (0) or D1A (1) OCD timings."""
        profiles = {"reference": 0, "d1a": 1}
        if profile not in profiles:
            raise ValueError(f"Unknown OCD profile: {profile}")
        self._w(b"S" + bytes([profiles[profile]]))
        self._expect(b"SK")

    def set_baud(self, baud: int):
        self._w(b"B" + struct.pack("<I", baud))
        self._expect(b"BK")

    def reset_line(self, assert_low: bool):
        self._w(b"R" + bytes([1 if assert_low else 0]))
        self._expect(b"RK")

    def vtarget(self, on: bool):
        """Enable/disable target power via PicoGlitcher VTARGET_EN (GP22)."""
        self._w(b"P" + bytes([1 if on else 0]))
        self._expect(b"PK")

    def auto_reset(self, off_ms: int = 50, on_settle_ms: int = 20):
        """Cold power-cycle with /RESET held asserted, leaving the target in
        reset so the next enter() latches bootloader mode cleanly."""
        self._w(b"A" + struct.pack("<HH", off_ms, on_settle_ms))
        self._expect(b"AK")

    def ocd_bypass(self, voltage: int, corrupt: bool, ocd_id: bytes) -> dict:
        """Run the whole timing-critical OCD sequence ON the Pico (no USB gaps):
        reset -> 0xC5 -> Baud-Rate-Set -> 0x00/0x00/0x00 -> CONNECT 0x91 ->
        10-byte ID + checksum. Returns the key status bytes."""
        if len(ocd_id) != 10:
            raise BridgeError("ocd_id must be 10 bytes")
        self._w(b"O" + bytes([voltage & 0xFF, 1 if corrupt else 0]) + bytes(ocd_id))
        self._expect(b"O")
        st1, ping1, ping2, connect, idst = self._r(5)
        return {"st1": st1, "ping1": ping1, "ping2": ping2,
                "connect": connect, "idst": idst}

    def glitched_ocd(self, voltage: int, corrupt: bool, ocd_id: bytes,
                     delay_ns: int, width_ns: int, mosfet: str = "lp") -> dict:
        """Like ocd_bypass(), but fire a crowbar pulse (width_ns) delay_ns after
        the ID+checksum is sent -- i.e. during the chip's ID compare before F3.
        Self-triggered on the Pico, no UART trigger. Returns the status bytes."""
        if len(ocd_id) != 10:
            raise BridgeError("ocd_id must be 10 bytes")
        mf = 1 if mosfet.lower() == "hp" else 0
        self._w(b"G" + bytes([voltage & 0xFF, 1 if corrupt else 0]) + bytes(ocd_id)
                + struct.pack("<II", delay_ns, width_ns) + bytes([mf]))
        self._expect(b"G")
        st1, ping1, ping2, connect, idst = self._r(5)
        return {"st1": st1, "ping1": ping1, "ping2": ping2,
                "connect": connect, "idst": idst}

    def fast_glitched_ocd(self, voltage: int, corrupt: bool, ocd_id: bytes,
                          delay_ns: int, width_ns: int, mosfet: str = "lp") -> dict:
        """Like glitched_ocd() but uses 'Q' (skip identify phase, ~2x faster)."""
        if len(ocd_id) != 10:
            raise BridgeError("ocd_id must be 10 bytes")
        mf = 1 if mosfet.lower() == "hp" else 0
        self._w(b"Q" + bytes([voltage & 0xFF, 1 if corrupt else 0]) + bytes(ocd_id)
                + struct.pack("<II", delay_ns, width_ns) + bytes([mf]))
        self._expect(b"Q")
        st1, ping1, ping2, connect, idst = self._r(5)
        return {"st1": st1, "ping1": ping1, "ping2": ping2,
                "connect": connect, "idst": idst}

    def protect_glitched_ocd(self, voltage: int, corrupt: bool, ocd_id: bytes,
                             delay_ns: int, width_ns: int, mosfet: str = "lp") -> dict:
        """Glitch during Baud-Rate-Set to bypass ProtectError (0x10).
        delay_ns = ns from end of baud frame echo (chip deciding ACK vs ProtectError).
        Returns extra field 'baud_resp_ns': time from echo end to chip response."""
        if len(ocd_id) != 10:
            raise BridgeError("ocd_id must be 10 bytes")
        mf = 1 if mosfet.lower() == "hp" else 0
        self._w(b"H" + bytes([voltage & 0xFF, 1 if corrupt else 0]) + bytes(ocd_id)
                + struct.pack("<II", delay_ns, width_ns) + bytes([mf]))
        self._expect(b"H")
        st1, ping1, ping2, connect, idst = self._r(5)
        baud_resp_ns = struct.unpack("<I", self._r(4))[0]
        return {"st1": st1, "ping1": ping1, "ping2": ping2,
                "connect": connect, "idst": idst, "baud_resp_ns": baud_resp_ns}

    def test_glitch(self, width_ns: int, mosfet: str = "lp",
                    count: int = 1, interval_us: int = 0) -> int:
        """Fire bare crowbar pulse(s) without OCD — for scope testing."""
        mf = 1 if mosfet.lower() == "hp" else 0
        self._w(b"T" + struct.pack("<I", width_ns) + bytes([mf])
                + struct.pack("<HH", count, interval_us))
        self._expect(b"T")
        fired = struct.unpack("<H", self._r(2))[0]
        return fired

    def flush(self):
        self._w(b"F")
        self._expect(b"FK")

    def enter(self, mode_byte: int, followup: bytes = b"") -> bytes:
        """Run the reset-entry waveform, then transmit `mode_byte` and `followup`
        BACK-TO-BACK with no USB gap (RL78/F13 OCD needs the Baud-Rate-Set right
        after 0xC5). Returns ~40 ms of captured bytes: echo(mode+followup) +
        chip response + any trailing bytes."""
        self._w(b"E" + bytes([mode_byte]) + struct.pack("<H", len(followup)) + followup)
        self._expect(b"E")
        n = self._r(1)[0]
        cap = self._r(n) if n else b""
        if self.debug:
            print(f"[enter] mode=0x{mode_byte:02x} fu={followup.hex(' ')} cap={cap.hex(' ')}")
        return cap

    def xfer(self, tx: bytes, rxlen: int, timeout_ms: int = 200) -> bytes:
        """Atomic: transmit `tx`, then collect up to `rxlen` bytes (including the
        single-wire echo of `tx`).  All on-wire timing is done by the Pico."""
        if len(tx) > 1024 or rxlen > 1024:
            raise BridgeError("xfer limited to 1024 bytes per direction")
        hdr = b"X" + struct.pack("<H", len(tx)) + tx + struct.pack("<HH", rxlen, timeout_ms)
        self._w(hdr)
        self._expect(b"X")
        n = struct.unpack("<H", self._r(2))[0]
        rx = self._r(n) if n else b""
        if self.debug:
            print(f"[xfer] tx={tx.hex(' ')} rx={rx.hex(' ')}")
        return rx

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass

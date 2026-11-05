"""
rl78_proto.py -- RL78 Protocol A (serial programming) + OCD debug-monitor layer.

Every Protocol A state is backed by Renesas R01AN0815 (RL78 Protocol A Serial
Programming Guide).  The OCD debug-monitor layer follows the de-facto reference
fail0verflow/rl78-debug (Renesas does not publish the E1/E2 OCD byte protocol).

Spec map (state -> source):
  Frame format / checksum ........ R01AN0815 Fig 2-1/2-2, Table 2-1
  Status codes (06 ACK / 15 NACK). R01AN0815 Table 1-4
  Baud-Rate-Set (0x9A), voltage=21. R01AN0815 (2.1 V -> 21 -> 15H)
  Silicon Signature (0xC0) ....... R01AN0815 3.7 (DEC/DEV/CEN/DEN/VER)
  Mode byte 0x3A (1-wire prog) ... R20AN6332 Table 5 / R01AN5756
  Mode byte 0xC5 (OCD) ........... fail0verflow rl78-debug MODE_OCD
  OCD cmds / F0..F4 unlock codes .. fail0verflow rl78-debug ProtoOCD
"""

# ---- Mode bytes (sent as the single reset-entry mode byte) -----------------
MODE_A_1WIRE = 0x3A      # single-line UART flash programming  (R20AN6332 Table 5)
MODE_A_2WIRE = 0x00      # dedicated 2-wire UART flash programming
MODE_OCD     = 0xC5      # on-chip debug monitor               (f0f MODE_OCD)

# ---- Protocol A framing (R01AN0815 Table 2-1) ------------------------------
SOH = 0x01   # command-frame header
STX = 0x02   # data/status-frame header
ETX = 0x03   # last-frame footer
ETB = 0x17   # non-last data-frame footer

# ---- Protocol A commands ---------------------------------------------------
COM_RESET             = 0x00
COM_VERIFY            = 0x13
COM_BLOCK_ERASE       = 0x22
COM_BLOCK_BLANK_CHECK = 0x32
COM_PROGRAMMING       = 0x40
COM_BAUDRATE_SET      = 0x9A
COM_SEC_SET           = 0xA0
COM_SEC_GET           = 0xA1
COM_SEC_RELEASE       = 0xA2
COM_SILICON_SIG       = 0xC0

# ---- Protocol A status codes (R01AN0815 Table 1-4) -------------------------
ST_COM_NUM_ERR = 0x04
ST_PARAM_ERR   = 0x05
ST_ACK         = 0x06
ST_SUM_ERR     = 0x07
ST_VERIFY_ERR  = 0x0F
ST_PROTECT_ERR = 0x10
ST_NACK        = 0x15
ST_ERASE_ERR   = 0x1A
ST_BLANK_ERR   = 0x1B
ST_WRITE_ERR   = 0x1C

ST_NAMES = {
    0x04: "COMMAND-NUMBER-ERROR", 0x05: "PARAMETER-ERROR", 0x06: "ACK",
    0x07: "CHECKSUM-ERROR", 0x0F: "VERIFY-ERROR", 0x10: "PROTECT-ERROR",
    0x15: "NACK", 0x1A: "ERASE-ERROR", 0x1B: "BLANK-ERROR", 0x1C: "WRITE-ERROR",
}

# ---- Baud-rate codes used by the Baud-Rate-Set command ---------------------
BR_CODE = {115200: 0, 250000: 1, 500000: 2, 1000000: 3}
VOLTAGE_21V = 21          # 2.1 V -> 21 -> 0x15 (R01AN0815)

# ---- OCD debug-monitor protocol (f0f rl78-debug) ---------------------------
# kirya-dev/PicoRL78 constants (verified on RL78/F13)
OCD_SYNC        = 0x00
OCD_CMD_CONNECT = 0x91     # "connect" / unlock begin
OCD_CMD_READ    = 0x92
OCD_CMD_WRITE   = 0x93
OCD_CMD_EXEC    = 0x94

ST_UNLOCK_ALREADY = 0xF0   # OCD_STS_UNLOCKED  : already unlocked
ST_UNLOCK_LOCKED  = 0xF1   # OCD_STS_LOCKED    : locked -> send 10-byte ID + checksum
ST_UNLOCK_OK      = 0xF2   # OCD_STS_UNLOCK_OK : ID accepted (fully unlocked)
ST_UNLOCK_ERR     = 0xF3   # OCD_STS_UNLOCK_ERR: ID authentication failed (expected NACK)
ST_UNLOCK_NG      = 0xF4   # OCD_STS_UNLOCK_NG
OCD_UNLOCK_NAMES = {
    0xF0: "UNLOCKED (F0)", 0xF1: "LOCKED (F1)", 0xF2: "UNLOCK-OK (F2)",
    0xF3: "UNLOCK-ERR / auth-fail (F3)", 0xF4: "UNLOCK-NG (F4)",
}


class ProtoError(Exception):
    pass


# ============================================================================
#  Link: byte transport on top of the Pico bridge, with single-wire echo strip
# ============================================================================
class Link:
    def __init__(self, bridge, chip="R5F10BAG", trace=True, default_timeout_ms=150):
        self.b = bridge
        self.chip = chip
        self.trace = trace
        self.to = default_timeout_ms

    def _log(self, direction: str, data: bytes, label: str):
        if not self.trace or not data:
            return
        tag = f"  ({label})" if label else ""
        print(f"    {direction} : {data.hex(' ')}{tag}", flush=True)

    def txrx(self, tx: bytes, nresp: int, timeout_ms=None, label="") -> bytes:
        """Send `tx`, return up to `nresp` response bytes (echo of tx removed).
        Shows both directions: PROG>chip (sent) and chip>PROG (received)."""
        to = self.to if timeout_ms is None else timeout_ms
        rx = self.b.xfer(tx, len(tx) + nresp, to)
        resp = rx[len(tx):]
        self._log(f"PROG>{self.chip}", tx, label)
        self._log(f"{self.chip}>PROG", resp, label)
        return resp

    def send(self, tx: bytes, label="") -> None:
        """Transmit a frame and consume only its single-wire echo (len(tx))."""
        self.b.xfer(tx, len(tx), self.to)
        self._log(f"PROG>{self.chip}", tx, label)

    def read(self, n: int, timeout_ms=None, label="", log=True) -> bytes:
        """Pure read of n bytes (txlen==0 -> firmware does NOT flush, so bytes
        that already arrived, e.g. a trailing SYNC, are preserved)."""
        to = self.to if timeout_ms is None else timeout_ms
        resp = self.b.xfer(b"", n, to)
        if log:
            self._log(f"{self.chip}>PROG", resp, label)
        return resp

    # back-compat alias used by the OCD passive reader
    def recv(self, nresp: int, timeout_ms=None, label="") -> bytes:
        return self.read(nresp, timeout_ms=timeout_ms, label=label)


# ============================================================================
#  Protocol A  (R01AN0815)
# ============================================================================
def _csum(data: bytes) -> int:
    # SUM = 00h - (sum of all target bytes), borrow ignored, lower 8 bits.
    return (-sum(data)) & 0xFF


def build_command(com: int, info: bytes = b"") -> bytes:
    payload = bytes([com]) + info
    ln = len(payload) & 0xFF                 # 00h => 256
    sm = _csum(bytes([ln]) + payload)        # LEN + COM + info
    return bytes([SOH, ln]) + payload + bytes([sm, ETX])


def build_data_frame(data: bytes, last: bool = True) -> bytes:
    ln = len(data) & 0xFF                    # 00h => 256
    sm = _csum(bytes([ln]) + data)
    footer = ETX if last else ETB
    return bytes([STX, ln]) + data + bytes([sm, footer])


def _addr_info(sa: int, ea: int) -> bytes:
    return sa.to_bytes(3, 'little') + ea.to_bytes(3, 'little')


def parse_frame(buf: bytes):
    """Parse one data/status frame (STX LEN data SUM ETX|ETB). Returns (data,last)."""
    if len(buf) < 4:
        raise ProtoError(f"status frame too short: {buf.hex(' ')!r}")
    if buf[0] != STX:
        raise ProtoError(f"expected STX(02), got frame {buf.hex(' ')!r}")
    ln = buf[1]
    n = 256 if ln == 0 else ln
    if len(buf) < 2 + n + 2:
        raise ProtoError(f"truncated frame ({len(buf)} bytes): {buf.hex(' ')!r}")
    data = buf[2:2 + n]
    sm = buf[2 + n]
    tr = buf[3 + n]
    if sm != _csum(bytes([ln]) + data):
        raise ProtoError(f"frame checksum error: {buf.hex(' ')!r}")
    if tr not in (ETX, ETB):
        raise ProtoError(f"bad frame footer 0x{tr:02x}: {buf.hex(' ')!r}")
    return data, (tr == ETX)


class ProtoA:
    def __init__(self, link: Link):
        self.link = link

    def _read_frame(self, timeout_ms=200, label="") -> bytes:
        """Read exactly one STX/LEN/.../SUM/ETX frame, sized from its LEN byte, so
        trailing bytes the monitor emits next (e.g. an OCD SYNC) stay buffered."""
        hdr = self.link.read(2, timeout_ms=timeout_ms, log=False)
        if len(hdr) < 2:
            raise ProtoError(f"no frame header (got {hdr.hex(' ')!r})")
        if hdr[0] != STX:
            raise ProtoError(f"expected STX(02), got {hdr.hex(' ')!r}")
        n = 256 if hdr[1] == 0 else hdr[1]
        body = self.link.read(n + 2, timeout_ms=timeout_ms, log=False)
        frame = hdr + body
        self.link._log(f"{self.link.chip}>PROG", frame, label)
        data, _ = parse_frame(frame)
        return data

    def command_status(self, com: int, info: bytes = b"", timeout_ms=200, label="") -> int:
        """Send a command and return the status byte from its reply frame."""
        self.link.send(build_command(com, info), label=label)
        return self._read_frame(timeout_ms=timeout_ms, label=label)[0]

    def reset(self) -> int:
        return self.command_status(COM_RESET, label="Reset")

    def set_baudrate(self, baud: int, voltage: int = VOLTAGE_21V) -> int:
        if baud not in BR_CODE:
            raise ProtoError(f"unsupported baud {baud}")
        return self.command_status(COM_BAUDRATE_SET, bytes([BR_CODE[baud], voltage]),
                                   label="Baud-Rate-Set")

    def silicon_signature(self, timeout_ms=300):
        """Returns (status, signature_bytes). Non-destructive (no erase)."""
        self.link.send(build_command(COM_SILICON_SIG), label="Silicon-Signature")
        st = self._read_frame(timeout_ms=timeout_ms, label="status")[0]
        sig = b""
        try:
            sig = self._read_frame(timeout_ms=timeout_ms, label="signature")
        except ProtoError:
            pass
        return st, sig

    def security_get(self, timeout_ms=500):
        """Returns (status, 8-byte security flags)."""
        self.link.send(build_command(COM_SEC_GET), label="Security-Get")
        st = self._read_frame(timeout_ms=timeout_ms, label="status")[0]
        sec = b""
        if st == ST_ACK:
            try:
                sec = self._read_frame(timeout_ms=timeout_ms, label="security")
            except ProtoError:
                pass
        return st, sec

    def block_erase(self, sa: int, ea: int, timeout_ms=10000) -> int:
        return self.command_status(COM_BLOCK_ERASE, _addr_info(sa, ea),
                                   timeout_ms=timeout_ms, label="Block-Erase")

    def block_blank_check(self, sa: int, ea: int, timeout_ms=2000) -> int:
        return self.command_status(COM_BLOCK_BLANK_CHECK, _addr_info(sa, ea),
                                   timeout_ms=timeout_ms, label="Block-Blank-Check")

    def programming(self, sa: int, ea: int, data: bytes, timeout_ms=5000) -> int:
        """Write `data` to flash range [sa..ea]. Data is sent in 256-byte frames."""
        total = ea - sa + 1
        if len(data) < total:
            data = data + b'\xFF' * (total - len(data))
        self.link.send(build_command(COM_PROGRAMMING, _addr_info(sa, ea)),
                       label="Programming")
        st = self._read_frame(timeout_ms=timeout_ms, label="status")[0]
        if st != ST_ACK:
            return st
        for off in range(0, total, 256):
            chunk = data[off:off + 256]
            if len(chunk) < 256:
                chunk = chunk + b'\xFF' * (256 - len(chunk))
            last = (off + 256 >= total)
            frame = build_data_frame(chunk, last=last)
            self.link.send(frame, label=f"data @0x{sa + off:06x}")
            st = self._read_frame(timeout_ms=timeout_ms, label="data-ack")[0]
            if st != ST_ACK:
                return st
        return ST_ACK

    def verify(self, sa: int, ea: int, data: bytes, timeout_ms=5000) -> int:
        """Compare `data` against flash range [sa..ea]."""
        total = ea - sa + 1
        if len(data) < total:
            data = data + b'\xFF' * (total - len(data))
        self.link.send(build_command(COM_VERIFY, _addr_info(sa, ea)),
                       label="Verify")
        st = self._read_frame(timeout_ms=timeout_ms, label="status")[0]
        if st != ST_ACK:
            return st
        for off in range(0, total, 256):
            chunk = data[off:off + 256]
            if len(chunk) < 256:
                chunk = chunk + b'\xFF' * (256 - len(chunk))
            last = (off + 256 >= total)
            frame = build_data_frame(chunk, last=last)
            self.link.send(frame, label=f"verify @0x{sa + off:06x}")
            st = self._read_frame(timeout_ms=timeout_ms, label="verify-ack")[0]
            if st != ST_ACK:
                return st
        return ST_ACK

    def security_release(self, timeout_ms=30000) -> int:
        """Full chip erase + security flag reset (nuclear option)."""
        return self.command_status(COM_SEC_RELEASE, timeout_ms=timeout_ms,
                                   label="Security-Release")


# ============================================================================
#  OCD debug monitor  (kirya-dev/PicoRL78 -- verified on RL78/F13 R5F10AGG)
# ============================================================================
class ProtoOCD:
    """RL78/F13 OCD entry exactly as kirya-dev/PicoRL78 does it (minus glitch):
       after Baud-Rate-Set ACK the monitor does a 0x00 ping/pong, then CONNECT
       (0x91) returns LOCKED(F1)/UNLOCKED(F0), then a 10-byte ID + checksum
       returns F2(OK)/F3(auth-fail = the expected clean marker)/F4."""

    def __init__(self, link: Link):
        self.link = link

    def sync_pong(self, timeout_ms=400):
        """kirya 0x00 handshake tail: send 0x00 (pong), read the 0x00 (ping)."""
        self.link.send(b"\x00", label="OCD 0x00 pong")        # echo consumed
        return self.link.read(1, timeout_ms=timeout_ms, label="OCD 0x00 ping")

    def connect(self, timeout_ms=400) -> int:
        """Send OCD CONNECT (0x91); returns F0 (unlocked) or F1 (locked)."""
        resp = self.link.txrx(bytes([OCD_CMD_CONNECT]), nresp=1,
                              timeout_ms=timeout_ms, label="OCD CONNECT (0x91)")
        if not resp:
            raise ProtoError("no response to OCD CONNECT (0x91)")
        return resp[0]

    @staticmethod
    def ocd_checksum(ocd_id) -> int:
        # kirya: ~((0x100 - sum) & 0xFF) == (sum - 1) & 0xFF
        return (sum(ocd_id) - 1) & 0xFF

    def send_id(self, ocd_id, corrupt_sum=False, timeout_ms=400) -> int:
        """Send 10 ID bytes, then the checksum byte (two writes, as kirya does);
        returns the status (F2 ok / F3 auth-fail / F4)."""
        if len(ocd_id) != 10:
            raise ProtoError("OCD ID must be exactly 10 bytes")
        csum = self.ocd_checksum(ocd_id)
        if corrupt_sum:
            csum = (csum + 1) & 0xFF
        self.link.send(bytes(ocd_id), label="OCD ID (10 bytes)")
        lbl = "OCD checksum(bad)" if corrupt_sum else "OCD checksum"
        resp = self.link.txrx(bytes([csum]), nresp=1, timeout_ms=timeout_ms, label=lbl)
        if not resp:
            raise ProtoError("no response to OCD ID checksum")
        return resp[0]

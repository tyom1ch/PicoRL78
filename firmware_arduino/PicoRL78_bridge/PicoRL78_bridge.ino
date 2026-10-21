/* ===========================================================================
 * PicoRL78_bridge.ino -- RL78 TOOL0 UART bridge (Arduino).
 *
 * Board core: "Raspberry Pi Pico/RP2040" by Earle F. Philhower, III
 *             (arduino-pico). Board: Raspberry Pi Pico.
 *
 * Generic bridge commands plus an on-device OCD handshake ('O'). UART bits
 * are hardware generated. 'O' follows CAP_CODE_STRIP.sr / dataflash.sr;
 * its deadlines use the hardware timer and are independent of USB latency.
 *
 * Board: PicoGlitcher v3.0 (Raspberry Pi Pico 2 / RP2350). In Arduino IDE pick
 *        board "Raspberry Pi Pico 2" (use "Raspberry Pi Pico" if yours is RP2040).
 *
 * PicoGlitcher v3.0 fixed pin map used here:
 *   GP16 UART0 TX  -> diode (cathode to GP16) -> TOOL0  (drives line low only)
 *   GP17 UART0 RX  -> TOOL0                              (reads line; sees echo)
 *                     (GP16-19 are bidirectional, NO level shifter -- direct)
 *   GP2  RESET     -> level shifter -> RL78 /RESET  (push-pull: LOW=assert,
 *                     HIGH=release -- the board's shifter drives the line)
 *   GP22 VTARGET_EN-> target power enable (used for auto power-cycle reset)
 *   GND  common
 * TOOL0 needs a pull-up (target side; GP17 internal pull-up also enabled).
 *
 * Control plane: USB Serial, same binary protocol as the C-SDK firmware, so the
 * host scripts (host/*.py) work unchanged:
 *   'V'                                    -> 'V' verMaj verMin
 *   'B' u32 baud                           -> 'B' 'K'
 *   'R' u8 lvl (1=/RESET low,0=release)    -> 'R' 'K'
 *   'E' u8 mode                            -> 'E' u8 n  n*init_echo
 *   'X' u16 txlen tx u16 rxlen u16 to_ms   -> 'X' u16 n  n*rx (echo included)
 *   'F'                                    -> 'F' 'K'
 *   'P' u8 (1=VTARGET on,0=off)            -> 'P' 'K'
 *   'A' u16 off_ms u16 on_settle_ms        -> 'A' 'K'  (auto power-cycle reset)
 *
 * Timing/framing for 'O': analysis/reference-timing.md (measured 8N1).
 * ===========================================================================*/

#include <Arduino.h>
#include <hardware/gpio.h>   // gpio_pull_up (sets pad pull-up without re-muxing)
#include <hardware/uart.h>
#include <hardware/sync.h>
#include <pico/time.h>

// ---- PicoGlitcher v3.0 fixed pin map ----
#define PIN_TOOL0_TX  16   // UART0 TX -> diode -> TOOL0
#define PIN_TOOL0_RX  17   // UART0 RX <- TOOL0
#define PIN_RESET      2   // RESET via level shifter (push-pull)
#define PIN_VTARGET   22   // VTARGET_EN: target power enable
// Crowbar glitch stage (PicoGlitcher v3.0)
#define PIN_GLITCH_EN  3   // glitch-stage enable
#define PIN_GLITCH_LP 13   // low-power crowbar MOSFET gate
#define PIN_GLITCH_HP 12   // high-power crowbar MOSFET gate
static uint8_t glitchPin = PIN_GLITCH_LP;   // selected crowbar output
// Glitch arming for 'G'/'Q' commands. Fired DURING the checksum byte transmission:
// delay = ns from checksum byte start on wire to crowbar pulse.
static bool     gArmed   = false;
static uint32_t gDelayNs = 0;
static uint32_t gWidthNs = 0;

#define FW_VER_MAJOR 1
#define FW_VER_MINOR 14  // 1.14: + 'H' ProtectError glitch (baud-rate-set bypass)

// Reset/entry window (ms). f0f enter_rom uses 40/1/10; we use 2 ms for tHD to
// sit above the 1 ms minimum, well under the 100 ms tSUINIT ceiling.
#define T_RESET_LOW_MS 40
#define T_HD_MS         2
#define T_TOOL0_HI_MS  10

static uint32_t curBaud = 115200;

// ---- USB helpers -----------------------------------------------------------
static uint8_t rdU8() {
  int c;
  while ((c = Serial.read()) < 0) { /* spin */ }
  return (uint8_t)c;
}
static uint16_t rdU16() { uint8_t lo = rdU8(), hi = rdU8(); return lo | (hi << 8); }
static uint32_t rdU32() {
  uint32_t v = rdU8();
  v |= (uint32_t)rdU8() << 8;
  v |= (uint32_t)rdU8() << 16;
  v |= (uint32_t)rdU8() << 24;
  return v;
}
static void wrU8(uint8_t b)   { Serial.write(b); }
static void wrU16(uint16_t v) { Serial.write(v & 0xff); Serial.write((v >> 8) & 0xff); }

// ---- UART (re)configuration ------------------------------------------------
static void uartBegin(uint32_t baud) {
  curBaud = baud;
  Serial1.end();
  Serial1.setTX(PIN_TOOL0_TX);
  Serial1.setRX(PIN_TOOL0_RX);
  Serial1.begin(baud, SERIAL_8N1);   // reference: 10 bits/byte, ~87.125 us
  // Add a pad pull-up on the RX pin WITHOUT changing its UART function mux.
  // (pinMode(..., INPUT_PULLUP) here would detach GP17 from UART0 -> no RX.)
  gpio_pull_up(PIN_TOOL0_RX);
}
static void uartFlushRx() { while (Serial1.available()) Serial1.read(); }

// ---- RESET line (push-pull through the board level shifter) -----------------
static void resetAssert()  { pinMode(PIN_RESET, OUTPUT); digitalWrite(PIN_RESET, LOW);  }
static void resetRelease() { pinMode(PIN_RESET, OUTPUT); digitalWrite(PIN_RESET, HIGH); }

// ---- Target power (VTARGET_EN, GP22) ---------------------------------------
static void vtargetOn()  { pinMode(PIN_VTARGET, OUTPUT); digitalWrite(PIN_VTARGET, HIGH); }
static void vtargetOff() { pinMode(PIN_VTARGET, OUTPUT); digitalWrite(PIN_VTARGET, LOW);  }

// ---- Crowbar glitch -------------------------------------------------------
static void glitchInit() {
  pinMode(PIN_GLITCH_EN, OUTPUT); digitalWrite(PIN_GLITCH_EN, LOW);
  pinMode(PIN_GLITCH_LP, OUTPUT); digitalWrite(PIN_GLITCH_LP, LOW);
  pinMode(PIN_GLITCH_HP, OUTPUT); digitalWrite(PIN_GLITCH_HP, LOW);
}
// Cycle-accurate ns delay (call with interrupts disabled for precision).
static inline void waitNs(uint32_t ns) {
  if (!ns) return;
  uint64_t cyc = (uint64_t)ns * clock_get_hz(clk_sys) / 1000000000ull;
  if (!cyc) cyc = 1;
  uint32_t start = rp2040.getCycleCount();
  while ((uint32_t)(rp2040.getCycleCount() - start) < (uint32_t)cyc) tight_loop_contents();
}
// Fire one crowbar pulse of width_ns on the selected MOSFET (REGC short).
static inline void glitchPulseNs(uint32_t width_ns) {
  gpio_put(PIN_GLITCH_EN, 1);
  gpio_put(glitchPin, 1);
  waitNs(width_ns);
  gpio_put(glitchPin, 0);
  gpio_put(PIN_GLITCH_EN, 0);
}

// ---- Auto power-cycle reset: /RESET low, power off, settle, power on, hold --
// Brings the target to a clean cold-start with /RESET asserted, so the next
// 'E' entry latches the bootloader mode reliably.
static void autoReset(uint16_t offMs, uint16_t onSettleMs) {
  resetAssert();              // hold target in reset while power toggles
  vtargetOff();
  delay(offMs ? offMs : 50);
  vtargetOn();
  delay(onSettleMs ? onSettleMs : 20);   // let VDD/POR settle, still in reset
  // leave /RESET asserted; doEnter() releases it with correct tSU/tHD timing
}

// ---- Entry sequence (timed on-chip): mode byte + immediate follow-up -------
// The reset/TOOL0 waveform runs here, then the mode byte and the host-supplied
// follow-up frame (e.g. Baud-Rate-Set) are transmitted BACK-TO-BACK with no USB
// gap -- RL78/F13 OCD entry needs the baud command right after 0xC5 (kirya).
// Then RX is captured for ~40 ms and returned (echo + chip response + any ping).
static uint8_t fbuf[64];
static void doEnter(uint8_t modeByte, const uint8_t *followup, uint16_t flen) {
  Serial1.end();
  pinMode(PIN_TOOL0_TX, OUTPUT);

  digitalWrite(PIN_TOOL0_TX, LOW);   // TOOL0 low
  resetAssert();                     // /RESET low
  delay(T_RESET_LOW_MS);

  resetRelease();                    // /RESET released; TOOL0 still low (tHD)
  delay(T_HD_MS);

  digitalWrite(PIN_TOOL0_TX, HIGH);  // TOOL0 high
  delay(T_TOOL0_HI_MS);

  uartBegin(curBaud);
  uartFlushRx();

  // mode byte + follow-up, no gap
  Serial1.write(modeByte);
  if (flen) Serial1.write(followup, flen);

  // Capture everything on the wire for ~40 ms (echo + response + any ping).
  static uint8_t cbuf[96];
  uint8_t n = 0;
  unsigned long deadline = millis() + 40;
  while (n < sizeof(cbuf) && (long)(deadline - millis()) > 0) {
    if (Serial1.available()) { cbuf[n++] = (uint8_t)Serial1.read(); deadline = millis() + 5; }
  }
  wrU8('E');
  wrU8(n);
  for (uint8_t i = 0; i < n; i++) wrU8(cbuf[i]);
}

// ---- Atomic transfer -------------------------------------------------------
static uint8_t txbuf[1024];
static uint8_t rxbuf[1024];

static void doXfer() {
  uint16_t txlen = rdU16();
  if (txlen > sizeof(txbuf)) txlen = sizeof(txbuf);
  for (uint16_t i = 0; i < txlen; i++) txbuf[i] = rdU8();
  uint16_t rxlen = rdU16();
  uint16_t toMs  = rdU16();
  if (rxlen > sizeof(rxbuf)) rxlen = sizeof(rxbuf);

  // Flush stale echo ONLY when starting a new command (txlen>0). Pure reads
  // (txlen==0, e.g. OCD wait_ack) must keep bytes that already arrived, such as
  // a SYNC(0x00) the monitor emitted right after the previous response.
  if (txlen > 0) uartFlushRx();

  uint16_t ti = 0, ri = 0;
  unsigned long last = millis();
  while (ri < rxlen) {
    if (ti < txlen && Serial1.availableForWrite() > 0) {
      Serial1.write(txbuf[ti++]);           // non-blocking feed
    }
    if (Serial1.available()) {
      rxbuf[ri++] = (uint8_t)Serial1.read(); // echo + response
      last = millis();
    } else if (ti >= txlen && (millis() - last) > toMs) {
      break;
    }
  }

  wrU8('X');
  wrU16(ri);
  for (uint16_t i = 0; i < ri; i++) wrU8(rxbuf[i]);
}

// ===========================================================================
// Capture-derived OCD entry. CAP_CODE_STRIP is the timing template; dataflash
// independently confirms the sequence. All delays below are microseconds.
// Raw UART polling timestamps each received byte (near its stop-bit sample).
// Interrupts are masked during 'O' only; the USB reply is sent after restoring
// them. Each read is bounded, and any missing/bad echo or response aborts.
// ===========================================================================
static const uint32_t REF_BAUD = 114800; // measured ~8.71 us/bit; protocol baud code 0
static const uint32_t REF_RESET_LOW_US = 100134;
static const uint32_t REF_TOOL0_HOLD_US = 10017;
static const uint32_t REF_TOOL0_HIGH_US = 2748;
static uint32_t lastRxUs;

static void waitUntilUs(uint32_t deadline) {
  while ((int32_t)(time_us_32() - deadline) < 0) tight_loop_contents();
}
static void afterRxUs(uint32_t interval) { waitUntilUs(lastRxUs + interval); }

static int readWire(uint32_t timeoutUs = 20000) {
  uint32_t deadline = time_us_32() + timeoutUs;
  do {
    if (uart_is_readable(uart0)) {
      uint32_t raw = uart_get_hw(uart0)->dr;
      lastRxUs = time_us_32();
      if (raw & 0xF00) return -2; // framing/parity/break/overrun
      return raw & 0xFF;
    }
  } while ((int32_t)(time_us_32() - deadline) < 0);
  return -1;
}
static void clearWire() {
  while (uart_is_readable(uart0)) (void)uart_get_hw(uart0)->dr;
  uart_get_hw(uart0)->rsr = 0;
}
static bool readEcho(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; ++i) if (readWire() != data[i]) return false;
  return true;
}
static bool sendWire(const uint8_t *data, size_t len) {
  // All calls have <=11 bytes, below the hardware FIFO capacity. Read echo
  // immediately so a following target reply remains queued for its reader.
  uart_write_blocking(uart0, data, len);
  return readEcho(data, len);
}
static bool sendByte(uint8_t data) { return sendWire(&data, 1); }

static uint8_t cksum(const uint8_t *d, int len) {   // 0x100 - sum (kirya cmd_checksum)
  int s = 0; while (len--) s += d[len]; return (uint8_t)(0x100 - s);
}

// Keep UART configured while overriding TX low. Reinitializing it after TOOL0
// rises would add an unmeasured delay. RESET is already an output from setup().
static void referenceEntry() {
  uart_tx_wait_blocking(uart0);
  gpio_put(PIN_RESET, 0);
  uint32_t asserted = time_us_32();
  gpio_set_outover(PIN_TOOL0_TX, GPIO_OVERRIDE_LOW);
  waitUntilUs(asserted + REF_RESET_LOW_US);
  gpio_put(PIN_RESET, 1);
  uint32_t released = time_us_32();
  waitUntilUs(released + REF_TOOL0_HOLD_US);
  gpio_set_outover(PIN_TOOL0_TX, GPIO_OVERRIDE_NORMAL);
  uint32_t toolHigh = time_us_32();
  clearWire(); // break generated by our own TOOL0-low interval
  waitUntilUs(toolHigh + REF_TOOL0_HIGH_US);
}

// Validate an entire Protocol-A response, leaving any following frame/ping
// untouched. Timestamp of its last byte is retained for the next deadline.
static bool readFrame(uint8_t expectedLen, int expectedFirst, uint8_t *first) {
  int stx = readWire();
  if (stx != 0x02 || readWire() != expectedLen) return false;
  uint8_t sum = expectedLen;
  for (uint8_t i = 0; i < expectedLen; ++i) {
    int value = readWire();
    if (value < 0) return false;
    if (i == 0) *first = (uint8_t)value;
    sum += (uint8_t)value;
  }
  int check = readWire();
  if (check < 0 || (uint8_t)(sum + check) != 0 || readWire() != 0x03) return false;
  return expectedFirst < 0 || *first == expectedFirst;
}

// Like readFrame but accepts ANY LEN from the wire (needed for OCD baud response:
// ACK has LEN=3, ProtectError has LEN=1).
static bool readFrameAny(uint8_t *first) {
  int stx = readWire();
  if (stx != 0x02) return false;
  int len = readWire();
  if (len <= 0 || len > 64) return false;
  uint8_t sum = (uint8_t)len;
  for (uint8_t i = 0; i < (uint8_t)len; ++i) {
    int value = readWire();
    if (value < 0) return false;
    if (i == 0) *first = (uint8_t)value;
    sum += (uint8_t)value;
  }
  int check = readWire();
  if (check < 0 || (uint8_t)(sum + check) != 0 || readWire() != 0x03) return false;
  return true;
}

static bool sendModeBaud(uint8_t mode, const uint8_t *baud, uint32_t startGapUs) {
  uint32_t modeStart = time_us_32();
  if (!sendByte(mode)) return false;
  // Gap is START-to-START in the capture, not a delay after the mode stop bit.
  waitUntilUs(modeStart + startGapUs);
  return sendWire(baud, 7);
}

// send a 1-byte-command Protocol-A frame: 01 01 COM SUM 03
static bool sendCmdA(uint8_t com) {
  uint8_t f[5] = {0x01, 0x01, com, 0x00, 0x03};
  f[3] = cksum(&f[1], 2);
  return sendWire(f, 5);
}

// Fills out[5] = {st1, ping1, ping2, connect, idst}. Plain uint8_t* avoids the
// Arduino auto-prototype ordering problem that a struct parameter would cause.
static void doOcd(uint8_t voltage, uint8_t corrupt, const uint8_t id[10], uint8_t *out) {
  uint8_t st1=0xEE, ping1=0xEE, ping2=0xEE, connect=0xEE, idst=0xEE; // 0xEE=not reached

  uint8_t baud[7] = {0x01, 0x03, 0x9A, 0x00, voltage, 0x00, 0x03};
  baud[5] = cksum(&baud[1], 4);                 // SUM over LEN,0x9A,0,voltage
  uint8_t first = 0, auth[11];
  for (int i = 0; i < 10; ++i) auth[i] = id[i];
  auth[10] = (uint8_t)~cksum(id, 10);
  if (corrupt) auth[10]++;

  // Disable the Arduino UART reader so it cannot race our direct FIFO reads.
  gpio_put(PIN_TOOL0_TX, 1); // idle-high SIO latch while Serial1.end() restores mux
  gpio_set_dir(PIN_TOOL0_TX, GPIO_OUT);
  Serial1.end();
  Serial1.setPollingMode(true);
  uartBegin(REF_BAUD);
  uint32_t irqState = save_and_disable_interrupts();

  // Phase 1: identify, as present in BOTH reference traces. Inter-command
  // deadlines are relative to the last response byte's stop-bit sample.
  st1 = 0xE3; // identify failed; later OCD stages not reached
  referenceEntry();
  if (!sendModeBaud(0x3A, baud, 408) || !readFrame(3, 0x06, &first)) goto done;
  afterRxUs(503);
  if (!sendCmdA(0x00) || !readFrame(1, 0x06, &first)) goto done;
  afterRxUs(509);
  if (!sendCmdA(0xC0) || !readFrame(1, 0x06, &first) ||
      !readFrame(22, -1, &first)) goto done;
  afterRxUs(15789);
  if (!sendCmdA(0xA1) || !readFrame(1, 0x06, &first) ||
      !readFrame(8, -1, &first)) goto done;
  afterRxUs(3196);

  // Phase 2: RESET low ~100 ms, TOOL0 held low 10 ms AFTER release, then
  // TOOL0 high ~2.75 ms. No application-run / hot-plug assumption.
  referenceEntry();
  st1 = 0xE2; // echo error
  if (!sendModeBaud(0xC5, baud, 403)) goto done;
  st1 = 0xE0; // missing/malformed baud response
  if (!readFrameAny(&first)) goto done;
  st1 = first;
  if (st1 != 0x06) goto done;

  ping1 = (uint8_t)readWire();
  if (ping1 != 0x00) goto done;
  afterRxUs(186); // target 00 start -> host 00 start ~269 us
  if (!sendByte(0x00)) goto done;
  ping2 = (uint8_t)readWire();
  if (ping2 != 0x00) goto done;
  afterRxUs(32); // second target 00 -> host 90 ~114.5 us
  if (!sendByte(0x90) || readWire() != 0x03 || readWire() != 0x04) goto done;
  afterRxUs(426); // final PONG byte -> CONNECT ~509 us
  if (!sendByte(0x91)) goto done;
  connect = (uint8_t)readWire();
  if (connect == 0xF0) { idst = 0xF0; goto done; }  // already unlocked
  if (connect != 0xF1) goto done;                   // only send ID if LOCKED
  afterRxUs(525); // F1 start -> ID start ~608 us
  // All 11 bytes (10 ID + checksum) queued to FIFO — no gap on wire.
  uart_write_blocking(uart0, auth, sizeof(auth));
  // Read 10 ID echoes: validates link, syncs to checksum byte start.
  { bool echoOk = true;
    for (int i = 0; i < 10; i++) { if (readWire() != auth[i]) { echoOk = false; break; } }
    if (!echoOk) goto done;
  }
  // Glitch DURING checksum byte (delay=0 ≈ byte start on wire).
  if (gArmed) { waitNs(gDelayNs); glitchPulseNs(gWidthNs); }
  readWire(500); // checksum echo — may be corrupted by glitch
  uart_get_hw(uart0)->rsr = 0;
  idst = (uint8_t)readWire(5000);

done:
  restore_interrupts(irqState);
  // Resume buffered RX for subsequent generic 'X' transfers, preserving the
  // measured baud and 8N1 format. No target reset or power cycle here.
  gpio_put(PIN_TOOL0_TX, 1);
  Serial1.end();
  Serial1.setPollingMode(false);
  uartBegin(REF_BAUD);
  out[0] = st1; out[1] = ping1; out[2] = ping2; out[3] = connect; out[4] = idst;
}

// Fast OCD: skip Phase 1 (identify), do only Phase 2 (OCD entry + glitch).
// Saves ~144ms per attempt (100ms reset + 44ms identify handshake).
static void doOcdFast(uint8_t voltage, uint8_t corrupt, const uint8_t id[10], uint8_t *out) {
  uint8_t st1=0xEE, ping1=0xEE, ping2=0xEE, connect=0xEE, idst=0xEE;

  uint8_t baud[7] = {0x01, 0x03, 0x9A, 0x00, voltage, 0x00, 0x03};
  baud[5] = cksum(&baud[1], 4);
  uint8_t first = 0, auth[11];
  for (int i = 0; i < 10; ++i) auth[i] = id[i];
  auth[10] = (uint8_t)~cksum(id, 10);
  if (corrupt) auth[10]++;

  gpio_put(PIN_TOOL0_TX, 1);
  gpio_set_dir(PIN_TOOL0_TX, GPIO_OUT);
  Serial1.end();
  Serial1.setPollingMode(true);
  uartBegin(REF_BAUD);
  uint32_t irqState = save_and_disable_interrupts();

  // Straight to OCD entry — no identify phase.
  referenceEntry();
  st1 = 0xE2;
  if (!sendModeBaud(0xC5, baud, 403)) goto done;
  st1 = 0xE0;
  if (!readFrameAny(&first)) goto done;
  st1 = first;
  if (st1 != 0x06) goto done;

  ping1 = (uint8_t)readWire();
  if (ping1 != 0x00) goto done;
  afterRxUs(186);
  if (!sendByte(0x00)) goto done;
  ping2 = (uint8_t)readWire();
  if (ping2 != 0x00) goto done;
  afterRxUs(32);
  if (!sendByte(0x90) || readWire() != 0x03 || readWire() != 0x04) goto done;
  afterRxUs(426);
  if (!sendByte(0x91)) goto done;
  connect = (uint8_t)readWire();
  if (connect == 0xF0) { idst = 0xF0; goto done; }
  if (connect != 0xF1) goto done;
  afterRxUs(525);
  uart_write_blocking(uart0, auth, sizeof(auth));
  { bool echoOk = true;
    for (int i = 0; i < 10; i++) { if (readWire() != auth[i]) { echoOk = false; break; } }
    if (!echoOk) goto done;
  }
  if (gArmed) { waitNs(gDelayNs); glitchPulseNs(gWidthNs); }
  readWire(500);
  uart_get_hw(uart0)->rsr = 0;
  idst = (uint8_t)readWire(5000);

done:
  restore_interrupts(irqState);
  gpio_put(PIN_TOOL0_TX, 1);
  Serial1.end();
  Serial1.setPollingMode(false);
  uartBegin(REF_BAUD);
  out[0] = st1; out[1] = ping1; out[2] = ping2; out[3] = connect; out[4] = idst;
}

// ProtectError glitch: glitch AFTER Baud-Rate-Set frame (before chip responds),
// to bypass ProtectError (0x10) on chips where OCD is disabled via security flag.
// Delay = ns from end of last baud echo byte.  No Phase 1 (identify).
// out[0..4] = st1,ping1,ping2,connect,idst; out[5..8] = baudRespNs (LE u32).
static void doOcdGlitchBaud(uint8_t voltage, uint8_t corrupt, const uint8_t id[10], uint8_t *out) {
  uint8_t st1=0xEE, ping1=0xEE, ping2=0xEE, connect=0xEE, idst=0xEE;
  uint32_t baudRespNs = 0;

  uint8_t baud[7] = {0x01, 0x03, 0x9A, 0x00, voltage, 0x00, 0x03};
  baud[5] = cksum(&baud[1], 4);
  uint8_t first = 0, auth[11];
  for (int i = 0; i < 10; ++i) auth[i] = id[i];
  auth[10] = (uint8_t)~cksum(id, 10);
  if (corrupt) auth[10]++;

  gpio_put(PIN_TOOL0_TX, 1);
  gpio_set_dir(PIN_TOOL0_TX, GPIO_OUT);
  Serial1.end();
  Serial1.setPollingMode(true);
  uartBegin(REF_BAUD);
  uint32_t irqState = save_and_disable_interrupts();

  uint32_t t0Us = 0;
  referenceEntry();
  st1 = 0xE2;
  if (!sendModeBaud(0xC5, baud, 403)) goto done;
  // Record T0 = end of baud echo (chip starts processing NOW).
  t0Us = time_us_32();
  // Glitch during chip's security check.
  st1 = 0xE0;
  if (gArmed) { waitNs(gDelayNs); glitchPulseNs(gWidthNs); }
  if (!readFrameAny(&first)) goto done;
  // lastRxUs was set by readWire inside readFrameAny (first STX byte arrival).
  baudRespNs = (lastRxUs - t0Us) * 1000;
  st1 = first;
  if (st1 != 0x06) goto done; // still ProtectError? glitch missed

  // ACK — chip accepted baud, continue normal OCD handshake
  ping1 = (uint8_t)readWire();
  if (ping1 != 0x00) goto done;
  afterRxUs(186);
  if (!sendByte(0x00)) goto done;
  ping2 = (uint8_t)readWire();
  if (ping2 != 0x00) goto done;
  afterRxUs(32);
  if (!sendByte(0x90) || readWire() != 0x03 || readWire() != 0x04) goto done;
  afterRxUs(426);
  if (!sendByte(0x91)) goto done;
  connect = (uint8_t)readWire();
  if (connect == 0xF0) { idst = 0xF0; goto done; }
  if (connect != 0xF1) goto done;
  afterRxUs(525);
  uart_write_blocking(uart0, auth, sizeof(auth));
  { bool echoOk = true;
    for (int i = 0; i < 10; i++) { if (readWire() != auth[i]) { echoOk = false; break; } }
    if (!echoOk) goto done;
  }
  readWire(500); // checksum echo
  uart_get_hw(uart0)->rsr = 0;
  idst = (uint8_t)readWire(5000);

done:
  restore_interrupts(irqState);
  gpio_put(PIN_TOOL0_TX, 1);
  Serial1.end();
  Serial1.setPollingMode(false);
  uartBegin(REF_BAUD);
  out[0] = st1; out[1] = ping1; out[2] = ping2; out[3] = connect; out[4] = idst;
  out[5] = baudRespNs & 0xFF; out[6] = (baudRespNs >> 8) & 0xFF;
  out[7] = (baudRespNs >> 16) & 0xFF; out[8] = (baudRespNs >> 24) & 0xFF;
}

// ---- Command dispatch ------------------------------------------------------
static void handle(uint8_t cmd) {
  switch (cmd) {
    case 'V': wrU8('V'); wrU8(FW_VER_MAJOR); wrU8(FW_VER_MINOR); break;
    case 'B': { uint32_t b = rdU32(); uartBegin(b); wrU8('B'); wrU8('K'); break; }
    case 'R': { uint8_t lvl = rdU8(); if (lvl) resetAssert(); else resetRelease();
                wrU8('R'); wrU8('K'); break; }
    case 'E': { uint8_t m = rdU8(); uint16_t fl = rdU16();
                if (fl > sizeof(fbuf)) fl = sizeof(fbuf);
                for (uint16_t i = 0; i < fl; i++) fbuf[i] = rdU8();
                doEnter(m, fbuf, fl); break; }
    case 'X': doXfer(); break;
    case 'F': uartFlushRx(); wrU8('F'); wrU8('K'); break;
    case 'P': { uint8_t on = rdU8(); if (on) vtargetOn(); else vtargetOff();
                wrU8('P'); wrU8('K'); break; }
    case 'A': { uint16_t off = rdU16(); uint16_t settle = rdU16();
                autoReset(off, settle); wrU8('A'); wrU8('K'); break; }
    case 'O': { uint8_t voltage = rdU8(); uint8_t corrupt = rdU8();
                uint8_t id[10]; for (int i = 0; i < 10; i++) id[i] = rdU8();
                uint8_t res[5]; doOcd(voltage, corrupt, id, res);
                wrU8('O'); for (int i = 0; i < 5; i++) wrU8(res[i]); break; }
    // Glitched OCD: like 'O' but fire a crowbar pulse during the ID compare.
    // 'G' voltage corrupt id[10] delayNs(u32) widthNs(u32) mosfet(0=LP,1=HP)
    case 'G': { uint8_t voltage = rdU8(); uint8_t corrupt = rdU8();
                uint8_t id[10]; for (int i = 0; i < 10; i++) id[i] = rdU8();
                gDelayNs = rdU32(); gWidthNs = rdU32();
                glitchPin = rdU8() ? PIN_GLITCH_HP : PIN_GLITCH_LP;
                gArmed = (gWidthNs > 0);
                uint8_t res[5]; doOcd(voltage, corrupt, id, res);
                gArmed = false;
                wrU8('G'); for (int i = 0; i < 5; i++) wrU8(res[i]); break; }
    // Quick glitched OCD: skip identify phase, ~2x faster. Same wire format as 'G'.
    case 'Q': { uint8_t voltage = rdU8(); uint8_t corrupt = rdU8();
                uint8_t id[10]; for (int i = 0; i < 10; i++) id[i] = rdU8();
                gDelayNs = rdU32(); gWidthNs = rdU32();
                glitchPin = rdU8() ? PIN_GLITCH_HP : PIN_GLITCH_LP;
                gArmed = (gWidthNs > 0);
                uint8_t res[5]; doOcdFast(voltage, corrupt, id, res);
                gArmed = false;
                wrU8('Q'); for (int i = 0; i < 5; i++) wrU8(res[i]); break; }
    // ProtectError glitch: glitch during Baud-Rate-Set to bypass ProtectError.
    // Same wire format as 'G'. Delay = ns from end of baud frame echo.
    // Response: 'H' st1 ping1 ping2 connect idst baudRespNs(u32LE)
    case 'H': { uint8_t voltage = rdU8(); uint8_t corrupt = rdU8();
                uint8_t id[10]; for (int i = 0; i < 10; i++) id[i] = rdU8();
                gDelayNs = rdU32(); gWidthNs = rdU32();
                glitchPin = rdU8() ? PIN_GLITCH_HP : PIN_GLITCH_LP;
                gArmed = (gWidthNs > 0);
                uint8_t res[9]; doOcdGlitchBaud(voltage, corrupt, id, res);
                gArmed = false;
                wrU8('H'); for (int i = 0; i < 9; i++) wrU8(res[i]); break; }
    // Test glitch: fire crowbar pulse without any OCD / UART activity.
    // 'T' widthNs(u32) mosfet(0=LP,1=HP) count(u16) intervalUs(u16)
    //  -> 'T' count(u16)  (echoes how many pulses were fired)
    case 'T': { uint32_t wNs = rdU32();
                uint8_t mf = rdU8();
                uint16_t cnt = rdU16();
                uint16_t ivUs = rdU16();
                glitchPin = mf ? PIN_GLITCH_HP : PIN_GLITCH_LP;
                uint32_t irq = save_and_disable_interrupts();
                for (uint16_t i = 0; i < cnt; i++) {
                  glitchPulseNs(wNs);
                  if (ivUs && i + 1 < cnt) {
                    uint32_t t = time_us_32();
                    while ((int32_t)(time_us_32() - t) < (int32_t)ivUs) tight_loop_contents();
                  }
                }
                restore_interrupts(irq);
                wrU8('T'); wrU16(cnt); break; }
    default: break;   // ignore stray bytes
  }
}

void setup() {
  Serial.begin(115200);         // USB CDC (baud irrelevant)
  glitchInit();                 // crowbar outputs low/safe
  vtargetOn();                  // enable target power (PicoGlitcher VTARGET)
  resetRelease();               // /RESET released at boot
  uartBegin(curBaud);
}

void loop() {
  if (Serial.available()) handle(rdU8());
}

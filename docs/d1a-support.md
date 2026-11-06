# D1A OCD profile (bridge v1.15)

R5F10DMF is selected automatically from Silicon Signature. Override with
`--ocd-profile d1a` when identification is skipped. Firmware command
`S 01` selects D1A; `S 00` restores reference timing. Reply: `SK`.
The profile applies to O/G/Q/H. Each host run explicitly selects its profile
on firmware >= 1.15, avoiding a stale D1A profile on subsequent F13 sessions.

Timing is based on the successful DMF.sr capture: RESET low 100125 us,
TOOL low after reset release 10013 us, TOOL high before mode 2654 us,
mode-to-baud start gap 359 us. Post-RX waits are 78/17/266/344 us for
first ping / second ping / response to 90 / F1. These waits account for
the UART stop-bit sampling time (~82 us from start).
Command 90 must return 03 03 for D1A; the reference profile retains 03 04.

Build the updated bridge for PicoGlitcher v3 / Pico 2:

```powershell
arduino-cli compile --fqbn rp2040:rp2040:rpipico2 --output-dir build/d1a firmware_arduino/PicoRL78_bridge
```

After installing firmware v1.15, read with the known zero ID:

```powershell
python dump.py -p COM9 --memory all --auth bypass --id "00 00 00 00 00 00 00 00 00 00"
```

Permanent --unlock for this profile is rejected: the F13 option-byte/CRC
patch must not be applied to D1A. --rescue retains its exact-image behavior.
Hardware validation: R5F10DMF was read successfully with firmware v1.15 and
`--ocd-profile d1a`. The reference profile did not complete the first ping on
this chip. The D1A profile is required for this case; it is not merely an
optional timing adjustment. A poor contact was initially suspected, but the
working D1A profile confirmed that the profile differences matter.

To compare profiles explicitly, add `--ocd-profile reference` or
`--ocd-profile d1a`; default `auto` selects D1A for R5F10DMF.

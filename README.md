# PicoRL78 — Pico → RL78/F13 OCD

<img width="1544" height="213" alt="image" src="https://github.com/user-attachments/assets/cc08f13f-0809-4479-b400-baab3475180a" />

<img width="919" height="281" alt="image" src="https://github.com/user-attachments/assets/e8413beb-43a4-4198-86bc-1b38671d8c4a" />

Voltage fault injection (crowbar glitch) на RL78 OCD через PicoGlitcher v3.0 (RP2350).
Автоматический глитч ID-compare → дамп code/data flash.

## Железо

- **PicoGlitcher v3.0** (RP2350) — GP16/GP17 → TOOL0, GP2 → /RESET, GP22 → VTARGET
- **Crowbar**: GP3 GLITCH_EN, GP13 LP MOSFET, GP12 HP MOSFET → REGC
- Saleae Logic (опционально, для отладки тайминга)

## Прошивка

```bash
# Сборка (arduino-cli)
arduino-cli compile --fqbn rp2040:rp2040:rpipico2 --output-dir build/glitch firmware_arduino/PicoRL78_bridge

# Прошивка: зажать BOOTSEL, подключить USB, скопировать build/glitch/PicoRL78_bridge.ino.uf2
```

Текущая версия: **v1.14** — ProtectError bypass (Baud-Rate-Set glitch) + timing measurement.

## Использование

### Быстрый старт — глитч + дамп

```bash
cd host
python dump.py -p COM9 --memory codeflash
```

Скрипт автоматически:
1. Определяет чип (модель, размеры flash) через Silicon Signature
2. Сканирует глитч-параметры до verified unlock
3. Дампит flash в `dumps/MODEL_NNN_codeflash.bin`

### dump.py — аргументы

| Аргумент | По умолчанию | Описание |
|----------|-------------|----------|
| `-p, --port` | — | COM-порт PicoGlitcher (обязательный) |
| `--memory` | — | Что дампить: `codeflash`, `dataflash`, `rom`, `both`, `all` |
| `--auth` | `glitch` | Метод входа: `glitch`, `bypass` (известный ID), `session` |
| `--id` | 10×00 | OCD ID (hex), если известен |
| `--delay` | `0 100000` | Диапазон delay [min max] ns от начала чексуммы |
| `--width` | `80 300` | Диапазон ширины пульса [min max] ns |
| `--attempts` | `5000` | Макс. количество попыток |
| `--mosfet` | `lp` | Crowbar MOSFET: `lp` или `hp` |
| `--grid` | — | Детерминированный перебор вместо рандома |
| `--protect` | авто | ProtectError bypass (глитч Baud-Rate-Set вместо ID auth) |
| `--no-fast` | — | Использовать 'G' (с identify) вместо 'Q' |
| `--no-identify` | — | Пропустить идентификацию чипа |
| `--dump-dir` | `../dumps` | Папка для дампов (создаётся автоматически) |
| `--cf-out` | авто | Имя файла codeflash (переопределяет авто-нумерацию) |
| `--df-out` | авто | Имя файла dataflash |
| `--cf-pages` | авто | Количество страниц code flash (авто из Silicon Sig) |
| `--df-pages` | авто | Количество страниц data flash (авто из Silicon Sig) |
| `--voltage` | `50` | Напряжение (V×10): 50=5.0V, 33=3.3V |
| `--unlock` | — | После дампа: перманентно снять OCD-защиту (erase block 0 + reprogram с патченными option bytes) |
| `--rescue DUMP` | — | Стереть весь code flash и перепрошить из файла дампа (Protocol A, без глитча) |

### Примеры

**Полный дамп (code + data flash) с автоопределением:**
```bash
python dump.py -p COM9 --memory both
# -> dumps/R5F10BAG_001_codeflash.bin, dumps/R5F10BAG_001_dataflash.bin
```

**Быстрый глитч с узким окном (когда рабочая точка известна):**
```bash
python dump.py -p COM9 --memory codeflash --delay 63000 73000 --width 200 350 --attempts 500
# ~1-3 секунды до хита вместо ~26
```

**Дамп с известным OCD ID (без глитча):**
```bash
python dump.py -p COM9 --memory both --auth bypass --id "00 00 00 00 00 00 00 00 00 00"
```

**Продолжить дамп в существующей OCD сессии (без ресета):**
```bash
python dump.py -p COM9 --memory dataflash --auth session
```

**Дамп OCD boot ROM:**
```bash
python dump.py -p COM9 --memory rom --auth bypass
# -> dumps/R5F10BAG_001_rom.bin (0xF0000-0xFDEFF)
```

**Всё сразу (ROM + data + code):**
```bash
python dump.py -p COM9 --memory all
```

**Дамп в конкретную папку:**
```bash
python dump.py -p COM9 --memory codeflash --dump-dir ./output
# -> output/R5F10BAG_001_codeflash.bin
```

**Grid-скан (детерминированный перебор):**
```bash
python dump.py -p COM9 --memory codeflash --grid --delay 60000 80000 --width 200 350 --delay-step 100 --width-step 10
```

**Дамп + перманентная разблокировка (снятие ProtectError + ID-CODE):**
```bash
python dump.py -p COM9 --memory codeflash --unlock
# глитч → дамп → erase block 0 → reprogram с OCD enabled, OCD ID = 00*10
```

**Восстановление заблокированного чипа из дампа (без глитча):**
```bash
python dump.py -p COM9 --rescue dumps/R5F10BAG_001_codeflash.bin
# Protocol A: erase all → reprogram all → option bytes патчатся автоматически
```

### Авто-нумерация дампов

Файлы именуются `MODEL_NNN_тип.bin` (номер инкрементится автоматически):
```
dumps/
├── R5F10BAG_001_codeflash.bin    # первый дамп
├── R5F10BAG_001_dataflash.bin
├── R5F10BAG_002_codeflash.bin    # второй дамп (другой чип или повторный)
├── R5F10GCE_001_codeflash.bin    # другая модель — нумерация отдельная
└── ...
```

## Структура проекта

```
PicoRL78/
├── firmware_arduino/PicoRL78_bridge/   # прошивка RP2350 (v1.14)
├── build/glitch/                       # скомпилированный UF2
├── host/
│   ├── dump.py                         # глитч + дамп (основной скрипт)
│   ├── rl78bridge.py                   # транспорт Pico ↔ host
│   ├── rl78_proto.py                   # Protocol A + OCD (справочная реализация)
│   ├── enter_ocd.py                    # чистый OCD вход (диагностика, без глитча)
│   ├── probe_ocd.py                    # проба OCD статуса
│   └── glitch_test.py                  # тест crowbar пульса (без OCD)
├── captures/                           # Saleae Logic (.sr/.pvs)
├── dumps/                              # дампы flash (авто-создаётся)
└── tools/analyze_capture.py            # анализ захватов
```

## Как работает глитч

1. **Identify** (опционально) — mode 0x3A, Silicon Signature → модель чипа
2. **OCD entry** — mode 0xC5, Baud-Rate-Set, ping/pong, CONNECT → F1 (locked)
3. **Auth** — отправка 10 байт ID + чексумма (0xFF для ID=10×00)
4. **Glitch** — crowbar pulse на REGC **во время security check** (delay = ns от начала чексуммы, сбивает сравнение ID)
5. **Verify** — CONNECT(0x91) → F0 подтверждает что чип реально разлочен
6. **Dump** — OCD READ/WRITE/EXEC для чтения flash

Сладкая зона delay:
- **ID-CODE (F3)**: 0–100000 ns (security check возле чексуммы)
- **ProtectError (0x10)**: 150000–400000 ns (security check после Baud-Rate-Set echo)

### ProtectError bypass

Для чипов с ProtectError (OCD заблокирован полностью, не ID-CODE) — автодетекция:
```bash
python dump.py -p COM9 --memory codeflash
# автоопределение: st1=0x10 → --protect mode, delay 0-600000ns
```
Ручной запуск:
```bash
python dump.py -p COM9 --memory codeflash --protect --delay 0 600000
```

#### Документация RL78:
- [Protocol A](https://www.renesas.com/en/document/apn/rl78-microcontrollers-rl78-protocol-programmer-edition-application-note)
- [RL78 Microcontroller (RL78 Protocol B) Serial Programming Guide](https://www.renesas.com/en/document/apn/rl78-family-rl78-microcontroller-rl78-protocol-b-serial-programming-guide)
- [RL78/F12 User's Manual: Hardware](https://www.renesas.com/en/document/mah/rl78f12-users-manual-hardware)
- [RL78/F13,F14 User's Manual: Hardware](https://www.renesas.com/en/document/mah/rl78f13-f14-users-manual-hardware-rev220)

#### Взломанные устройства:
- RL78/F13 R5F10BAG - KTM ICKT_64100110T39 (защита ID-CODE)
- RL78/F12 R5F109GC - Honda GATEWAY 38890-T22-A11 (защита ProtectError) (CODE одинаковая с 38890-T20-A22, 38890-T20-A52, ...)
- RL78/F13 R5F10AGG - VW 5Q1953569C (защита ID-CODE)
- RL78/F14 R5F10PPJ - Honda Relay Module 38830-TVA-A01 (защита ProtectError)

![HELL](https://github.com/VV1LD/SYSGLITCH/blob/master/hell.jpg)

## Референсы

- fail0verflow `rl78-debug` — <https://github.com/fail0verflow/rl78-debug>
- fail0verflow PS4 Syscon — <https://fail0verflow.com/blog/2018/ps4-syscon/>
- kirya-dev `PicoRL78` — <https://github.com/kirya-dev/PicoRL78>
- Renesas: R20AN6332, R01AN0815, R01AN5756 (Protocol B/A/C), R01UH0368 (UM F13/F14)

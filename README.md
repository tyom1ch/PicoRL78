# PicoRL78 — чистый UART-мост Pico → RL78/F13 (R5F10BAG), вход в OCD

## Текущая Arduino-прошивка: v1.9

Вход `O` перенесён по двум захватам рабочего программатора:
`CAP_CODE_STRIP.sr` и `dataflash.sr`. RESET low — 100134 мкс; после отпускания
RESET TOOL0 остаётся low ещё 10017 мкс; затем high 2748 мкс до `C5`.
UART — 8N1, 114800 бод по измеренной длительности бита; код скорости RL78 — 0.
Гипотеза v1.8 о входе через запуск приложения/hot plug-in удалена.

UF2 для **Pico 2 / RP2350**: `artifacts/v1.9/PicoRL78_bridge.ino.uf2`.
После загрузки прошивки:

```powershell
python host/enter_ocd.py -p COM9
```

Скрипт отправляет указанный ID (по умолчанию десять `00`) с корректной
контрольной суммой. Для намеренно неверной суммы есть `--corrupt-sum`.
`--slow` не использует новый обмен. Измерения, ограничения и диагностика:
[analysis/reference-timing.md](analysis/reference-timing.md).
Новая прошивка собрана; проверка на целевой плате ещё не выполнена.

Задача: довести чип **R5F10BAG** (RL78/F13, 128 КБ code flash) до стадии
**OCD-аутентификации по 10-байтному паролю** строго по документации — **без
глитчинга**. Первый ожидаемый результат — **F3 NACK** (checksum mismatch),
который подтверждает, что чип в OCD, фрейминг верный и флеш цел.

Arduino-прошивка использует аппаратный UART и выполняет OCD-обмен на Pico.
Альтернативный C/PIO-вариант в `firmware/` не обновлён до этого обмена.

---

## Тайминги

Весь timing-critical слой выполняется на Pico аппаратно:

- **Биты UART** в Arduino-прошивке формирует аппаратный UART.
- **Окна reset/entry и паузы `O`** отсчитываются по таймеру Pico; прерывания
  временно отключаются. Точность воспроизведения проверяется новым захватом.
- **Transfer (`X`)** атомарен: Pico передаёт и тут же ловит ответ сам, так что
  латентность USB не попадает на линию.

---

## Железо / распиновка — PicoGlitcher v3.0 (Pico 2 / RP2350)

Пины фиксированы разводкой платы. Single-wire TOOL0, полудуплекс, TX через диод:

| Pico GP | Плата v3.0 | Подключение к RL78 |
|---|---|---|
| GP16 | UART0 TX (без level shifter) | → диод (катод к GP16) → TOOL0 (тянет только в 0) |
| GP17 | UART0 RX (без level shifter) | → прямо на TOOL0 (читает линию, видит эхо) |
| GP2  | RESET (через level shifter)  | → `/RESET` RL78 (push-pull: LOW=сброс, HIGH=работа) |
| GP22 | VTARGET_EN                   | питание цели (вкл/выкл, авто power-cycle) |
| GND  | —                            | → GND цели |

- На TOOL0 нужен pull-up (на стороне цели; на GP17 внутренняя подтяжка включена).
- RESET на GP2 идёт через level shifter платы → драйвится **push-pull** (не hi-Z).
- **Авторесет**: вход `E` сам дёргает GP2 по таймингам tSU/tHD; `--power-cycle`
  делает холодный цикл по VTARGET (GP22), держа чип в ресете.
- **Логический анализатор**: цепляй прямо на TOOL0 (и на GP2 для reset).
- OCD-ядро работает на 2.1 В (регулятор задаётся Baud-Rate-Set, voltage=21).
- GP14=TRIGGER, GP3/12/13=glitch — не используются (мы не глитчим).

---

## Сборка прошивки

### Вариант A (рекомендуемый): Arduino — `firmware_arduino/`

1. Arduino IDE → добавь ядро **arduino-pico** (Earle F. Philhower):
   Boards Manager URL `https://github.com/earlephilhower/arduino-pico/releases/download/global/package_rp2040_index.json`
2. Плата: **Raspberry Pi Pico 2** (если у тебя RP2040 — «Raspberry Pi Pico»).
3. Открой `firmware_arduino/PicoRL78_bridge/PicoRL78_bridge.ino`, Upload.

Использует аппаратный UART (PL011); сборка через ядро arduino-pico.

### Вариант B (альтернатива): Pico C SDK + PIO — `firmware/`

```sh
cd firmware && mkdir build && cd build
cmake -G "Ninja" ..        # нужен PICO_SDK_PATH
ninja                      # -> tool0_bridge.uf2  (BOOTSEL -> копировать на RPI-RP2)
```

## Хост

```sh
cd host
pip install -r requirements.txt

# Основной сценарий: вход в OCD + безопасное подтверждение F3, затем СТОП.
python enter_ocd.py -p COM7

# Сначала проверить сам физический слой (чтение silicon signature, mode 0x3A,
# ничего не стирает) — метод исключения, если OCD-коннект не идёт:
python enter_ocd.py -p COM7 --sig

# Отправить ID с намеренно неверной контрольной суммой:
python enter_ocd.py -p COM7 --corrupt-sum
```

---

## Безопасность флеша (подтверждено дампом того же чипа)

- **Option byte 000C3H = `0x87`** → `OCDENSET=1, HPIEN=1, OCDERSD=1`
  (R01UH0368 Fig 29-4, строка «1 1 1»): OCD включён + hot plug-in, и **флеш НЕ
  стирается при провале аутентификации ID**.
- **OCD ID (000C4H–000CDH) = десять `0x00`** — валидный ID (запрещён только all-FF).
- Скрипт по умолчанию шлёт десять `00` с корректной суммой; в эталонных
  захватах это приводит к `F2`. Поведение при неверном ID зависит от option
  byte конкретной цели. Команд стирания и программирования в обмене `O` нет.

---

## Карта «состояние → норма»

| Этап | Источник |
|---|---|
| Reset/entry waveform (tSU≥10µs, tHD≥1ms, tSUINIT≤100ms) | R20AN6332 §1.4 (+ f0f `enter_rom`) |
| UART 115200, 8 data LSB-first, 2 stop (host→MCU), без parity | R20AN6332 Table 3 / R01AN0815 |
| Mode-byte `0x3A` (1-wire prog) / `0xC5` (OCD) | R20AN6332 Table 5 / kirya `MODE_OCD` |
| Кадр SOH/STX/LEN/SUM/ETX, SUM=(0−Σ)&0xFF | R01AN0815 Fig 2-1/2-2, Table 2-1 |
| Статусы 06=ACK / 15=NACK / 10=PROTECT … | R01AN0815 Table 1-4 |
| Baud-Rate-Set 0x9A ответ `STX 03 ST1 D01 D02` | R01AN0815 Fig 3-3/3-4 |
| Baud-Rate-Set voltage **5.0 В→50(0x32)** | kirya-dev (F13) |
| OCD: хендшейк `00/00/00`, CONNECT 0x91, коды F0–F4 | **kirya-dev/PicoRL78 (F13)** |
| **F3** = OCD_STS_UNLOCK_ERR (auth-fail NACK, норма) | kirya-dev / DRIVE2 (R5F10AGG) |
| 000C3H=0x87 (OCDERSD=1, не стирать) | R01UH0368 Fig 29-4 + дамп `OPBT` |
| OCD ID = 10×0x00 | R01UH0368 §31.3 + дамп `OCDID` |

## Прошивочный протокол Pico↔хост (little-endian)

```
'V'                                    -> 'V' verMaj verMin
'B' u32 baud                           -> 'B' 'K'
'R' u8 lvl (1=/RESET low, 0=release)   -> 'R' 'K'
'E' u8 mode u16 flen fu[flen]          -> 'E' u8 n  n*cap  (mode+fu back-to-back; cap=echo+resp)
'X' u16 txlen tx u16 rxlen u16 to_ms   -> 'X' u16 n  n*rx   (эхо включено, хост срезает)
'F'                                    -> 'F' 'K'
'P' u8 (1=VTARGET on,0=off)            -> 'P' 'K'
'A' u16 off_ms u16 on_settle_ms        -> 'A' 'K'   (авто power-cycle, держит reset)
```

## Референсы

- fail0verflow `rl78-debug` — <https://github.com/fail0verflow/rl78-debug>
- fail0verflow PS4 Syscon — <https://fail0verflow.com/blog/2018/ps4-syscon/>
- kirya-dev `PicoRL78` — <https://github.com/kirya-dev/PicoRL78>
- Renesas: R20AN6332, R01AN0815, R01AN5756 (Protocol B/A/C), R01UH0368 (UM F13/F14)

# Chip Notes — глитч-параметры по чипам

## R5F10BAG — RL78/F13

**Устройство:** KTM ICKT_64100110T39
**Защита:** ID-CODE (F3)
**OCD ID:** 10×0x00 (пароля фактически нет)

### Проблема

Чип изначально был без реальной защиты — OCD ID все нули, подключение проходит с дефолтным паролем. Пришлось самому прошить пароль через Renesas Flash Programmer чтобы протестировать глитчер.

### Рабочие параметры

| Параметр | Значение |
|----------|----------|
| Рабочая точка | **d=800ns w=160ns** |
| Диапазон delay | 0–100µs |
| Диапазон width | 80–300ns |
| MOSFET | LP |
| Напряжение | 5.0V (обязательно) |

### Проблемы при разработке

- **Напряжение 3.3V не работает** — чип не отвечал на ping, строго 5.0V
- **Отсутствовал шаг 0x90 PING** в OCD последовательности — без него чип не проходил дальше handshake. Нашли только из захвата реального программатора (Saleae)
- **Host-side тайминг слишком медленный** — USB-латенция между ping и pong ломала протокол. Решение: перенесли весь OCD handshake на Pico (fw команда 'O', потом 'G'/'Q')

### Дамп

128KB code flash, 4KB data flash, 57KB ROM (0xF0000–0xFDEFF)

---

## R5F10BGG — RL78/G13

**Устройство:** ProtectError чип
**Защита:** ProtectError (0x10) — OCD полностью заблокирован
**OCD ID:** нет (чип даже не доходит до проверки пароля)

### Рабочие параметры

| Параметр | Значение |
|----------|----------|
| Рабочий кластер | **d=135–142µs, w=200–240ns** |
| Диапазон delay | 105–255µs |
| Диапазон width | 80–300ns |
| MOSFET | LP |
| Напряжение | 5.0V |
| Резистор | не нужен |

### Все хиты

| # | Попытка | Delay (ns) | Width (ns) | Диапазон скана |
|---|---------|-----------|-----------|----------------|
| 1 | 1594/5000 | 229852 | 153 | d=150000–400000 w=80–300 |
| 2 | 98/5000 | 141848 | 220 | d=105000–255000 w=10–500 |
| 3 | 527/5000 | 135732 | 205 | d=130000–245000 w=100–280 |
| 4 | 149/5000 | 137354 | 240 | d=125000–155000 w=150–280 |
| 5 | 52/5000 | 136437 | 202 | d=132000–145000 w=180–260 |

Кластер 135–142µs стабильный (4 из 5 хитов). Выброс на 230µs — возможно второе уязвимое место в security check.

### Проблемы

- **Crowbar слишком сильный** — LP MOSFET без ограничений просаживает VCC почти до 0V. Окно между "ничего" и "крэш" очень узкое
- **Резистор на crowbar не помог** — пробовали подтяжку, слишком глубокая просадка даже с резистором
- **Mask ROM другой** — ROM R5F10BGG (G13) отличается от R5F10BAG (F13) на 93%. Тайминги security check не переносятся между семействами, нельзя использовать анализ одного ROM для другого
- **Первый хит был невоспроизводим** — d=229852ns сработал один раз, при сужении до ±5µs не повторился. Стабильный кластер нашёлся только после расширения скана

### Дамп

128KB code flash, 4KB data flash, 57KB ROM

## R5F10AGF — RL78/F13

**Устройство:** ProtectError чип
**Защита:** ProtectError (0x10) — OCD полностью заблокирован
**OCD ID:** нет (чип даже не доходит до проверки пароля)

<img width="1067" height="312" alt="image" src="https://github.com/user-attachments/assets/2b955af7-ff94-469d-b3c3-f1afa8b70fb1" />

### Confirmed R5F10AGF result

The screenshot above records VERIFIED UNLOCK at attempt 106/10000:
`d=155055 ns`, `w=104 ns`, `st1=ACK`, `idst=0xF2`, followed by verified CONNECT.
Reading completed with `Done.`:

| Region | Bytes | 256-byte pages |
|---|---:|---:|
| CodeFlash | 98304 (96 KiB) | 384 |
| DataFlash | 4096 (4 KiB) | 16 |
| ROM, 0xF0000-0xFDEFF | 57088 | 223 |

This confirms protection bypass and memory readout. The screenshot does not
show completion of permanent unlock after reprogramming. Timing values describe
this successful attempt and are not guaranteed for other specimens.

### CodeFlash CRC

Both original R5F10AGF dumps match the high-speed CRC described in Renesas
R01UH0368 section 27.3.1: polynomial 0x1021, initial value 0, no final XOR.
Process 0x00000-0x17FFB, reversing the byte order within each 32-bit word.
Store the result little-endian at 0x17FFC-0x17FFD; leave the final FF FF unchanged.

| Dump | Original CRC | After C2=C3=FF and OCD ID=10 zero bytes |
|---|---:|---:|
| 001 | CDB9 | EA6D |
| 002 | 2024 (bytes 24 20) | 07F0 (bytes F0 07) |

`--unlock` validates the original CRC, patches a copy in memory and recalculates
CRC before programming. `--rescue DUMP` restores the file byte-for-byte,
including its original option bytes, OCD ID and CRC. Both write block 0 last.

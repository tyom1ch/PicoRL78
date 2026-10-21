# RL78 OCD Protection: ID-CODE vs ProtectError

## Два типа защиты OCD

RL78 имеет два независимых механизма защиты OCD (On-Chip Debug):

### 1. ID-CODE Protection (ответ F3)

Чип **разрешает** OCD-подключение, но требует 10-байтный пароль (OCD Security ID).

**Протокол:**
```
Host → 0xC5 (OCD mode)
Host → Baud-Rate-Set frame
Chip → ACK (0x06)              ← OCD разрешён
Host → ping/pong (0x00/0x00)
Host → CONNECT (0x91)
Chip → F1 (locked)             ← требуется авторизация
Host → 10 байт ID + checksum
Chip → F3 (AUTH-FAIL)          ← неверный пароль
```

**Управляется:** option byte по адресу `0x000C3` (Security Set в Renesas Flash Programmer).

**Глитч:** crowbar pulse в момент проверки ID (delay 0–100µs от начала чексуммы). Просадка напряжения сбивает CPU во время сравнения полученного ID со значением в flash — пропуск условного перехода или искажение прочитанных из flash данных.

### 2. ProtectError Protection (ответ 0x10)

Чип **полностью запрещает** OCD. Отказ происходит на этапе Baud-Rate-Set — до проверки пароля.

**Протокол:**
```
Host → 0xC5 (OCD mode)
Host → Baud-Rate-Set frame
Chip → ProtectError (0x10)     ← OCD запрещён, дальше не идём
```

**Управляется:** option byte по адресу `0x000C2`. Если OCD запрещён — чип даже не доходит до этапа ID-авторизации. **Пароль не нужен и не проверяется.**

**Глитч:** crowbar pulse после echo Baud-Rate-Set фрейма (delay 150–400µs от конца echo). Просадка напряжения вызывает сбой при чтении option bytes из flash или пропуск условного перехода в security check. Чип отвечает ACK вместо ProtectError.

## Option Bytes

RL78 option bytes расположены в code flash по адресу `0x000C0`:

| Адрес | Назначение |
|-------|-----------|
| `0x000C0` | Watchdog timer config |
| `0x000C1` | LVD / voltage detect config |
| `0x000C2` | **OCD mode enable/disable** (ProtectError если бит сброшен) |
| `0x000C3` | **OCD Security ID enable** (ID-CODE protection если установлен) |

При записи через Renesas Flash Programmer:
- Сброс бита в `0xC2` → OCD полностью заблокирован (ProtectError)
- Установка бита в `0xC3` + запись 10-байт ID → OCD через пароль (ID-CODE)
- Оба могут быть активны одновременно

## Тайминг глитча

### ID-CODE (проверено на R5F10BAG — RL78/F13)
```
|←── checksum byte TX (~87µs) ──→|
     |← delay 0-100µs →|█|       ← crowbar pulse (width 80-300ns)
                         ^
                  security check (ID compare)
```
Рабочая точка: **d=800ns w=160ns** (LP MOSFET, без модификаций).

### ProtectError (проверено на R5F10BGG — RL78/G13)
```
|←── baud frame echo ──→|←── chip processing ~740µs ──→|←── response ──→|
                         |← delay 150-400µs →|█|        ← crowbar pulse
                                              ^
                                  security check / flash read
```
Рабочая точка: **d=229852ns w=153ns** (LP MOSFET).

## Boot ROM

Mask ROM (0xF0000–0xFDEFF) содержит OCD boot код. **ROM различается между подсемействами:** R5F10BAG (RL78/F13) и R5F10BGG (RL78/G13) совпадают только на 6.7% — адреса функций, структура кода и тайминги security check разные.

Ключевые функции (по анализу R5F10BAG ROM в IDA):
- `ocd_flash_option_init` — читает option bytes из flash, устанавливает флаги в `byte_F0890`
- `ocd_send_status` — вызывает `ocd_flash_option_init`, решает ACK/ProtectError
- `ocd_check_status_flags` — проверяет `(A & byte_F0890) == 0x47`

## Документация Renesas

- [RL78 Protocol A — Serial Programming](https://www.renesas.com/en/document/apn/rl78-microcontrollers-rl78-protocol-programmer-edition-application-note) (R20AN0815)
- [RL78/F13,F14 User's Manual: Hardware](https://www.renesas.com/en/document/mah/rl78f13-f14-users-manual-hardware-rev220) (R01UH0368) — Chapter 26: Flash memory / Option bytes
- [RL78/G13 User's Manual: Hardware](https://www.renesas.com/en/document/mah/rl78g13-users-manual-hardware-rev620) (R01UH0146) — Chapter 26: Flash memory / Option bytes
- [RL78 Protocol B — Serial Programming](https://www.renesas.com/en/document/apn/rl78-family-rl78-microcontroller-rl78-protocol-b-serial-programming-guide) (R01AN5756)
- [RL78 Microcontroller (RL78 Protocol C)](https://www.renesas.com/en/document/apn/rl78-family-rl78-microcontroller-rl78-protocol-c-serial-programming-guide) (R01AN6332)

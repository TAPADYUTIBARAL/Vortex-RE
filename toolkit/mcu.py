"""
MCU / controller database.
Maps user-supplied controller names to architecture parameters for radare2 and analysis.
"""
from dataclasses import dataclass


@dataclass
class MCUInfo:
    key: str            # match key (lowercase)
    family: str         # display name
    r2_arch: str        # radare2 -a value
    r2_bits: str        # radare2 -b value
    r2_cpu: str | None  # radare2 asm.cpu (None = not needed)
    thumb: bool         # Cortex-M Thumb-2 mode
    flash_base: int     # default flash start address
    ram_base: int       # default RAM start address
    description: str


# Ordered longest-key-first so "stm32f4" matches before "stm32"
_MCU_DB: list[MCUInfo] = [
    # ── STM32 ──────────────────────────────────────────────────────────────────
    MCUInfo("stm32u5",   "STM32U5",  "arm", "16", "cortex-m33", True, 0x08000000, 0x20000000, "STM32U5  Cortex-M33"),
    MCUInfo("stm32h7",   "STM32H7",  "arm", "16", "cortex-m7",  True, 0x08000000, 0x20000000, "STM32H7  Cortex-M7"),
    MCUInfo("stm32f7",   "STM32F7",  "arm", "16", "cortex-m7",  True, 0x08000000, 0x20000000, "STM32F7  Cortex-M7"),
    MCUInfo("stm32f4",   "STM32F4",  "arm", "16", "cortex-m4",  True, 0x08000000, 0x20000000, "STM32F4  Cortex-M4F"),
    MCUInfo("stm32f3",   "STM32F3",  "arm", "16", "cortex-m4",  True, 0x08000000, 0x20000000, "STM32F3  Cortex-M4"),
    MCUInfo("stm32f2",   "STM32F2",  "arm", "16", "cortex-m3",  True, 0x08000000, 0x20000000, "STM32F2  Cortex-M3"),
    MCUInfo("stm32f1",   "STM32F1",  "arm", "16", "cortex-m3",  True, 0x08000000, 0x20000000, "STM32F1  Cortex-M3"),
    MCUInfo("stm32f0",   "STM32F0",  "arm", "16", "cortex-m0",  True, 0x08000000, 0x20000000, "STM32F0  Cortex-M0"),
    MCUInfo("stm32g4",   "STM32G4",  "arm", "16", "cortex-m4",  True, 0x08000000, 0x20000000, "STM32G4  Cortex-M4"),
    MCUInfo("stm32g0",   "STM32G0",  "arm", "16", "cortex-m0",  True, 0x08000000, 0x20000000, "STM32G0  Cortex-M0+"),
    MCUInfo("stm32l4",   "STM32L4",  "arm", "16", "cortex-m4",  True, 0x08000000, 0x20000000, "STM32L4  Cortex-M4"),
    MCUInfo("stm32l0",   "STM32L0",  "arm", "16", "cortex-m0",  True, 0x08000000, 0x20000000, "STM32L0  Cortex-M0+"),
    MCUInfo("stm32wb",   "STM32WB",  "arm", "16", "cortex-m4",  True, 0x08000000, 0x20000000, "STM32WB  Cortex-M4"),
    MCUInfo("stm32wl",   "STM32WL",  "arm", "16", "cortex-m4",  True, 0x08000000, 0x20000000, "STM32WL  Cortex-M4"),
    MCUInfo("stm32",     "STM32",    "arm", "16", "cortex-m4",  True, 0x08000000, 0x20000000, "STM32    Cortex-M (generic)"),

    # ── NXP LPC ────────────────────────────────────────────────────────────────
    MCUInfo("lpc55",     "LPC55xx",  "arm", "16", "cortex-m33", True, 0x00000000, 0x20000000, "NXP LPC55xx Cortex-M33"),
    MCUInfo("lpc43",     "LPC43xx",  "arm", "16", "cortex-m4",  True, 0x1A000000, 0x10000000, "NXP LPC43xx Cortex-M4"),
    MCUInfo("lpc40",     "LPC40xx",  "arm", "16", "cortex-m4",  True, 0x00000000, 0x10000000, "NXP LPC40xx Cortex-M4"),
    MCUInfo("lpc18",     "LPC18xx",  "arm", "16", "cortex-m3",  True, 0x1A000000, 0x10000000, "NXP LPC18xx Cortex-M3"),
    MCUInfo("lpc17",     "LPC17xx",  "arm", "16", "cortex-m3",  True, 0x00000000, 0x10000000, "NXP LPC17xx Cortex-M3"),
    MCUInfo("lpc13",     "LPC13xx",  "arm", "16", "cortex-m3",  True, 0x00000000, 0x10000000, "NXP LPC13xx Cortex-M3"),
    MCUInfo("lpc11",     "LPC11xx",  "arm", "16", "cortex-m0",  True, 0x00000000, 0x10000000, "NXP LPC11xx Cortex-M0"),

    # ── NXP i.MX RT (MCU) ──────────────────────────────────────────────────────
    MCUInfo("imxrt11",   "i.MX RT11","arm", "16", "cortex-m7",  True, 0x30000000, 0x20000000, "NXP i.MX RT1170 Cortex-M7"),
    MCUInfo("imxrt10",   "i.MX RT10","arm", "16", "cortex-m7",  True, 0x60000000, 0x20000000, "NXP i.MX RT10xx Cortex-M7"),
    MCUInfo("imxrt",     "i.MX RT",  "arm", "16", "cortex-m7",  True, 0x60000000, 0x20000000, "NXP i.MX RT Cortex-M7"),

    # ── NXP i.MX (application processor — Linux) ──────────────────────────────
    MCUInfo("imx8",      "i.MX 8",   "arm", "64", None,         False, 0x80000000, 0x80000000, "NXP i.MX8   Cortex-A53/A72"),
    MCUInfo("imx6",      "i.MX 6",   "arm", "32", None,         False, 0x10000000, 0x10000000, "NXP i.MX6   Cortex-A9"),
    MCUInfo("imx",       "i.MX",     "arm", "32", None,         False, 0x10000000, 0x10000000, "NXP i.MX    Cortex-A (generic)"),

    # ── ESP ────────────────────────────────────────────────────────────────────
    MCUInfo("esp32c6",   "ESP32-C6", "riscv", "32", None,       False, 0x42000000, 0x40800000, "ESP32-C6  RISC-V"),
    MCUInfo("esp32c3",   "ESP32-C3", "riscv", "32", None,       False, 0x42000000, 0x3FC80000, "ESP32-C3  RISC-V"),
    MCUInfo("esp32s3",   "ESP32-S3", "xtensa","32", None,       False, 0x00010000, 0x3FC80000, "ESP32-S3  Xtensa LX7"),
    MCUInfo("esp32s2",   "ESP32-S2", "xtensa","32", None,       False, 0x00010000, 0x3FFB0000, "ESP32-S2  Xtensa LX7"),
    MCUInfo("esp32",     "ESP32",    "xtensa","32", None,       False, 0x00010000, 0x3FFA0000, "ESP32     Xtensa LX6"),
    MCUInfo("esp8266",   "ESP8266",  "xtensa","32", None,       False, 0x40000000, 0x3FFE8000, "ESP8266   Xtensa L106"),

    # ── Nordic ─────────────────────────────────────────────────────────────────
    MCUInfo("nrf9160",   "nRF9160",  "arm", "16", "cortex-m33", True, 0x00000000, 0x20000000, "Nordic nRF9160 Cortex-M33"),
    MCUInfo("nrf5340",   "nRF5340",  "arm", "16", "cortex-m33", True, 0x00000000, 0x20000000, "Nordic nRF5340 Cortex-M33"),
    MCUInfo("nrf52840",  "nRF52840", "arm", "16", "cortex-m4",  True, 0x00000000, 0x20000000, "Nordic nRF52840 Cortex-M4F"),
    MCUInfo("nrf52",     "nRF52",    "arm", "16", "cortex-m4",  True, 0x00000000, 0x20000000, "Nordic nRF52 Cortex-M4F"),
    MCUInfo("nrf51",     "nRF51",    "arm", "16", "cortex-m0",  True, 0x00000000, 0x20000000, "Nordic nRF51 Cortex-M0"),

    # ── Raspberry Pi / RP ──────────────────────────────────────────────────────
    MCUInfo("rp2350",    "RP2350",   "arm", "16", "cortex-m33", True, 0x10000000, 0x20000000, "RP2350 Cortex-M33"),
    MCUInfo("rp2040",    "RP2040",   "arm", "16", "cortex-m0",  True, 0x10000000, 0x20000000, "RP2040 Cortex-M0+"),

    # ── AVR ────────────────────────────────────────────────────────────────────
    MCUInfo("atmega328", "ATmega328","avr",  "8",  None,        False, 0x00000000, 0x00800100, "AVR ATmega328 (Arduino Uno)"),
    MCUInfo("atmega",    "ATmega",   "avr",  "8",  None,        False, 0x00000000, 0x00800100, "AVR ATmega"),
    MCUInfo("attiny",    "ATtiny",   "avr",  "8",  None,        False, 0x00000000, 0x00800060, "AVR ATtiny"),
    MCUInfo("avr",       "AVR",      "avr",  "8",  None,        False, 0x00000000, 0x00800100, "AVR (generic)"),

    # ── TI ─────────────────────────────────────────────────────────────────────
    MCUInfo("msp430",    "MSP430",   "msp430","16",None,        False, 0x00004400, 0x00000200, "TI MSP430"),
    MCUInfo("tm4c",      "TM4C",     "arm", "16", "cortex-m4",  True, 0x00000000, 0x20000000, "TI TM4C Stellaris Cortex-M4F"),
    MCUInfo("cc2640",    "CC2640",   "arm", "16", "cortex-m3",  True, 0x00000000, 0x20000000, "TI CC2640 Cortex-M3"),
    MCUInfo("cc26",      "CC26xx",   "arm", "16", "cortex-m3",  True, 0x00000000, 0x20000000, "TI CC26xx Cortex-M3"),
    MCUInfo("cc32",      "CC32xx",   "arm", "16", "cortex-m4",  True, 0x00000000, 0x20000000, "TI CC32xx Cortex-M4"),

    # ── Infineon / Cypress ─────────────────────────────────────────────────────
    MCUInfo("psoc6",     "PSoC 6",   "arm", "16", "cortex-m4",  True, 0x10000000, 0x08000000, "Infineon PSoC6 Cortex-M4"),
    MCUInfo("psoc4",     "PSoC 4",   "arm", "16", "cortex-m0",  True, 0x00000000, 0x20000000, "Infineon PSoC4 Cortex-M0"),
    MCUInfo("xmc4",      "XMC4xxx",  "arm", "16", "cortex-m4",  True, 0x08000000, 0x20000000, "Infineon XMC4xxx Cortex-M4"),
    MCUInfo("xmc1",      "XMC1xxx",  "arm", "16", "cortex-m0",  True, 0x10001000, 0x20000000, "Infineon XMC1xxx Cortex-M0"),

    # ── Renesas ────────────────────────────────────────────────────────────────
    MCUInfo("ra6",       "RA6",      "arm", "16", "cortex-m4",  True, 0x00000000, 0x20000000, "Renesas RA6 Cortex-M4"),
    MCUInfo("ra4",       "RA4",      "arm", "16", "cortex-m33", True, 0x00000000, 0x20000000, "Renesas RA4 Cortex-M33"),
    MCUInfo("ra",        "RA",       "arm", "16", "cortex-m4",  True, 0x00000000, 0x20000000, "Renesas RA Cortex-M4"),

    # ── Microchip PIC ──────────────────────────────────────────────────────────
    MCUInfo("pic32",     "PIC32",    "mips","32", None,         False, 0x9D000000, 0xA0000000, "Microchip PIC32 MIPS32"),
    MCUInfo("same5",     "SAME5",    "arm", "16", "cortex-m4",  True, 0x00000000, 0x20000000, "Microchip SAME5 Cortex-M4"),
    MCUInfo("samd",      "SAMD",     "arm", "16", "cortex-m0",  True, 0x00000000, 0x20000000, "Microchip SAMD Cortex-M0+"),

    # ── Broadcom / RPi SBC ─────────────────────────────────────────────────────
    MCUInfo("bcm2711",   "BCM2711",  "arm", "64", None,         False, 0x00008000, 0x00000000, "BCM2711 Cortex-A72 (RPi4)"),
    MCUInfo("bcm2837",   "BCM2837",  "arm", "64", None,         False, 0x00008000, 0x00000000, "BCM2837 Cortex-A53 (RPi3)"),
    MCUInfo("bcm2835",   "BCM2835",  "arm", "32", None,         False, 0x00008000, 0x00000000, "BCM2835 ARM1176 (RPi1)"),

    # ── Generic fallbacks ──────────────────────────────────────────────────────
    MCUInfo("cortex-m33","Cortex-M33","arm","16","cortex-m33",  True, 0x00000000, 0x20000000, "ARM Cortex-M33"),
    MCUInfo("cortex-m7", "Cortex-M7","arm","16", "cortex-m7",  True, 0x00000000, 0x20000000, "ARM Cortex-M7"),
    MCUInfo("cortex-m4", "Cortex-M4","arm","16", "cortex-m4",  True, 0x00000000, 0x20000000, "ARM Cortex-M4"),
    MCUInfo("cortex-m3", "Cortex-M3","arm","16", "cortex-m3",  True, 0x00000000, 0x20000000, "ARM Cortex-M3"),
    MCUInfo("cortex-m0", "Cortex-M0","arm","16", "cortex-m0",  True, 0x00000000, 0x20000000, "ARM Cortex-M0"),
    MCUInfo("cortex-a",  "Cortex-A", "arm","32", None,         False, 0x80000000, 0x80000000, "ARM Cortex-A (generic)"),
    MCUInfo("riscv",     "RISC-V",   "riscv","32",None,        False, 0x20000000, 0x80000000, "RISC-V 32-bit generic"),
    MCUInfo("xtensa",    "Xtensa",   "xtensa","32",None,       False, 0x40000000, 0x3FFE8000, "Xtensa (generic)"),
    MCUInfo("x86_64",    "x86-64",   "x86","64", None,         False, 0x00400000, 0x00000000, "x86-64"),
    MCUInfo("x86",       "x86",      "x86","32", None,         False, 0x00400000, 0x00000000, "x86 32-bit"),
    MCUInfo("arm64",     "ARM64",    "arm","64", None,         False, 0x40000000, 0x40000000, "AArch64 generic"),
    MCUInfo("arm",       "ARM",      "arm","32", None,         False, 0x00000000, 0x20000000, "ARM 32-bit generic"),
]


def resolve_mcu(name: str) -> MCUInfo | None:
    """Match user-supplied controller name to MCUInfo. Returns None if no match."""
    key = name.lower().replace("-", "").replace("_", "").replace(" ", "")
    for mcu in _MCU_DB:
        mcu_key = mcu.key.replace("-", "").replace("_", "")
        if mcu_key in key:
            return mcu
    return None


_GENERIC_ARM_CORTEX_M = MCUInfo(
    "cortex-m", "Cortex-M (generic)", "arm", "16", "cortex-m4",
    True, 0x08000000, 0x20000000, "ARM Cortex-M generic fallback",
)

def resolve_mcu_or_default(name: str, os_type: str) -> MCUInfo:
    """Resolve MCU; fall back to a sensible default based on OS type."""
    mcu = resolve_mcu(name)
    if mcu:
        return mcu
    # Bare-metal MCU hints: if user typed something unknown, guess Cortex-M
    if os_type == "BAREMETAL":
        return _GENERIC_ARM_CORTEX_M
    # RTOS on unknown controller — still Cortex-M as most common
    return _GENERIC_ARM_CORTEX_M

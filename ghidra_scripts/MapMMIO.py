# MapMMIO.py — Ghidra headless script
# Maps peripheral base address references (MMIO map) for baremetal targets.
# Identifies memory-mapped I/O regions accessed in the code.
#
# Usage: -postScript MapMMIO.py <output_dir>
# Output: <output_dir>/MapMMIO.json

import json
import os

from ghidra.program.model.address import AddressSet
from ghidra.util.task import ConsoleTaskMonitor


# Known peripheral base address ranges for common MCU families
PERIPHERAL_RANGES = [
    # STM32 (APB1/APB2/AHB peripherals)
    (0x40000000, 0x40007FFF, "STM32_APB1", "TIM/USART/SPI/I2C/CAN"),
    (0x40010000, 0x40015FFF, "STM32_APB2", "EXTI/GPIO/SPI1/USART1/ADC"),
    (0x40020000, 0x4007FFFF, "STM32_AHB1", "DMA/RCC/Flash/CRC"),
    (0x48000000, 0x4800FFFF, "STM32_AHB2", "GPIO(L4)"),
    (0x50000000, 0x5007FFFF, "STM32_AHB2B", "USB/RNG/AES"),
    # Nordic nRF5x
    (0x40000000, 0x4001FFFF, "nRF_APB",  "POWER/CLOCK/RADIO/UART/SPI/TWI"),
    # NXP LPC
    (0x40000000, 0x4003FFFF, "LPC_APB0", "SysTick/UART/SPI/I2C"),
    # Cortex-M system peripherals
    (0xE0000000, 0xE00FFFFF, "CorePeripherals", "SysTick/NVIC/SCB/DWT/ITM"),
    (0xE000E000, 0xE000EFFF, "NVIC_SCB",  "NVIC/SysTick/SCB"),
    # Generic AHB/APB
    (0x20000000, 0x2FFFFFFF, "SRAM",     "On-chip SRAM"),
    (0x60000000, 0x9FFFFFFF, "ExtMemory", "External/Flash interface"),
]


def _find_peripheral(addr_int):
    for base, end, name, desc in PERIPHERAL_RANGES:
        if base <= addr_int <= end:
            return name, desc
    return None, None


def run():
    args = getScriptArgs()
    out_dir = args[0] if args else "/tmp/ghidra_out"
    out_file = os.path.join(out_dir, "MapMMIO.json")

    program = currentProgram
    listing = program.getListing()
    mon = ConsoleTaskMonitor()

    mmio_regions = []
    seen_addrs = set()

    # Iterate all data references to peripheral address ranges
    ref_mgr = program.getReferenceManager()
    for block in program.getMemory().getBlocks():
        if not block.isInitialized():
            continue
        # Scan instructions for pointer-sized constants that fall in peripheral ranges
        addr = block.getStart()
        end  = block.getEnd()
        instr_iter = listing.getInstructions(addr, True)
        for instr in instr_iter:
            if monitor.isCancelled():
                break
            if instr.getAddress().compareTo(end) > 0:
                break
            # Check each scalar operand
            for i in range(instr.getNumOperands()):
                try:
                    scalars = instr.getScalar(i)
                    if scalars is None:
                        continue
                    val = scalars.getUnsignedValue()
                    pname, pdesc = _find_peripheral(val)
                    if pname and val not in seen_addrs:
                        seen_addrs.add(val)
                        mmio_regions.append({
                            "address":    hex(val),
                            "peripheral": pname,
                            "description": pdesc,
                            "referenced_at": str(instr.getAddress()),
                            "evidence": "%s @ %s references %s (%s)" % (
                                str(instr.getAddress()), instr.toString(), pname, pdesc),
                        })
                except Exception:
                    pass

    try:
        with open(out_file, "w") as fh:
            json.dump({"mmio_regions": mmio_regions}, fh)
        println("MapMMIO: %d MMIO references → %s" % (len(mmio_regions), out_file))
    except Exception as e:
        println("MapMMIO error: " + str(e))


run()

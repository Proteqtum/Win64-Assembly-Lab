#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# @file        generate_hashes.py
# @brief       Pre-computation script for API name and module hashing
# @author      Lukas 'RubberDuck' Cizmar (https://proteqtum.com)
# @date        2026
#
# @note        Simulates assembly hashing logic (ROR13, DJB2, CRC32C)
#              and generates the 'hashes.h' header file.
#
# @license     MIT License
# ============================================================================

import sys

def ror32(val, count):
    return ((val & 0xFFFFFFFF) >> count) | ((val << (32 - count)) & 0xFFFFFFFF)

def calculate_asm_hash(strToHash, algo, ignoreCase=False):
    if ignoreCase:
        strToHash = strToHash.lower()

    # initialize the accumulator register (EAX) based on the algo
    if algo == "DJB2":
        eax = 5381
    elif algo == "CRC32C":
        eax = 0
    else:  # ROR13
        eax = 0

    for char in strToHash:
        # ASM code strips the upper byte of WCHAR/ANSI via movzx/char loading
        ebx = ord(char) & 0xFF  

        if algo == "DJB2":
            # 'imul eax, 33'
            eax = (eax * 33) & 0xFFFFFFFF
            eax = (eax + ebx) & 0xFFFFFFFF       
        elif algo == "CRC32C":
            for _ in range(8):
                if (eax ^ ebx) & 1:
                    eax = ((eax >> 1) ^ 0x82F63B78) & 0xFFFFFFFF
                else:
                    eax = (eax >> 1) & 0xFFFFFFFF
                ebx >>= 1 
        else:  # ROR13
            eax = ror32(eax, 13)
            eax = (eax + ebx) & 0xFFFFFFFF

    return eax

def generate_header(algo):
    """Generates C header file with pre-computed hashes."""

    modules = ["kernel32.dll", "ntdll.dll", "advapi32.dll"]
    
    functions = ["VirtualAlloc", "VirtualProtect", "NtAllocateVirtualMemory", "NtProtectVirtualMemory"]
    
    filename = "hashes.h"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("// ========================================================\n")
        f.write(f"// AUTOMATICALLY GENERATED (Active algo: {algo})\n")
        f.write("// ========================================================\n\n")
        f.write("#ifndef CONFIG_HASHES_H\n")
        f.write("#define CONFIG_HASHES_H\n\n")
        
        f.write("// MODULES (PEB Resolution - Case-Insensitive)\n")
        for mod in modules:
            h = calculate_asm_hash(mod, algo, ignoreCase=True)
            macro_name = f"HASH_{mod.replace('.', '_').upper()}"
            f.write(f"#define {macro_name:<30} 0x{h:08X} // \"{mod}\"\n")
            
        f.write("\n// FUNCTIONS (EAT Resolution - Case-Sensitive) \n")
        for func in functions:
            h = calculate_asm_hash(func, algo, ignoreCase=False)
            macro_name = f"HASH_{func.upper()}"
            f.write(f"#define {macro_name:<30} 0x{h:08X} // \"{func}\"\n")
            
        f.write("\n#endif // CONFIG_HASHES_H\n")
    
    print(f"[+] Successfully generated: '{filename}' using {algo} logic.")

if __name__ == "__main__":
    selected_algo = sys.argv[1].upper() if len(sys.argv) > 1 else "CRC32C"
    if selected_algo not in ["ROR13", "DJB2", "CRC32C"]:
        selected_algo = "ROR13"
        
    generate_header(selected_algo)

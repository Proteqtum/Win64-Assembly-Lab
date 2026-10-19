# Modular PE/COFF Dynamic API Resolver (Object Library)

The following code serves as study material for Blue Team analysts and reverse engineers to test the robustness of EDR systems against techniques that eliminate the Import Address Table (IAT).

The module is designed as a standalone static object library (.obj / .o). Developers and analysts can link it directly into their own C/C++ projects and test utilities without needing to carry over the assembly source code.

> Disclaimer and Ethical Use: This repository contains educational materials and functional proof-of-concept demonstrations intended solely for authorized security research, red team training, and defensive engineering. Unauthorized targeting or misuse of systems without explicit written consent is strictly prohibited.

### Hashing Algorithm Selection

The hashing engine supports three hashing modes. The choice of algorithm is entirely up to the user. All three modes return 32-bit values.

- **ROR13:**
- **DJB2:** Uses multiplication by the constant 33 via the `imul` instruction.
- **CRC32C:** Hardware-based computation using the SSE4.2 `crc32` instruction.

## Integration and Static Linking

The library is compiled independently of the target program. The resulting OBJ file can be linked with C code or any other compatible project.

### Pre-compilation and Hash Generation

Before compilation, hashes must be generated for the target modules and API functions. This is handled by the `generate_hashes.py` script, which simulates the assembler's hashing logic and produces a `hashes.h` header file.

```bash
# Generate .h file with hashes for ROR13
python3 generate_hashes.py

# Generate .h file with hashes for DJB2
python3 generate_hashes.py DJB2

# Generate .h file with hashes for CRC32C
python3 generate_hashes.py CRC32C
```

### Compiling the Object Library (MinGW-w64 example)

```bash
# Generate object file for ROR13 mode
nasm -f win64 api_hashing.asm -o api_hashing.o

# Generate object file for DJB2 mode
nasm -f win64 -dUSE_DJB2 api_hashing.asm -o api_hashing.o

# Generate object file for CRC32C mode
nasm -f win64 -dUSE_CRC32C api_hashing.asm -o api_hashing.o
```

### Usage in C Code

In your C project, simply include the header file containing the function prototypes and hash macros:

```c
#include "api_hashing.h"
#include "hashes.h" // Generated via helper script

void DemonstrateResolution() {
    // Locate kernel32.dll by hash via PEB
    HMODULE hKernel32 = (HMODULE)GetModuleBaseViaPeb(HASH_KERNEL32_DLL);
    // Locate the VirtualAlloc Windows API function by hash
    FARPROC pVirtualAlloc = GetProcAddressViaHash(hKernel32, HASH_VIRTUALALLOC);
    
    // Further code based on the resolved VirtualAlloc address
}
```

### Linking the Final Project

```bash
# Link with the object in ROR13 mode
x86_64-w64-mingw32-gcc main.c api_hashing.o -o emulation_suite.exe

# Link with the object in DJB2 mode
x86_64-w64-mingw32-gcc main.c api_hashing.o -DUSE_DJB2 -o emulation_suite.exe

# Link with the object in CRC32C mode
x86_64-w64-mingw32-gcc main.c api_hashing.o -DUSE_CRC32C -o emulation_suite.exe
```

### Using the Makefile

A Makefile is provided for quick compilation during testing.

```bash
# Build all three configurations at once (3 separate .exe files)
make

# Build a single specific configuration, e.g. CRC32C
make crc32c

# Clean the working directory
make clean
```

## Integration with High-Level Languages (Rust, C, Go)

Since the library compiles into a standard COFF object, it can also be linked into other languages via their Foreign Function Interface (FFI) or native compilation pipelines.

> **WARNING!**
> **Keep two technical constraints in mind before starting:**
> 1. The object code is strictly for **Windows x64**, i.e. `x86_64`.
> 2. The internal functions use the **Microsoft x64 Calling Convention** (`ms_abi` / `win64`). When compiling on Windows with MSVC or MinGW, this is handled automatically. When cross-compiling from Linux, however, you must explicitly instruct the compiler to use Windows register mapping. Otherwise, arguments will be passed in the wrong registers (`RDI`/`RSI` instead of `RCX`/`RDX`), causing an immediate crash or a NULL return.

### Rust

Rust lets you enforce the Microsoft x64 convention natively. Declare the functions in an `extern "win64"` block.

```rust
use std::ffi::c_void;

extern "win64" {
    fn GetModuleBaseViaPeb(module_hash: u32) -> *mut c_void;
    fn GetProcAddressViaHash(module_base: *mut c_void, function_hash: u32) -> *mut c_void;
}

fn main() {
    unsafe {
        let hash_kernel32: u32 = 0x8FECD63F; // ROR13 hash
        let hash_virtual_alloc: u32 = 0x91AFCA54; // ROR13 hash

        println!("[*] Resolving kernel32.dll via PEB (Hash: 0x{:08X})...", hash_kernel32);
        let h_kernel32 = GetModuleBaseViaPeb(hash_kernel32);
        
        if h_kernel32.is_null() {
            eprintln!("[-] Failed to locate kernel32.dll base address.");
            return;
        }
        println!("[+] Successfully located kernel32.dll: {:?}", h_kernel32);

        println!("[*] Resolving VirtualAlloc via EAT (Hash: 0x{:08X})...", hash_virtual_alloc);
        let p_virtual_alloc = GetProcAddressViaHash(h_kernel32, hash_virtual_alloc);
        
        if p_virtual_alloc.is_null() {
            eprintln!("[-] Failed to resolve VirtualAlloc from Export Address Table.");
            return;
        }
        
        println!("[+] Successfully resolved VirtualAlloc: {:?}", p_virtual_alloc);
        println!("[+] API Runtime Resolution completed successfully.");
    }
}
```

### Pure C (no .H file)

When using the provided `api_hashing.h` header, the calling convention is handled automatically by internal macros.

When declaring prototypes manually inside a `.c` file while cross-compiling on Linux with MinGW-w64 GCC, you must explicitly add the `__attribute__((ms_abi))` modifier. This forces GCC to use Windows register mapping instead of the default Linux registers.

```c
#include <stdio.h>
#include <windows.h>

__attribute__((ms_abi)) extern void* GetModuleBaseViaPeb(unsigned int module_hash);
__attribute__((ms_abi)) extern void* GetProcAddressViaHash(void* module_base, unsigned int function_hash);

int main() {
    unsigned int hash_kernel32 = 0x8FECD63F;
    unsigned int hash_virtual_alloc = 0x91AFCA54;

    printf("[*] Resolving kernel32.dll via PEB (Hash: 0x%08X)...\n", hash_kernel32);
    void* h_kernel32 = GetModuleBaseViaPeb(hash_kernel32);
    
    if (h_kernel32 == NULL) {
        fprintf(stderr, "[-] Failed to locate kernel32.dll base address.\n");
        return 1;
    }
    printf("[+] Successfully located kernel32.dll: %p\n", h_kernel32);

    printf("[*] Resolving VirtualAlloc via EAT (Hash: 0x%08X)...\n", hash_virtual_alloc);
    void* p_virtual_alloc = GetProcAddressViaHash(h_kernel32, hash_virtual_alloc);
    
    if (p_virtual_alloc == NULL) {
        fprintf(stderr, "[-] Failed to resolve VirtualAlloc from Export Address Table.\n");
        return 1;
    }
    
    printf("[+] Successfully resolved VirtualAlloc: %p\n", p_virtual_alloc);
    printf("[+] API Runtime Resolution completed successfully.\n");

    return 0;
}
```

### Golang

Go handles static object linking via `runtime/cgo`. The compiler automatically selects the Windows calling convention when the target OS is set to Windows.

Compilation requires the `CGO_ENABLED=1` environment variable; without it, Go ignores `.o` files entirely.

```go
package main

import "C"
import (
	"fmt"
	"os"
)

func main() {
	var hashKernel32 uint32 = 0x8FECD63F
	var hashVirtualAlloc uint32 = 0x91AFCA54

	fmt.Printf("[*] Resolving kernel32.dll via PEB (Hash: 0x%08X)...\n", hashKernel32)
	hKernel32 := C.GetModuleBaseViaPeb(C.uint(hashKernel32))

	if hKernel32 == nil {
		fmt.Fprintln(os.Stderr, "[-] Failed to locate kernel32.dll base address.")
		os.Exit(1)
	}
	fmt.Printf("[+] Successfully located kernel32.dll: %v\n", hKernel32)

	fmt.Printf("[*] Resolving VirtualAlloc via EAT (Hash: 0x%08X)...\n", hashVirtualAlloc)
	pVirtualAlloc := C.GetProcAddressViaHash(hKernel32, C.uint(hashVirtualAlloc))

	if pVirtualAlloc == nil {
		fmt.Fprintln(os.Stderr, "[-] Failed to resolve VirtualAlloc from Export Address Table.")
		os.Exit(1)
	}

	fmt.Printf("[+] Successfully resolved VirtualAlloc: %v\n", pVirtualAlloc)
	fmt.Println("[+] API Runtime Resolution completed successfully.")
}
```

## Detection Strategies for Blue Team

When this technique is used, the program's Import Address Table is typically empty, causing traditional static analysis to fail. Defense must therefore rely on internal code analysis and runtime anomaly monitoring.

### 1. Static Detection (YARA)

The following rule searches for specific opcodes from the search loop and GS register access that are characteristic of this particular module.

```yara
rule Win_Object_PEB_EAT_Resolver {
    meta:
        description = "Detects advanced linked modules traversing PEB/EAT manually with polymorphism evasion protection"
        severity = "High"

    strings:
        $peb_gs_polymorphic = { 65 48 8B [1-4] }

        $peb_ldr_traversal = { 48 8B [1-3] 18 48 8B [1-3] 10 }

        $algo_ror13 = { C1 C8 0D } /* ror eax, 13 */
        $algo_djb2  = { 69 C0 21 00 00 00 } /* imul eax, 33 */
        $algo_crc32 = { F2 41 0F 38 F1 } /* crc32 eax, r11b */

    condition:
        uint16(0) == 0x5A4D and 
        ($peb_gs_polymorphic and peb_ldr_traversal) and 
        (1 of ($algo_ror13, $algo_djb2, $algo_crc32))
}
```

### 2. Dynamic Detection (EDR / Telemetry)

- **PEB traversal detection:** Standard applications access InLoadOrderModuleList rarely. If an EDR — for example via Intel PT or anomalous thread behavior detection — observes manual traversal of this list outside the system loader code (ntdll.dll), this is a signal of an attempt at covert memory mapping.
- **Calls from unverified pages:** Resolving addresses via EAT parsing is very often the first step toward allocating executable memory (RWX). EDR systems monitor calls to allocation APIs. If the address that triggered the call resides in a memory region with no valid backing file on disk (so-called unbacked memory), the activity is flagged as malicious.

## Significance for Defensive Analysis

Threat emulation frequently reveals that detection rules built around compiler-specific anomalies — such as those produced by MSVC — fail entirely when the same low-level code is embedded in a non-traditional runtime like Go or Rust, or in raw shellcode. This module allows analysts to test the behavior of memory telemetry (e.g. anomalous jumps outside standard Go routines, or API calls originating from raw assembly) independently of the high-level language in use.

## Notes

**Localization:** The original documentation and research notes were authored in Czech and reviewed with the assistance of AI-based language tools to ensure clarity and accuracy of the English translation.
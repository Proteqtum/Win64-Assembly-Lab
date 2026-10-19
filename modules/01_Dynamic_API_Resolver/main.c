#include <stdio.h>
#include <windows.h>

#include "api_hashing.h"
#include "hashes.h"

typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

#ifdef USE_DJB2
    #define ALGO_NAME "DJB2"
#elif defined(USE_CRC32C)
    #define ALGO_NAME "HARDWARE CRC32C"
#else
    #define ALGO_NAME "ROR13 (DEFAULT)"
#endif

int main() {
    DWORD dwKernel32Hash = 0;
    DWORD dwVirtualAllocHash = 0;
    HMODULE hKernel32 = NULL;
    LPVOID lpMem = NULL;

    printf("====================================================================\n");
    printf("  PE/COFF TELEMETRY SUITE: %s\n", ALGO_NAME);
    printf("====================================================================\n\n");

    printf("[*] Running diagnostics...\n");

    dwKernel32Hash = CalculateStringHash("kernel32.dll", TRUE, FALSE);  // Insensitive
    dwVirtualAllocHash = CalculateStringHash("VirtualAlloc", FALSE, FALSE); // Sensitive

    printf("\t-> KERNEL32.DLL: Macro compile-time: 0x%08X | Runtime calculated: 0x%08X\n", 
           HASH_KERNEL32_DLL, dwKernel32Hash);
    printf("\t-> VIRTUALALLOC: Macro compile-time: 0x%08X | Runtime calculated: 0x%08X\n\n", 
           HASH_VIRTUALALLOC, dwVirtualAllocHash);

    if (HASH_KERNEL32_DLL != dwKernel32Hash || HASH_VIRTUALALLOC != dwVirtualAllocHash) {
        printf("[-] ERROR: Macro constant mismatch. Verification aborted.\n");
        return 1;
    }

    printf("[*] Parsing PEB for kernel32.dll base...\n");
    hKernel32 = (HMODULE)GetModuleBaseViaPeb(HASH_KERNEL32_DLL);

    if (hKernel32 == NULL) {
        printf("[-] ERROR: Module not found in InLoadOrderModuleList.\n");
        return 1;
    }
    printf("[+] SUCCESS: Module located: 0x%p\n\n", hKernel32);

    printf("[*] Parsing EAT for VirtualAlloc...\n");
    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)GetProcAddressViaHash(hKernel32, HASH_VIRTUALALLOC);

    if (pVirtualAlloc == NULL) {
        printf("[-] ERROR: Function not found in export directory tables.\n");
        return 1;
    }
    printf("[+] SUCCESS: Function address resolved: 0x%p\n\n", pVirtualAlloc);

    printf("[*] Executing functional verification test...\n");
    lpMem = pVirtualAlloc(NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (lpMem == NULL) {
        printf("[-] ERROR: Memory allocation failed.\n");
        return 1;
    }

    printf("[+] SUCCESS: Memory region successfully allocated at: 0x%p\n", lpMem);
    printf("--------------------------------------------------------------------\n");

    return 0;
}

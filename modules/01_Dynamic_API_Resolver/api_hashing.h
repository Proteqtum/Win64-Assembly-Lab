/*****************************************************************************
 * @file        api_hashing.h
 * @brief       Modular PE/COFF Dynamic API Resolver
 * @author      Lukas 'RubberDuck' Cizmar (https://proteqtum.com)
 * @date        2026
 *
 * @note        This module is designed for academic research, defensive
 *              testing, and malware analysis evasion studies.
 *
 * @license     MIT License
 *****************************************************************************/

#ifndef API_HASHING_H
#define API_HASHING_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generates a 32-bit hash from the given string (ANSI or UTF-16).
 *
 * @param pString      Pointer to the string (const char* if bIsWchar=FALSE, const wchar_t* if bIsWchar=TRUE).
 * @param bIgnoreCase  If TRUE, converts characters to lowercase before hashing.
 * @param bIsWchar     If TRUE, the string is processed as UTF-16 (wchar_t). If FALSE, as ANSI (char).
 * @return DWORD       The resulting 32-bit hash.
 */

DWORD CalculateStringHash(
    const void* pString,
    BOOL        bIgnoreCase,
    BOOL        bIsWchar
);

/**
 * @brief Resolves the base address of a loaded module in process memory via the PEB (Process Environment Block).
 *
 * @param ModuleHash   32-bit hash of the module name (e.g. hash of "ntdll.dll" or "kernel32.dll").
 *                     NOTE: Module names in the PEB are always compared case-insensitively (bIgnoreCase = TRUE).
 * @return PVOID       Absolute base address of the module in memory (HMODULE / PVOID), or NULL on failure.
 */

PVOID GetModuleBaseViaPeb(
    DWORD ModuleHash
);

/**
 * @brief Replaces the standard GetProcAddress. Resolves a function address from the module's Export Address Table (EAT).
 *
 * @param ModuleBase   Base address of the module containing the target function (e.g. retrieved via GetModuleBaseViaPeb).
 * @param FunctionHash 32-bit hash of the target function name (e.g. hash of "NtAllocateVirtualMemory").
 *                     NOTE: Function names in the EAT are case-sensitive by convention (bIgnoreCase = FALSE).
 * @return PVOID       Absolute pointer to the function, or NULL on failure.
 */

PVOID GetProcAddressViaHash(
    PVOID ModuleBase,
    DWORD FunctionHash
);

#ifdef __cplusplus
}
#endif

#endif // API_HASHING_H

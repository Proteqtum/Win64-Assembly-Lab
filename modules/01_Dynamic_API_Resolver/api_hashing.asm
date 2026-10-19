; ============================================================================
; @file        api_hashing.asm
; @brief       Modular PE/COFF Dynamic API Resolver (Win x64)
; @author      Lukas 'RubberDuck' Cizmar (https://proteqtum.com)
; @date        2026
; 
; @note        Implements custom PEB and EAT traversal using Microsoft x64 
;              calling convention. Supported modes: ROR13, DJB2, CRC32C.
;
; @license     MIT License
; ============================================================================


BITS 64
DEFAULT REL

GLOBAL CalculateStringHash
GLOBAL GetModuleBaseViaPeb
GLOBAL GetProcAddressViaHash

SECTION .text

; ==============================================================================
; DWORD CalculateStringHash(const void* rcx, BOOL rdx, BOOL r8b)
; ==============================================================================
CalculateStringHash:
    xor eax, eax

%ifdef USE_DJB2
    mov eax, 5381
%endif

standalone_hash_loop:
    test r8b, r8b
    jz standalone_load_ansi

    movzx r9d, word [rcx]
    add rcx, 2
    jmp standalone_check_null

standalone_load_ansi:
    movzx r9d, byte [rcx]
    inc rcx

standalone_check_null:
    test r9d, r9d
    jz standalone_done

    test edx, edx
    jz standalone_apply_hash

    lea r10d, [r9d - 'A']
    cmp r10d, 26
    jae standalone_apply_hash

    add r9d, 32

standalone_apply_hash:

%ifdef USE_DJB2
    imul eax, 33
    add eax, r9d
%elifdef USE_CRC32C
    crc32 eax, r9b
%else
    ror eax, 13
    add eax, r9d
%endif

    jmp standalone_hash_loop

standalone_done:
    ret

; ==============================================================================
; PVOID GetModuleBaseViaPeb(DWORD ecx [ModuleHash])
; ==============================================================================
GetModuleBaseViaPeb:
    push rbx
    push rsi
    push r12
    sub rsp, 32

    mov r12d, ecx

    xor eax, eax
    mov al, 0x03
    shl al, 5

    mov rax, [gs:rax]
    mov rax, [rax + 0x18]
    mov rsi, [rax + 0x10]
    mov rbx, rsi

module_loop:
    mov rax, [rsi + 0x30]
    test rax, rax
    jz next_module

    movzx eax, word [rsi + 0x58]
    test eax, eax
    jz next_module

    mov rcx, [rsi + 0x60]
    test rcx, rcx
    jz next_module

    mov rdx, 1
    mov r8b, 1
    call CalculateStringHash

    cmp eax, r12d
    je module_found

next_module:
    mov rsi, [rsi]
    cmp rsi, rbx
    jne module_loop

    xor rax, rax
    jmp end

module_found:
    mov rax, [rsi + 0x30]

end:
    add rsp, 32
    pop r12
    pop rsi
    pop rbx
    ret

; ==============================================================================
; PVOID GetProcAddressViaHash(PVOID rcx [ModuleBase], DWORD edx [FunctionHash])
; COMPACT RECURSIVE - Using clean function calls instead of inline duplication
; ==============================================================================
GetProcAddressViaHash:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r14
    push r15
    sub rsp, 32                 ; Shadow space

    mov rbp, rcx                ; RBP = ModuleBase
    mov r12d, edx               ; R12D = Target FunctionHash

    xor rax, rax
    mov eax, [rbp + 0x3C]       ; EAX = e_lfanew
    add rax, rbp                ; RAX = IMAGE_NT_HEADERS
    
    mov r8d, [rax + 0x88]       ; R8D = Export Directory RVA
    test r8d, r8d               ; Verify if exports exist
    jz not_found
    
    mov r15d, r8d               ; R15 = Start Export RVA
    xor r13, r13
    mov r13d, [rax + 0x8C]      ; R13D = Export Directory Size
    add r13, r15                ; R13 = End Export RVA limit

    add r8, rbp                 ; R8 = Absolute Address of IMAGE_EXPORT_DIRECTORY
    mov r9d, [r8 + 0x18]        ; R9D = NumberOfNames
    test r9d, r9d
    jz not_found

    mov esi, [r8 + 0x20]        ; ESI = AddressOfNames RVA
    add rsi, rbp                ; RSI = Absolute Address of AddressOfNames Table

    mov edi, [r8 + 0x24]        ; EDI = AddressOfNameOrdinals RVA
    add rdi, rbp                ; RDI = Absolute Address of Ordinals Table

    mov r14d, [r8 + 0x1C]       ; R14D = AddressOfFunctions RVA
    add r14, rbp                ; R14 = Absolute Address of Functions Table

    xor rbx, rbx                ; RBX = Name Index = 0

search_loop:
    cmp ebx, r9d                ; All names processed?
    jae not_found
    
    xor rcx, rcx
    mov ecx, [rsi + rbx * 4]
    add rcx, rbp                ; RCX = Absolute char* to function name

    xor rdx, rdx                ; RDX = bIgnoreCase = FALSE
    xor r8b, r8b                ; R8B = bIsWchar = FALSE
    
    push r9                     ; Save volatile NumberOfNames from R9D
    call CalculateStringHash    ; Compute hash for current name (Returns in EAX)
    pop r9                      ; Restore volatile NumberOfNames

    cmp eax, r12d               ; Does computed hash match our target?
    je found

    inc rbx
    jmp search_loop             ; Jump to next iteration

not_found:
    xor rax, rax
    jmp exit

found:
    movzx r11d, word [rdi + rbx * 2]
    mov eax, [r14 + r11 * 4]    ; EAX = Resolved Function RVA

    cmp rax, r15
    jb direct_address
    cmp rax, r13
    jae direct_address

    ; ==========================================================================
    ; RECURSIVE FORWARDER DISPATCHER
    ; ==========================================================================
    add rax, rbp                ; RAX = Absolute pointer to forwarder string
    mov rsi, rax                ; RSI = Forwarder string start

    xor rcx, rcx                ; RCX = Length counter
find_dot:
    mov r11b, byte [rsi + rcx]
    cmp r11b, ''
    je dot_found
    inc rcx
    jmp find_dot

dot_found:
    sub rsp, 272                ; Max path allocation on stack (16-byte aligned)
    mov rdi, rsp
    
    xor r10, r10
copy_dll:
    cmp r10, rcx
    jae dll_copied
    mov r11b, byte [rsi + r10]
    mov [rdi + r10], r11b
    inc r10
    jmp copy_dll

dll_copied:
    mov dword [rdi + rcx], 0x6C6C642E ; Append ".dll"
    mov byte [rdi + rcx + 4], 0       ; Terminate string

    lea r14, [rsi + rcx + 1]          ; R14 = Pointer to forwarded function name string

    ; Calculate Target Module Hash
    mov rcx, rsp
    mov rdx, 1
    xor r8b, r8b
    call CalculateStringHash
    mov r12d, eax                     ; R12D = Target Module Hash

    ; Calculate Target Function Hash
    mov rcx, r14
    xor rdx, rdx
    xor r8b, r8b
    call CalculateStringHash
    mov r14d, eax                     ; R14D = Target Function Hash

    add rsp, 272                      ; Restore stack buffer

    ; Resolve target module base address
    mov ecx, r12d
    call GetModuleBaseViaPeb
    test rax, rax
    jz not_found               ; Target DLL must be loaded

    ; Recursively invoke resolver with updated targets
    mov rcx, rax                ; Argument 1: Target Module Base
    mov edx, r14d               ; Argument 2: Target Function Hash
    call GetProcAddressViaHash
    jmp exit

direct_address:
    add rax, rbp                ; RAX = Absolute Virtual Address (VA)

exit:
    add rsp, 32                 ; Restore shadow space
    pop r15
    pop r14
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret

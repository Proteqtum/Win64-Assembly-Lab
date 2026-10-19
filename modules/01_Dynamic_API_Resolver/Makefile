# ============================================================================
# @file        Makefile
# @brief       Build automation for the api_hashing emulation suite
# @author      Lukas 'RubberDuck' Cizmar (https://proteqtum.com)
# @date        2026
# 
# @note        Requires x86_64-w64-mingw32-gcc and nasm.
#              Targets: all, ror13, djb2, crc32c, clean
#
# @license     MIT License
# ============================================================================


# Compilers and tools definition
CC      = x86_64-w64-mingw32-gcc
ASM     = nasm
PYTHON  = python3
RM      = rm -f

# Source and object definitions
ASM_SRC = api_hashing.asm
ASM_OBJ = api_hashing.o
C_SRC   = main.c
HEADER  = hashes.h

# Output binaries definitions
BIN_ROR13  = test_suite_ror13.exe
BIN_DJB2   = test_suite_djb2.exe
BIN_CRC32C = test_suite_crc32c.exe

# Default target: builds all available configurations
all: ror13 djb2 crc32c

# ------------------------------------------------------------------------------
# CONFIGURATION 1: ROR13 (Default fallback logic)
# ------------------------------------------------------------------------------
ror13:
	@echo "[*] Building verification environment for: ROR13"
	$(PYTHON) generate_hashes.py ROR13
	$(ASM) -f win64 $(ASM_SRC) -o $(ASM_OBJ)
	$(CC) $(C_SRC) $(ASM_OBJ) -o $(BIN_ROR13)
	@echo "[+] Successfully generated $(BIN_ROR13)"
	@echo ""

# ------------------------------------------------------------------------------
# CONFIGURATION 2: DJB2 (Imul-driven dynamic hashing)
# ------------------------------------------------------------------------------
djb2:
	@echo "[*] Building verification environment for: DJB2"
	$(PYTHON) generate_hashes.py DJB2
	$(ASM) -f win64 -dUSE_DJB2 $(ASM_SRC) -o $(ASM_OBJ)
	$(CC) $(C_SRC) $(ASM_OBJ) -DUSE_DJB2 -o $(BIN_DJB2)
	@echo "[+] Successfully generated $(BIN_DJB2)"
	@echo ""

# ------------------------------------------------------------------------------
# CONFIGURATION 3: HARDWARE CRC32C (SSE4.2 accelerated execution)
# ------------------------------------------------------------------------------
crc32c:
	@echo "[*] Building verification environment for: HARDWARE CRC32C"
	$(PYTHON) generate_hashes.py CRC32C
	$(ASM) -f win64 -dUSE_CRC32C $(ASM_SRC) -o $(ASM_OBJ)
	$(CC) $(C_SRC) $(ASM_OBJ) -DUSE_CRC32C -o $(BIN_CRC32C)
	@echo "[+] Successfully generated $(BIN_CRC32C)"
	@echo ""

# ------------------------------------------------------------------------------
# CLEANUP: Removes all intermediate objects and compiled binaries
# ------------------------------------------------------------------------------
clean:
	@echo "[*] Cleaning up build artifacts and temporary files..."
	$(RM) $(ASM_OBJ) $(HEADER) $(BIN_ROR13) $(BIN_DJB2) $(BIN_CRC32C)
	@echo "[+] Workspace is now clean."

.PHONY: all ror13 djb2 crc32c clean

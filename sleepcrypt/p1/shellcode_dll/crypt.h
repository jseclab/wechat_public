#pragma once
#include <Windows.h>
#include "win.h"

VOID Xor(BYTE* buffer, SIZE_T size, BYTE key);
ULONGLONG RoundUp(ULONGLONG numToRound, ULONGLONG multiple);
BOOL Encrypt(pVirtualProtect fnvp, PVOID secadd, SIZE_T size);
BOOL Decrypt(pVirtualProtect fnvp, PVOID secadd, SIZE_T size, DWORD pro);

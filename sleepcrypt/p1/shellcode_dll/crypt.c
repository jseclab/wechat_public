#include "crypt.h"


VOID Xor(BYTE* buffer, SIZE_T size, BYTE key)
{
	for (SIZE_T i = 0; i < size; i++)
		buffer[i] ^= key;
}

ULONGLONG RoundUp(ULONGLONG numToRound, ULONGLONG multiple)
{
	return (numToRound + multiple - 1) & -multiple;
}

BOOL Encrypt(pVirtualProtect fnvp, PVOID secadd, SIZE_T size)
{
	DWORD oldPro = 0;
	DWORD ret = 0;
	ret = fnvp(secadd, size, PAGE_READWRITE, &oldPro);

	if (!ret)
		return FALSE;

	Xor((BYTE*)secadd, size, 0x89);
	return TRUE;
}

BOOL Decrypt(pVirtualProtect fnvp, PVOID secadd, SIZE_T size, DWORD pro)
{
	DWORD oldPro = 0;
	DWORD ret = 0;

	Xor((BYTE*)secadd, size, 0x89);
	ret = fnvp(secadd, size, pro, &oldPro);

	if (!ret)
		return FALSE;

	return TRUE;
}

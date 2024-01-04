#include "hash.h"
#include "win.h"
#include "ntdll.h"

PVOID fnGetModuleAddr(INT32 ModuleHash) {
	HMODULE               image_base = NULL;
	PPEB                  peb = NULL;
	PLIST_ENTRY           header = NULL;
	PLIST_ENTRY           entry = NULL;
	PLDR_DATA_TABLE_ENTRY ldr = NULL;

	peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	header = &((PEB_LDR_DATA*)(peb->Ldr))->InLoadOrderModuleList;
	entry = header->Flink;

	for (entry; entry != header; entry = entry->Flink)
	{
		ldr = (LDR_DATA_TABLE_ENTRY*)entry;

		if (HashStringMurmurW(ldr->BaseDllName.Buffer) == ModuleHash)
			image_base = ldr->DllBase;
	}

	return image_base;
}

PVOID fnGetProcAddr(PVOID pModuleAddr, INT32 FunctionHash)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleAddr;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleAddr + pImageDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleAddr + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleAddr + pImgExportDir->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleAddr + pImgExportDir->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleAddr + pImgExportDir->AddressOfNameOrdinals);

	for (WORD i = 0; i < pImgExportDir->NumberOfNames; i++)
	{
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleAddr + pdwAddressOfNames[i]);
		if (HashStringMurmurA(pczFunctionName) == FunctionHash)
		{
			return (PBYTE)pModuleAddr + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]];

		}
	}

	return NULL;
}
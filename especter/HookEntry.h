#pragma once

#include <ntddk.h>
#include <wdf.h>

#define MYFUNCOUNT 0xB

// define module load callback pointer
typedef void (*PLOADIMAGENOTIFYROUTINE)(PUNICODE_STRING,HANDLE,PIMAGE_INFO);

// globle notify routin
PLOADIMAGENOTIFYROUTINE g_IsLoadNotifyRoutin = NULL;

// kernel32.dll is loaded and get necessary fun address
extern UINT32 g_KernelDllLoaded;

//
PVOID GetFunAddress(PVOID imagebase, CHAR* funcname);

//
NTSTATUS InitGloableFunction();
extern UINT32 g_MyFunNumber;
extern PVOID g_MyFunAddress[0x10];
extern INT32 g_SvhostHooked;
extern INT32 g_SvhostEntryRva;
extern CHAR g_OldCode[5];
extern CHAR g_NewCode[5];
extern CHAR g_LoadDllA[];
extern CHAR g_ExportFun[];

// shellcode
extern CHAR g_GlobleShellCode[0x320];
extern CHAR g_ShellCodeA[0x17D];
extern CHAR g_ShellCodeB[0x18];

typedef NTSTATUS(*PfnZwQueryInformationProcess) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

PfnZwQueryInformationProcess ZwQueryInformationProcess;

typedef NTSTATUS(*PfnZwProtectVirtualMemory) (
	IN HANDLE hProcess,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG Protect,
	OUT PULONG OldProtect
	);

PfnZwProtectVirtualMemory ZwProtectVirtualMemory;

typedef NTSTATUS(*pfnZwQuerySection)(
	_In_ HANDLE SectionHandle,
	_In_ SECTION_INFORMATION_CLASS SectionInformationClass,
	_Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation,
	_In_ SIZE_T SectionInformationLength,
	_Out_opt_ PSIZE_T ReturnLength
);

pfnZwQuerySection ZwQuerySection;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation,
	SectionRelocationInformation, // name:wow64:whNtQuerySection_SectionRelocationInformation
	SectionOriginalBaseInformation, // PVOID BaseAddress
	MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

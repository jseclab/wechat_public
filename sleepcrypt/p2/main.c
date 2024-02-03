#include <Windows.h>
#include <subauth.h>
#include <stdio.h>

DWORD WINAPI QueueApcThread( LPVOID EvtHandle )
{
    WaitForSingleObjectEx(GetCurrentProcess(), INFINITE, TRUE);
    return 0;
}

VOID NTAPI WaitEventApc( _In_ ULONG_PTR Evthandle )
{
    WaitForSingleObjectEx((HANDLE)Evthandle, INFINITE, FALSE);
}

VOID SleepOb(PVOID ImageBase, DWORD Size, DWORD TimeOut)
{
    PVOID       SystemFunction040   =       NULL;
    PVOID       SystemFunction041   =       NULL;
    PVOID       RtlDispatchAPC      =       NULL;
    PVOID       NtContinue          =       NULL;
    HANDLE      ThreadHd            =       NULL;
    HANDLE      StartEvtHd          =       NULL;
    HANDLE      EndEvtHd            =       NULL;
    HMODULE     NtdllHd             =       NULL;
    HMODULE     CryptHd             =       NULL;
    DWORD       OldPt               =        0;

    CONTEXT     Ctx = { 0 }, Vp = { 0 }, Enc = { 0 }, Slp = { 0 }, Dec = { 0 }, EndEvt = { 0 }, Vp1 = { 0 };

    NtdllHd = GetModuleHandleA("ntdll");
    CryptHd = LoadLibraryA("CryptBase");

    if (!NtdllHd || !CryptHd)
        return;

    SystemFunction040 = GetProcAddress(CryptHd, "SystemFunction040");
    SystemFunction041 = GetProcAddress(CryptHd, "SystemFunction041");
    RtlDispatchAPC    = GetProcAddress(NtdllHd, (LPCSTR)8);
    NtContinue        = GetProcAddress(NtdllHd, "NtContinue");

    StartEvtHd = CreateEventA(NULL, TRUE, FALSE, NULL);
    EndEvtHd   = CreateEventA(NULL, TRUE, FALSE, NULL);

    if (!StartEvtHd || !EndEvtHd)
        return;

    DWORD ThreadId = 0;
    ThreadHd = CreateThread(NULL, 0, QueueApcThread, NULL, 0, &ThreadId);

    if (!ThreadHd)
        return;

    QueueUserAPC((PAPCFUNC)RtlCaptureContext, ThreadHd, (ULONG_PTR)&Ctx);
    QueueUserAPC(WaitEventApc, ThreadHd, (ULONG_PTR)StartEvtHd);

    Sleep(0x32);

    memcpy_s(&Vp,     sizeof(CONTEXT), &Ctx, sizeof(CONTEXT));
    memcpy_s(&Enc,    sizeof(CONTEXT), &Ctx, sizeof(CONTEXT));
    memcpy_s(&Slp,    sizeof(CONTEXT), &Ctx, sizeof(CONTEXT));
    memcpy_s(&Dec,    sizeof(CONTEXT), &Ctx, sizeof(CONTEXT));
    memcpy_s(&Vp1,    sizeof(CONTEXT), &Ctx, sizeof(CONTEXT));
    memcpy_s(&EndEvt, sizeof(CONTEXT), &Ctx, sizeof(CONTEXT));

    Vp.Rip  =  (ULONG_PTR)VirtualProtect;
    Vp.Rcx  =  (ULONG_PTR)ImageBase;
    Vp.R8   =  PAGE_READWRITE;
    Vp.R9   =  (ULONG_PTR)&OldPt;
    Vp.Rdx  =  Size;
    Vp.Rsp  -= 0x8;
    QueueUserAPC((PAPCFUNC)NtContinue, ThreadHd, (ULONG_PTR)&Vp);

    Enc.Rip =  (ULONG_PTR)SystemFunction040;
    Enc.Rcx =  (ULONG_PTR)ImageBase;
    Enc.Rdx =  Size;
    Enc.R8  =  0;
    Enc.Rsp -= 0x8;
    QueueUserAPC((PAPCFUNC)NtContinue, ThreadHd, (ULONG_PTR)&Enc);

    Slp.Rip = (ULONG_PTR)WaitForSingleObjectEx;
    Slp.Rcx = (ULONG_PTR)GetCurrentProcess();
    Slp.Rdx = TimeOut;
    Slp.R8 = FALSE;
    Slp.Rsp -= 0x8;
    QueueUserAPC((PAPCFUNC)NtContinue, ThreadHd, (ULONG_PTR)&Slp);

    Dec.Rip = (ULONG_PTR)SystemFunction041;
    Dec.Rcx = (ULONG_PTR)ImageBase;
    Dec.Rdx = Size;
    Dec.R8 = 0;
    Dec.Rsp -= 0x8;
    QueueUserAPC((PAPCFUNC)NtContinue, ThreadHd, (ULONG_PTR)&Dec);

    Vp1.Rip = (ULONG_PTR)VirtualProtect;
    Vp1.Rcx = (ULONG_PTR)ImageBase;
    Vp1.R8 = PAGE_EXECUTE_READ;
    Vp1.R9 = (ULONG_PTR)&OldPt;
    Vp1.Rdx = Size;
    Vp1.Rsp -= 0x8;
    QueueUserAPC((PAPCFUNC)NtContinue, ThreadHd, (ULONG_PTR)&Vp1);

    EndEvt.Rip = (ULONG_PTR)SetEvent;
    EndEvt.Rcx = (ULONG_PTR)EndEvtHd;
    EndEvt.Rsp -= 0x8;
    QueueUserAPC((PAPCFUNC)NtContinue, ThreadHd, (ULONG_PTR)&EndEvt);

    // SetEvent(StartEvtHd);
    // WaitForSingleObject(EndEvtHd, INFINITE);
    SignalObjectAndWait(StartEvtHd, EndEvtHd, INFINITE, FALSE);
    CloseHandle(ThreadHd);
}

int main() {
    PVOID ImageBase = { 0 };
    ULONG ImageSize = { 0 };

    ImageBase = GetModuleHandleA(NULL);
    ImageSize = ((PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;
  
    do {
        printf("sleeping..\n");
        SleepOb(ImageBase, ImageSize, 1000);
        printf("active..\n");
    } while (TRUE);

    return 0;
}

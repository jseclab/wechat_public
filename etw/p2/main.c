#pragma warning(disable: 4100)
#pragma warning(disable: 4201)
#include <ntifs.h>
#include <ntstrsafe.h>

/*
x nt!PspHostSiloGlobals
*/
#define PSPHOSTSILOGLOBALS_OFFSET 0xD24540

/*
kd> dt nt!_ESERVERSILO_GLOBALS fffff800`3592d540
   +0x000 ObSiloState      : _OBP_SILODRIVERSTATE
   +0x2e0 SeSiloState      : _SEP_SILOSTATE
   +0x310 SeRmSiloState    : _SEP_RM_LSA_CONNECTION_STATE
   +0x360 EtwSiloState     : 0xffffb10e`f8bd2000 _ETW_SILODRIVERSTATE
*/
#define ETWSILOSTAT_OFFSETE 0x360   

/*
点击上面的 EtwSiloState
    [+0x000] Silo             : 0x0 [Type: _EJOB *]
    [+0x008] SiloGlobals      : 0xfffff8003592d540 [Type: _ESERVERSILO_GLOBALS *]
    [+0x010] MaxLoggers       : 0x40 [Type: unsigned long]
    [+0x018] EtwpSecurityProviderGuidEntry [Type: _ETW_GUID_ENTRY]
    [+0x1c0] EtwpLoggerRundown : 0xffffb10ef8b24b40 [Type: _EX_RUNDOWN_REF_CACHE_AWARE * *]
    [+0x1c8] EtwpLoggerContext : 0xffffb10ef8b24d40 [Type: _WMI_LOGGER_CONTEXT * *]
    [+0x1d0] EtwpGuidHashTable [Type: _ETW_HASH_BUCKET [64]]
*/
#define ETWPGUIDHASHTABLE 0x1d0

/*
0: kd> dt nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : Ptr64 Void
*/
#define EPROCESS_PROCESSID_OFFSET 0x440

#define ESERVERSILO_GLOBALS ULONG_PTR  
#define ETW_SILODRIVERSTATE ULONG_PTR  


// 以下内核基地址获取代码修改自 https://www.cnblogs.com/LyShark/p/16770955.html

static PVOID g_KernelBase = 0;
static ULONG g_KernelSize = 0;
static ULONG_PTR g_PspHostSiloGlobals = 0;
static ETW_SILODRIVERSTATE g_EtwSiloDriverState = 0;
static ESERVERSILO_GLOBALS g_EserverSiloGlobals = 0;

NTSYSAPI
NTSTATUS
NTAPI ZwQuerySystemInformation(
    IN ULONG SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength
);

#pragma pack(1)
typedef struct _EPROCESS
{
    UINT8 Reserved[EPROCESS_PROCESSID_OFFSET];
    ULONG_PTR UniqueProcessId;
}EPROCESS;

#pragma pack()

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _ETW_HASH_BUCKET
{
    LIST_ENTRY ListHead[3];
    ULONG_PTR* BucketLock;
}ETW_HASH_BUCKET,*PETW_HASH_BUCKET;

typedef struct _ETW_GUID_ENTRY
{
    LIST_ENTRY GuidList;
    LIST_ENTRY SiloGuidList;
    ULONG_PTR RefCount;
    GUID Guid;
    LIST_ENTRY RegListHead;
}ETW_GUID_ENTRY,*PETW_GUID_ENTRY;

typedef struct _ETW_REG_ENTRY
{
    LIST_ENTRY RegList;                                            
    LIST_ENTRY GroupRegList;                                       
    ETW_GUID_ENTRY* GuidEntry;                                     
    ETW_GUID_ENTRY* GroupEntry;                                    
    union
    {
        struct _ETW_REPLY_QUEUE* ReplyQueue;                                
        struct _ETW_QUEUE_ENTRY* ReplySlot[4];                              
        struct
        {
            VOID* Caller;                                                  
            ULONG SessionId;                                               
        };
    };

    union
    {
        EPROCESS* Process;
        VOID* CallbackContext;                                             
    }Context;
}ETW_REG_ENTRY, * PETW_REG_ENTRY;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemModuleInformation = 0xb,
} SYSTEM_INFORMATION_CLASS;


VOID GuidToString(GUID* guid, PCHAR string) {
    RtlStringCchPrintfA(string, 39,
        "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        guid->Data1, guid->Data2, guid->Data3,
        guid->Data4[0], guid->Data4[1],
        guid->Data4[2], guid->Data4[3],
        guid->Data4[4], guid->Data4[5],
        guid->Data4[6], guid->Data4[7]);
}

PVOID UtilKernelBase(OUT PULONG pSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    PRTL_PROCESS_MODULES pMods = 0;
    PVOID checkPtr = 0;
    UNICODE_STRING routineName;

    if (g_KernelBase != 0)
    {
        if (pSize)
            *pSize = g_KernelSize;
        return g_KernelBase;
    }

    RtlInitUnicodeString(&routineName, L"NtOpenFile");

    checkPtr = MmGetSystemRoutineAddress(&routineName);
    if (checkPtr == 0)
        return 0;

    __try
    {
        status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
        if (bytes == 0)
        {
            DbgPrint("Invalid SystemModuleInformation size\n");
            return 0;
        }

        pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPoolNx, bytes, 'etwm');

        if(pMods)
            RtlZeroMemory(pMods, bytes);

        status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

        if (NT_SUCCESS(status))
        {
            PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

            for (ULONG i = 0; i < pMods->NumberOfModules; i++)
            {
                if (checkPtr >= pMod[i].ImageBase &&
                    checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
                {
                    g_KernelBase = pMod[i].ImageBase;
                    g_KernelSize = pMod[i].ImageSize;
                    if (pSize)
                        *pSize = g_KernelSize;
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }

    if (pMods)
        ExFreePoolWithTag(pMods, 'etwm');
    return g_KernelBase;
}

VOID UnDriver(PDRIVER_OBJECT driver)
{
    DbgPrint(("Uninstall Driver Is OK \n"));
}


BOOLEAN IsAddressValid(PVOID address) {
    BOOLEAN isValid = FALSE;

    if (MmIsAddressValid(address)) {
        __try {
            UCHAR value = *(UCHAR*)address;
            UNREFERENCED_PARAMETER(value);
            isValid = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    return isValid;
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
    DbgPrint((":D :D :D :D :D\n"));

    PULONG ulong = 0;
    UtilKernelBase(ulong);
    DbgPrint("ntoskrnl.exe 模块基址: 0x%p \n", g_KernelBase);
    DbgPrint("模块大小: 0x%p \n", g_KernelSize);

    g_PspHostSiloGlobals = (ULONG_PTR)g_KernelBase + PSPHOSTSILOGLOBALS_OFFSET;

    g_EserverSiloGlobals = g_PspHostSiloGlobals;
    DbgPrint("ESERVERSILO_GLOBALS对象地址: 0x%p \n", g_EserverSiloGlobals);

    g_EtwSiloDriverState = *(ULONG_PTR*)(g_EserverSiloGlobals + ETWSILOSTAT_OFFSETE);
    DbgPrint("ETWSILODRIVERSTATE对象地址: 0x%p \n", g_EtwSiloDriverState);


    ETW_HASH_BUCKET* pEtwpGuidHashTable = (ETW_HASH_BUCKET*)(g_EtwSiloDriverState + ETWPGUIDHASHTABLE);
    
    LIST_ENTRY*  pEntry   = 0;
    LIST_ENTRY*  pFlink   = 0;
    ETW_GUID_ENTRY* pGuidEntry  = 0;
    LIST_ENTRY*  pRegEntry  = 0;
    LIST_ENTRY*  pRegFlink  = 0;
    ETW_REG_ENTRY* pInstanceEntry = 0;
    
    CHAR guidString[40];

    for (INT i = 0; i < 64; i++)
    {

        DbgPrint("----------------------------------- BUCKET[%d] ----------------------------------- \n\n",i);

        for (INT j = 0; j < 3; j++)
        {
            if (0 == j)
            {
                DbgPrint("********************************** Trace Guid Type *********************************** \n\n");
            }
            if (1 == j)
            {
                DbgPrint("********************************** Notification Guid Type **************************** \n\n");
            }
            if (2 == j)
            {
                DbgPrint("********************************** Group Guid Type *********************************** \n\n");
            }

            pEntry = (LIST_ENTRY*)&((ULONG_PTR)pEtwpGuidHashTable[i].ListHead[j].Flink);
            pFlink = pEntry;

            do
            {
                pGuidEntry = (ETW_GUID_ENTRY*)(pFlink->Flink);

                RtlSecureZeroMemory(guidString, sizeof(guidString));
                GuidToString(&pGuidEntry->Guid,guidString);    
                DbgPrint("Providers GUID:%s\n", guidString);

                pRegEntry = (LIST_ENTRY*)&((ULONG_PTR)pGuidEntry->RegListHead.Flink);
                pRegFlink = pRegEntry;
                
                __try {
                    do
                    {
                        if (IsAddressValid(pRegFlink->Flink))
                        {
                            pInstanceEntry = (ETW_REG_ENTRY*)(pRegFlink->Flink);

                            if (IsAddressValid(&pInstanceEntry->Context.Process) && pInstanceEntry->Context.Process != NULL)
                            {
                                if (IsAddressValid(&pInstanceEntry->Context.Process->UniqueProcessId) && pInstanceEntry->Context.Process->UniqueProcessId > 0 && pInstanceEntry->Context.Process->UniqueProcessId < 4294967295)
                                {
                                    DbgPrint(" ======> Instance Pid = %lld \n", pInstanceEntry->Context.Process->UniqueProcessId);
                                }
                            }

                            pRegFlink = pRegFlink->Flink;
                        }

                    } while (pRegFlink->Flink != pRegEntry->Flink);

                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    DbgBreakPoint();
                }

                pFlink = pFlink->Flink;

                DbgPrint("------------------------------------------------- \n");
            } while (pFlink->Flink != pEntry->Flink);
        }
    }

    Driver->DriverUnload = UnDriver;
    return STATUS_SUCCESS;
}
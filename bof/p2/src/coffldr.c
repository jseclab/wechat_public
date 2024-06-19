#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include "coffldr.h"
#include "beacon_compatibility.h"

#if defined(__x86_64__) || defined(_WIN64)
#define PREPENDSYMBOLVALUE "__imp_"
#else
#define PREPENDSYMBOLVALUE "__imp__"
#endif

#pragma warning(disable:4244)

#define ALIGNPAGE 4*1024
#define ALIGN_TO_4K(num) ((num + 4095) & ~4095) //4k对齐

unsigned char* getContents(char* filepath, uint32_t* outsize) {
    FILE* fin = NULL;
    uint32_t fsize = 0;
    size_t readsize = 0;
    unsigned char* buffer = NULL;
    unsigned char* tempbuffer = NULL;

    fin = fopen(filepath, "rb");
    
    if (fin == NULL) {
        return NULL;
    }
    
    fseek(fin, 0, SEEK_END);
    fsize = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    tempbuffer = calloc(fsize, 1);
    
    if (tempbuffer == NULL) 
    {
        fclose(fin);
        return NULL;
    }

    memset(tempbuffer, 0, fsize);
    readsize = fread(tempbuffer, 1, fsize, fin);

    fclose(fin);
    buffer = calloc(readsize, 1);
    
    if (buffer == NULL) 
    {
        free(tempbuffer);
        return NULL;
    }
    
    memset(buffer, 0, readsize);
    memcpy(buffer, tempbuffer, readsize - 1);
    free(tempbuffer);
    *outsize = fsize;
    return buffer;
}

void* getSecHdrPointer(void* content)
{
    if (!content)
        return NULL;

    return (uint8_t*)content + sizeof(coff_file_header_t);
}

char* getStringTable(void* content, coff_file_header_t* filehdr)
{
    return (char*)((char*)content + filehdr->PointerToSymbolTable + filehdr->NumberOfSymbols * sizeof(coff_sym_t));
}

coff_file_header_t* procFileHeader(void* coffdata)
{
    if (coffdata)
        return (coff_file_header_t*)coffdata;
    else
        return NULL;
}

coff_sec_header_t* procSecHeader(void* conffdata, size_t index)
{
    coff_sec_header_t* secHdr = getSecHdrPointer(conffdata);
    
    if (!secHdr)
        return NULL;

    return (coff_sec_header_t*)(secHdr + index);
}

static BOOL starts_with(const char* string, const char* substring) {
    return strncmp(string, substring, strlen(substring)) == 0;
}

BOOL needAddSymValue(coff_sym_t* symPtr)
{
	if (symPtr->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && symPtr->SectionNumber != IMAGE_SYM_UNDEFINED)
		return TRUE;

	if (symPtr->StorageClass == IMAGE_SYM_CLASS_STATIC)
		return TRUE;

	if (symPtr->StorageClass == IMAGE_SYM_CLASS_LABEL)
		return TRUE;

	return FALSE;
}

void* process_symbol(char* symbolstring) {
    void* functionaddress = NULL;
    char localcopy[1024] = { 0 };
    char* locallib = NULL;
    char* localfunc = NULL;
    int tempcounter = 0;
    HMODULE llHandle = NULL;

    strncpy(localcopy, symbolstring, sizeof(localcopy) - 1);
    
    // 内部函数
    if (starts_with(symbolstring, PREPENDSYMBOLVALUE"Beacon") || starts_with(symbolstring, PREPENDSYMBOLVALUE"toWideChar") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"GetProcAddress") || starts_with(symbolstring, PREPENDSYMBOLVALUE"LoadLibraryA") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"GetModuleHandleA") || starts_with(symbolstring, PREPENDSYMBOLVALUE"FreeLibrary") ||
        starts_with(symbolstring, "__C_specific_handler")) 
    {
        if (strcmp(symbolstring, "__C_specific_handler") == 0)
        {
            localfunc = symbolstring;
            return InternalFunctions[29][1];
        }
        else
        {
            localfunc = symbolstring + strlen(PREPENDSYMBOLVALUE);
        }

        for (tempcounter = 0; tempcounter < 30; tempcounter++) {
            if (InternalFunctions[tempcounter][0] != NULL) {
                if (starts_with(localfunc, (char*)(InternalFunctions[tempcounter][0]))) {
                    functionaddress = (void*)InternalFunctions[tempcounter][1];
                    return functionaddress;
                }
            }
        }
    }
    // 外部引用
    else if (strncmp(symbolstring, PREPENDSYMBOLVALUE, strlen(PREPENDSYMBOLVALUE)) == 0) 
    {
        locallib = localcopy + strlen(PREPENDSYMBOLVALUE);
        locallib = strtok(locallib, "$");
        localfunc = strtok(NULL, "$");
        localfunc = strtok(localfunc, "@");
        llHandle = LoadLibraryA(locallib);

        if (llHandle)
            functionaddress = GetProcAddress(llHandle, localfunc);
    }

    return functionaddress;
}


int RunCoff(char* funcName,unsigned char* content,unsigned char* argData,int argSize)
{
	if (content)
	{

		// 文件头
		//showRawHex(content, 0, sizeof(coff_file_header_t));
		coff_file_header_t* coffFileHdr = procFileHeader(content);
		//showFileHeader(coffFileHdr);

		coff_sym_t* symHdr = (coff_sym_t*)(content + coffFileHdr->PointerToSymbolTable);
		size_t	allSection = 0;
		uint32_t* secMapOffset = (uint32_t*)calloc(sizeof(uint32_t*) * (coffFileHdr->NumberOfSections + 1), 1);
		char** secMapPtr = (char**)calloc(sizeof(char*) * (coffFileHdr->NumberOfSections + 1), 1);

		if (secMapOffset == NULL || secMapPtr == NULL)
		{
			printf("[-] Alloc secMap Failed!\n");
			return -1;
		}

		for (uint32_t i = 0; i < coffFileHdr->NumberOfSections; i++)
		{

			// 节头
			//showRawHex(content, sizeof(coff_file_header_t) + sizeof(coff_sec_header_t) * i, sizeof(coff_sec_header_t));
			coff_sec_header_t* secHdr = procSecHeader(content, i);
			//showSecHeader(secHdr);

			// 由于内存统一分配，所以这里记录每个节的偏移，稍后获取节的地址，CoffLoader直接通过VirtualAlloc为每个节分配内存
			secMapOffset[i] = allSection;
			allSection += ALIGN_TO_4K(secHdr->SizeOfRawData);
			// printf("[+] Section #%d: Size = #%d\n\n", i + 1 ,secHdr->SizeOfRawData);

			// 节的原始数据
			// if (secHdr->PointerToRawData > 0 && secHdr->SizeOfRawData > 0)
			// 	showRawHex(content, secHdr->PointerToRawData, secHdr->SizeOfRawData);

			//showLine(0x2d, 99);
		}

		size_t* funcMap = NULL;
		uint32_t funcMapCount = 0;
		void(*foo)(char* in, unsigned long datalen);

		// 额外分配一块内存作为coff的"导入表"/函数映射表
		void* ptrSection = VirtualAlloc(NULL, ALIGN_TO_4K(allSection + 0x1), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (ptrSection)
		{
			size_t i = 0;
			SecureZeroMemory(ptrSection, allSection);

			printf("[+] Alloc Memory For Sections With Size 0x%zx Succeed At Address 0x%p\n", allSection, ptrSection);

			size_t idx = 0;

			for (i = 0; i < coffFileHdr->NumberOfSections; i++)
			{
				coff_sec_header_t* secHdr = procSecHeader(content, i);

				if (secHdr->PointerToRawData != 0)
				{
					memcpy((char*)ptrSection + idx * ALIGNPAGE, content + secHdr->PointerToRawData, secHdr->SizeOfRawData);
					idx++;
				}

				secMapPtr[i] = (char*)ptrSection + secMapOffset[i]; //获取每个节的内存地址
			}

			funcMap = (size_t*)( (char*)ptrSection + allSection ); // 最后添加"导入表"/函数映射表
		}
		else
		{
			free(secMapOffset);
			free(secMapPtr);
			printf("[-] Alloc Memory For All Sections Failed With Error Code %d\n", GetLastError());
			return -1;
		}

		for (uint32_t i = 0; i < coffFileHdr->NumberOfSections; i++)
		{
			coff_sec_header_t* secHdr = procSecHeader(content, i);

			// 
			if (secHdr->PointerToRelocations > 0 && secHdr->NumberOfRelocations > 0)
			{
				coff_reloc_t* relPtr = (coff_reloc_t*)(content + secHdr->PointerToRelocations);

				for (uint32_t j = 0; j < secHdr->NumberOfRelocations; j++)
				{
					//showRawHex(content, secHdr->PointerToRelocations + j * sizeof(coff_reloc_t), sizeof(coff_reloc_t));
					//showRelocation(relPtr);

					if (symHdr[relPtr->SymbolTableIndex].sn.ln.AllZero != 0) //symbol name length < 8
					{
#ifdef  _WIN32
						printf("Symbol Name = %s\n", symHdr[relPtr->SymbolTableIndex].sn.Name);
#ifdef _WIN64			//x64 processor
						if (relPtr->Type == IMAGE_REL_AMD64_ADDR64)
						{
							uint64_t* tarRel = (uint64_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint64_t longOffsetValue = *tarRel;
							uint32_t symValue = 0;

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							*tarRel = (uint64_t)secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + longOffsetValue + symValue;

							printf("[+] Type %d Reloc Sn %d->0x%p To Sn %d->0x%llx\n", IMAGE_REL_AMD64_ADDR64, i + 1, tarRel, symHdr[relPtr->SymbolTableIndex].SectionNumber, *tarRel);
						}
						else if (relPtr->Type == IMAGE_REL_AMD64_ADDR32NB)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;
							uint32_t symValue = 0;
							offsetValue = secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue - ((char*)tarRel + sizeof(uint32_t));

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							offsetValue += symValue;

							if (offsetValue > 0xffffffff)
							{
								free(secMapOffset);
								free(secMapPtr);
								VirtualFree(ptrSection, 0, MEM_RELEASE);
								return -1;
							}

							*tarRel = offsetValue;
							printf("[+] Type %d Reloc Sn %d->0x%p To Sn %d->0x%x\n", IMAGE_REL_AMD64_ADDR32NB, i + 1, tarRel, symHdr[relPtr->SymbolTableIndex].SectionNumber, *tarRel);
						}
						else if (relPtr->Type == IMAGE_REL_AMD64_REL32)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;
							uint32_t symValue = 0;
							offsetValue = secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue - ((char*)tarRel + sizeof(uint32_t));

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							offsetValue += symValue;

							if (offsetValue > 0xffffffff)
							{
								free(secMapOffset);
								free(secMapPtr);
								VirtualFree(ptrSection, 0, MEM_RELEASE);
								return -1;
							}

							*tarRel = offsetValue;
							printf("[+] Type %d Reloc Sn %d->0x%p To Sn %d->0x%x\n", IMAGE_REL_AMD64_ADDR32, i + 1, tarRel, symHdr[relPtr->SymbolTableIndex].SectionNumber, *tarRel);
						}
						else if (relPtr->Type == IMAGE_REL_AMD64_REL32_1)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;
							uint32_t symValue = 0;
							offsetValue = secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue - ((char*)tarRel + sizeof(uint32_t) + 1);

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							offsetValue += symValue;

							if (offsetValue > 0xffffffff)
							{
								free(secMapOffset);
								free(secMapPtr);
								VirtualFree(ptrSection, 0, MEM_RELEASE);
								return -1;
							}

							*tarRel = offsetValue;
							printf("[+] Type %d Reloc Sn %d->0x%p To Sn %d->0x%x\n", IMAGE_REL_AMD64_ADDR32, i + 1, tarRel, symHdr[relPtr->SymbolTableIndex].SectionNumber, *tarRel);
						}
						else if (relPtr->Type == IMAGE_REL_AMD64_REL32_2)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;
							uint32_t symValue = 0;
							offsetValue = secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue - ((char*)tarRel + sizeof(uint32_t) + 2);

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							offsetValue += symValue;

							if (offsetValue > 0xffffffff)
							{
								free(secMapOffset);
								free(secMapPtr);
								VirtualFree(ptrSection, 0, MEM_RELEASE);
								return -1;
							}

							*tarRel = offsetValue;
							printf("[+] Type %d Reloc Sn %d->0x%p To Sn %d->0x%x\n", IMAGE_REL_AMD64_ADDR32, i + 1, tarRel, symHdr[relPtr->SymbolTableIndex].SectionNumber, *tarRel);
						}
						else if (relPtr->Type == IMAGE_REL_AMD64_REL32_3)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;
							uint32_t symValue = 0;
							offsetValue = secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue - ((char*)tarRel + sizeof(uint32_t) + 3);

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							offsetValue += symValue;

							if (offsetValue > 0xffffffff)
							{
								free(secMapOffset);
								free(secMapPtr);
								VirtualFree(ptrSection, 0, MEM_RELEASE);
								return -1;
							}

							*tarRel = offsetValue;
							printf("[+] Type %d Reloc Sn %d->0x%p To Sn %d->0x%x\n", IMAGE_REL_AMD64_ADDR32, i + 1, tarRel, symHdr[relPtr->SymbolTableIndex].SectionNumber, *tarRel);
						}
						else if (relPtr->Type == IMAGE_REL_AMD64_REL32_4)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;
							uint32_t symValue = 0;
							offsetValue = secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue - ((char*)tarRel + sizeof(uint32_t) + 4);

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							offsetValue += symValue;

							if (offsetValue > 0xffffffff)
							{
								free(secMapOffset);
								free(secMapPtr);
								VirtualFree(ptrSection, 0, MEM_RELEASE);
								return -1;
							}

							*tarRel = offsetValue;
							printf("[+] Type %d Reloc Sn %d->0x%p To Sn %d->0x%x\n", IMAGE_REL_AMD64_ADDR32, i + 1, tarRel, symHdr[relPtr->SymbolTableIndex].SectionNumber, *tarRel);
						}
						else if (relPtr->Type == IMAGE_REL_AMD64_REL32_5)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;
							uint32_t symValue = 0;
							offsetValue = secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue - ((char*)tarRel + sizeof(uint32_t) + 5);

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							offsetValue += symValue;

							if (offsetValue > 0xffffffff)
							{
								free(secMapOffset);
								free(secMapPtr);
								VirtualFree(ptrSection, 0, MEM_RELEASE);
								return -1;
							}

							*tarRel = offsetValue;
							printf("[+] Type %d Reloc Sn %d->0x%p To Sn %d->0x%x\n", IMAGE_REL_AMD64_ADDR32, i + 1, tarRel, symHdr[relPtr->SymbolTableIndex].SectionNumber, *tarRel);
						}
						else
							printf("[-] Unknown or Undo For Type %d\n", relPtr->Type);

#else
						// Intel 386 Processors
						if (relPtr->Type == IMAGE_REL_I386_DIR32)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;
							uint32_t symValue = 0;

							// 细化代码，当Value表示在节中的偏移时候才相加
							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							*tarRel = (uint32_t)secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue + symValue;
							printf("[+] Type %d Set Sn %d->0x%p With Value->0x%x\n", IMAGE_REL_I386_DIR32, i + 1, tarRel, *tarRel);

						}

						if (relPtr->Type == IMAGE_REL_I386_REL32)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;
							uint32_t symValue = 0;

							offsetValue = secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue - ((char*)tarRel + sizeof(uint32_t));

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							offsetValue += symValue;

							if (offsetValue > 0xffffffff)
							{
								free(secMapOffset);
								free(secMapPtr);
								VirtualFree(ptrSection, 0, MEM_RELEASE);
								return -1;
							}

							*tarRel = offsetValue;
							printf("[+] Type %d Set Sn %d->0x%p With Value->0x%x\n", IMAGE_REL_I386_DIR32, i + 1, tarRel, *tarRel);
						}

#endif // _WIN64
#endif //  _WIN32
					}
					else
					{
						
						uint32_t strOffset = symHdr[relPtr->SymbolTableIndex].sn.ln.Offset;
						char* symName = (char*)(symHdr + coffFileHdr->NumberOfSymbols) + strOffset;
						void* funcPtr = process_symbol(symName);
						printf("Symbol Name = %s\n", symName);

						if (funcPtr == NULL && symHdr[relPtr->SymbolTableIndex].SectionNumber == 0)
							printf("[-] Fialed To Resolve Symble %s\n", symName);
#ifdef  _WIN32

#ifdef _WIN64
						if (relPtr->Type == IMAGE_REL_AMD64_ADDR64)
						{
							uint64_t* tarRel = (uint64_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint64_t longOffsetValue = *tarRel;

							uint32_t symValue = 0;

							// 细化代码，当Value表示在节中的偏移时候才相加
							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							*tarRel = (uint64_t)secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + longOffsetValue + symValue;

							printf("[+] Type %d Reloc Sn %d->0x%p To Sn %d->0x%llx\n", IMAGE_REL_AMD64_ADDR64, i + 1, tarRel, symHdr[relPtr->SymbolTableIndex].SectionNumber, *tarRel);
						}
						else if (relPtr->Type == IMAGE_REL_AMD64_REL32 && funcPtr != NULL)
						{
							*(funcMap + funcMapCount) = (size_t)funcPtr;
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = (char*)(funcMap + funcMapCount) - ((char*)tarRel + 4);
							uint32_t symValue = 0;

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							*tarRel = offsetValue + symValue;
							funcMapCount++;
							printf("[+] Type %d Reloc Sn %d->0x%p To IAT->0x%x\n", IMAGE_REL_I386_DIR32, i + 1, tarRel, *tarRel);
						}
						else if (relPtr->Type == IMAGE_REL_AMD64_REL32)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;
							uint32_t symValue = 0;
							offsetValue = secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue - ((char*)tarRel + sizeof(uint32_t));

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							offsetValue += symValue;

							if (offsetValue > 0xffffffff)
							{
								free(secMapOffset);
								free(secMapPtr);
								VirtualFree(ptrSection, 0, MEM_RELEASE);
								return -1;
							}

							*tarRel = offsetValue;
							printf("[+] Type %d Reloc Sn %d->0x%p To Sn %d->0x%x\n", IMAGE_REL_AMD64_ADDR32, i + 1, tarRel, symHdr[relPtr->SymbolTableIndex].SectionNumber, *tarRel);
						}
						else if (relPtr->Type == IMAGE_REL_AMD64_ADDR32NB)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;
							uint32_t symValue = 0;
							offsetValue = secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue - ((char*)tarRel + sizeof(uint32_t));

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							offsetValue += symValue;

							if (offsetValue > 0xffffffff)
							{
								free(secMapOffset);
								free(secMapPtr);
								VirtualFree(ptrSection, 0, MEM_RELEASE);
								return -1;
							}

							*tarRel = offsetValue;
							printf("[+] Type %d Reloc Sn %d->0x%p To Sn %d->0x%x\n", IMAGE_REL_AMD64_ADDR32NB, i + 1, tarRel, symHdr[relPtr->SymbolTableIndex].SectionNumber, *tarRel);
						}
						else
							printf("[-] Unknown or Undo For Type %d\n", relPtr->Type);

#else
						if (relPtr->Type == IMAGE_REL_I386_DIR32 && funcPtr != NULL)
						{
							*(funcMap + funcMapCount) = (size_t)funcPtr;
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = (uint32_t)(funcMap + funcMapCount);
							*tarRel = offsetValue;
							funcMapCount++;
							printf("[+] Type %d Set Sn %d->0x%p With Value->0x%x\n", IMAGE_REL_I386_DIR32, i + 1, tarRel, *tarRel);
						}
						else if (relPtr->Type == IMAGE_REL_I386_DIR32)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;

							uint32_t symValue = 0;

							// 细化代码，当Value表示在节中的偏移时候才相加
							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							*tarRel = (uint32_t)secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue + symValue;
							printf("[+] Type %d Set Sn %d->0x%p With Value->0x%x\n", IMAGE_REL_I386_DIR32, i + 1, tarRel, *tarRel);
						}
						else if (relPtr->Type == IMAGE_REL_I386_REL32)
						{
							uint32_t* tarRel = (uint32_t*)(secMapPtr[i] + relPtr->VirtualAddress);
							uint32_t offsetValue = *tarRel;
							uint32_t symValue = 0;

							offsetValue = secMapPtr[symHdr[relPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue - ((char*)tarRel + sizeof(uint32_t));

							if (needAddSymValue(&symHdr[relPtr->SymbolTableIndex]))
								symValue = symHdr[relPtr->SymbolTableIndex].Value;

							offsetValue += symValue;

							if (offsetValue > 0xffffffff)
							{
								free(secMapOffset);
								free(secMapPtr);
								VirtualFree(ptrSection, 0, MEM_RELEASE);
								return -1;
							}

							*tarRel = offsetValue;
							printf("[+] Type %d Set Sn %d->0x%p With Value->0x%x\n", IMAGE_REL_I386_DIR32, i + 1, tarRel, *tarRel);
						}
#endif // _WIN64
#endif //  _WIN32
					}
					relPtr++;
				}
			}
		}

		char* entryFuncname = funcName;

#ifdef _WIN32

#ifndef _WIN64
		entryFuncname = calloc(strlen(funcName) + 2, 1);

		if (entryFuncname == NULL)
		{
			free(secMapOffset);
			free(secMapPtr);
			VirtualFree(ptrSection, 0, MEM_RELEASE);
			return 1;
		}
		sprintf(entryFuncname, "_%s", funcName);
#endif // !_WIN64

#endif // _WIN32

		for (uint32_t i = 0; i < coffFileHdr->NumberOfSymbols; i++)
		{
			if (strcmp(symHdr[i].sn.Name, entryFuncname) == 0)
			{
				printf("[+] Found Entry，Type = %d,StorageClass = %d\n\n", symHdr[i].Type, symHdr[i].StorageClass);
#ifdef  _WIN32
				foo = (void(*)(char*, unsigned long))(secMapPtr[symHdr[i].SectionNumber - 1] + symHdr[i].Value);
				foo(argData, argSize);

#endif //  _WIN32

			}
		}

		// 清理
		VirtualFree(ptrSection, 0, MEM_RELEASE);
#ifdef _WIN32
#ifndef _WIN64
		free(entryFuncname);
#endif // !_WIN64
#endif // _WIN32
		free(secMapOffset);
		free(secMapPtr);
		return 0;
	}

	return -1;
}
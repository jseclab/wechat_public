#include <stdio.h>
#include <string.h>
#include "coffldr.h"
#include "show.h"

void showLine(uint8_t asc, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++)
        printf("%c", asc);

    printf("\n");
}

void showRawHex(void* coffdata, uint32_t offset, uint32_t size)
{
    if (!coffdata || !size)
        return;

    for (uint32_t i = 0, count = 0; i < size; i++, count++)
    {
        if (count >= 16)
        {
            printf("\n");
            count = 0;
        }

        printf("%02x ", *((uint8_t*)coffdata + offset + i));
    }

    printf("\n");
}

void showFileHeader(void* coffhdr)
{
    if (!coffhdr)
        return;

    coff_file_header_t* f = (coff_file_header_t*)coffhdr;

    printf("[+] Machine: %#x\n", f->Machine);
    printf("[+] Number Of Sections: %d\n", f->NumberOfSections);
    printf("[+] Time/Date Stamp: %#x\n", f->TimeDateStamp);
    printf("[+] Pointer To Symbol Table: %#x\n", f->PointerToSymbolTable);
    printf("[+] Number Of Symbols: %d\n", f->NumberOfSymbols);
    printf("[+] Size Of Optional Header: %#x\n", f->SizeOfOptionalHeader);
    printf("[+] Characteristics: %#x\n", f->Characteristics);

    showLine(0x2d, 99);
}

void showSecHeader(void* coffsec)
{
    if (!coffsec)
        return;

    coff_sec_header_t* s = coffsec;

    printf("\tName: %s\n", s->Name);
    printf("\tVirtual Size: %#x\n", s->VirtualSize);
    printf("\tVirtual Address: %#x\n", s->VirtualAddress);
    printf("\tSize Of Raw Data: %d\n", s->SizeOfRawData);
    printf("\tPointer To Raw Data: %#x\n", s->PointerToRawData);
    printf("\tPointer To Relocations: %#x\n", s->PointerToRelocations);
    printf("\tPointer To Line Numbers: %#x\n", s->PointerToLinenumbers);
    printf("\tNumber Of Relocations: %d\n", s->NumberOfRelocations);
    printf("\tNumber Of Line numbers: %d\n", s->NumberOfLinenumbers);
    printf("\tCharacteristics: %#x\n", s->Characteristics);
    
}


void showRelocation(void* coffreloc)
{
    if (!coffreloc)
        return;

    coff_reloc_t* r = coffreloc;

    printf("  VAddress:%#9x  |", r->VirtualAddress);
    printf("  SymTab Index:%#5d  |", r->SymbolTableIndex);
    printf("  Type:%#5x\n", r->Type);
}

void showSymbleTitle()
{
    printf("%#4s  |%#9s     |%#9s  |%#6s  |%#14s |%#7s", "No.", "VALUE", "SECTION", "TYPE", "STORAGE CLASS", "NAME\n");
    return;
}

void showSymble(void* coffsym,char* stringtable,uint32_t index)
{
    if (!coffsym)
        return;

    coff_sym_t* s = (coff_sym_t*)coffsym;
    printf("%#4d  |", index);
    printf("%#12x  |", s->Value);
    printf("%#9x  |", s->SectionNumber);
    printf("%#6.4d  |", s->Type);
    printf("%#13d  |", s->StorageClass);

    if (s->StorageClass == 0)
        printf(" <undefined>");
    else if (s->sn.ln.AllZero != 0)
    {
        char shortName[10] = { 0 };
        memcpy(shortName, s->sn.Name, 8);
        printf(" %s", shortName);
    }
    else
        printf("%s", stringtable + s->sn.ln.Offset);

    printf("\n");
}
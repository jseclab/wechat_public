#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "coffldr.h"

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

coff_sec_header_t* procSecHeader(void* conffdata, uint32_t index)
{
    coff_sec_header_t* secHdr = getSecHdrPointer(conffdata);
    
    if (!secHdr)
        return NULL;

    return (coff_sec_header_t*)(secHdr + index);
}
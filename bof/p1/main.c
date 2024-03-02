#include <stdio.h>
#include "coffldr.h"
#include "show.h"

int main(int argc,char*argv[])
{
	if (argc < 2)
	{
		printf("error args count: %s path/of/obj\n", argv[0]);
		return -1;
	}
	uint32_t coffSize = 0;
	unsigned char* content = getContents(argv[1],&coffSize);

	if (content)
	{

		// file header
		showRawHex(content, 0, sizeof(coff_file_header_t));
		coff_file_header_t* coffFileHdr = procFileHeader(content);
		showFileHeader(coffFileHdr);

		for (uint32_t i = 0; i < coffFileHdr->NumberOfSections; i++)
		{
			printf("[+] Section #%d:\n\n", i + 1);
			// section header
			showRawHex(content, sizeof(coff_file_header_t) + sizeof(coff_sec_header_t) * i, sizeof(coff_sec_header_t));
			coff_sec_header_t* secHdr = procSecHeader(content, i);
			showSecHeader(secHdr);

			// section raw data
			if (secHdr->PointerToRawData > 0 && secHdr->SizeOfRawData > 0)
				showRawHex(content, secHdr->PointerToRawData, secHdr->SizeOfRawData);

			// relocation
			if (secHdr->PointerToRelocations > 0 && secHdr->NumberOfRelocations > 0)
			{
				coff_reloc_t* itr = (
					coff_reloc_t*)( content + secHdr->PointerToRelocations );
				
				for (uint32_t j = 0; j < secHdr->NumberOfRelocations; j++)
				{
					showRawHex(content, secHdr->PointerToRelocations + j * sizeof(coff_reloc_t), sizeof(coff_reloc_t));
					showRelocation(itr);
					itr++;
				}
			}

			showLine(0x2d, 99);
		}

		//symbol table
		if (coffFileHdr->PointerToSymbolTable > 0)
		{
			coff_sym_t* symHdr = (coff_sym_t*)( content + coffFileHdr->PointerToSymbolTable );
			showSymbleTitle();
		
			for (uint32_t i = 0; i < coffFileHdr->NumberOfSymbols; i++)
			{
				// showRawHex(content, coffFileHdr->PointerToSymbolTable + i * sizeof(coff_sym_t), sizeof(coff_sym_t));
				showSymble(symHdr,getStringTable(content, coffFileHdr),i);
				symHdr++;
			}
		}
	}
}
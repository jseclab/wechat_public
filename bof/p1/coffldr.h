#include <stdint.h>

typedef struct coff_file_header {
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader; // should be zero for an object file
	uint16_t Characteristics;
}coff_file_header_t;

typedef struct coff_sec_header {
	char Name[8];
	uint32_t VirtualSize;			// zero for object files.
	uint32_t VirtualAddress;		// compilers should set this to zero
	uint32_t SizeOfRawData;			// When a section contains only uninitialized data, this field should be zero.
	uint32_t PointerToRawData;		// When a section contains only uninitialized data, this field should be zero.
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers; // COFF Line Numbers (Deprecated)
	uint32_t Characteristics;

}coff_sec_header_t;

#pragma pack(push,1)

typedef struct coff_reloc {
	uint32_t VirtualAddress;
	uint32_t SymbolTableIndex;
	uint16_t Type;
}coff_reloc_t;

typedef struct coff_sym {
	union {
		char Name[8];
		struct {
			uint32_t AllZero;
			uint32_t Offset;
		}ln;
	} sn;
	uint32_t Value;
	uint16_t SectionNumber;
	uint16_t Type;				// microsoft tools set this field to 0x20(function) or 0x0(not a function)
	uint8_t StorageClass;
	uint8_t NumberOfAuxSymbols;

} coff_sym_t;

#pragma pack(pop)

unsigned char* getContents(char* filepath, uint32_t* outsize);
void* getSecHdrPointer(void* content);
char* getStringTable(void* content, coff_file_header_t* filehdr);
coff_file_header_t* procFileHeader(void* coffdata);
coff_sec_header_t* procSecHeader(void* conffdata, uint32_t index);
#include "pehelper.h"

BYTE* get_nt_hdrs(BYTE* buffer)
{
	if (!buffer)
		return NULL;

	IMAGE_DOS_HEADER* dh = (IMAGE_DOS_HEADER*)buffer;

	if (dh->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	CONST LONG pe_max_offset = 1024;
	LONG pe_offset = dh->e_lfanew;

	if (pe_offset > pe_max_offset) { return NULL; }

	IMAGE_NT_HEADERS32* nh = (IMAGE_NT_HEADERS32*)(buffer + pe_offset);

	if (nh->Signature != IMAGE_NT_SIGNATURE) { return NULL; }

	return (BYTE*)nh;
}

IMAGE_FILE_HEADER* fetch_file_hdr32(BYTE* payload, IMAGE_NT_HEADERS32* payload_nt_hdr)
{
	if (!payload || !payload_nt_hdr) return NULL;

	IMAGE_FILE_HEADER* fileHdr = &(payload_nt_hdr->FileHeader);

	return fileHdr;
}

IMAGE_FILE_HEADER* fetch_file_hdr64(BYTE* payload, IMAGE_NT_HEADERS64* payload_nt_hdr)
{
	if (!payload || !payload_nt_hdr) return NULL;

	IMAGE_FILE_HEADER* fileHdr = &(payload_nt_hdr->FileHeader);

	return fileHdr;
}

LPVOID fetch_opt_hdr32(BYTE* buffer, IMAGE_NT_HEADERS32* payload_nt_hdr)
{
	if (!buffer) return NULL;

	IMAGE_FILE_HEADER* fileHdr = fetch_file_hdr32(buffer, payload_nt_hdr);

	if (!fileHdr) { return NULL; }

	LPVOID opt_hdr = (LPVOID)&(payload_nt_hdr->OptionalHeader);
	return opt_hdr;
}

LPVOID fetch_opt_hdr64(BYTE* buffer, IMAGE_NT_HEADERS64* payload_nt_hdr)
{
	if (!buffer) return NULL;

	IMAGE_FILE_HEADER* fileHdr = fetch_file_hdr64(buffer, payload_nt_hdr);

	if (!fileHdr) { return NULL; }

	LPVOID opt_hdr = (LPVOID)&(payload_nt_hdr->OptionalHeader);
	return opt_hdr;
}

LPVOID fetch_section_hdrs32_ptr(BYTE* payload, IMAGE_NT_HEADERS32* payload_nt_hdr)
{
	IMAGE_FILE_HEADER* fileHdr = fetch_file_hdr32(payload, payload_nt_hdr);

	if (!fileHdr) { return NULL; }

	size_t opt_size = fileHdr->SizeOfOptionalHeader;

	BYTE* opt_hdr = (BYTE*)fetch_opt_hdr32(payload, payload_nt_hdr);
	//sections headers starts right after the end of the optional header
	return (LPVOID)(opt_hdr + opt_size);
}

LPVOID fetch_section_hdrs64_ptr(BYTE* payload,IMAGE_NT_HEADERS64* payload_nt_hdr)
{
	IMAGE_FILE_HEADER* fileHdr = fetch_file_hdr64(payload, payload_nt_hdr);

	if (!fileHdr) { return NULL; }

	size_t opt_size = fileHdr->SizeOfOptionalHeader;

	BYTE* opt_hdr = (BYTE*)fetch_opt_hdr64(payload, payload_nt_hdr);
	//sections headers starts right after the end of the optional header
	return (LPVOID)(opt_hdr + opt_size);
}

WORD get_nt_hdr_architecture(BYTE* pe_buffer)
{
	void* ptr = get_nt_hdrs(pe_buffer);
	if (!ptr) return 0;

	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)ptr;
	return inh->OptionalHeader.Magic;
}

BOOL is64bit(BYTE* pe_buffer)
{
	WORD arch = get_nt_hdr_architecture(pe_buffer);
	if (arch == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return TRUE;
	}
	return FALSE;
}

IMAGE_FILE_HEADER* get_file_hdr(BYTE* buffer)
{
	if (!buffer) return NULL;

	BYTE* payload_nt_hdr = get_nt_hdrs(buffer);
	if (!payload_nt_hdr) {
		return NULL;
	}
	if (is64bit(buffer)) {
		return fetch_file_hdr64(buffer,(IMAGE_NT_HEADERS64*)payload_nt_hdr);
	}
	return fetch_file_hdr32(buffer, (IMAGE_NT_HEADERS32*)payload_nt_hdr);
}

SIZE_T get_sections_count(BYTE* buffer)
{
	IMAGE_FILE_HEADER* fileHdr = get_file_hdr(buffer);
	if (!fileHdr) {
		return 0;
	}
	return fileHdr->NumberOfSections;
}

PIMAGE_SECTION_HEADER get_section_hdr(BYTE* buffer, size_t section_num)
{
	if (!buffer) return NULL;

	size_t sections_count = get_sections_count(buffer);

	if (section_num >= sections_count) { return NULL; }

	LPVOID nt_hdrs = get_nt_hdrs(buffer);
	if (!nt_hdrs) return NULL; //this should never happened, because the get_sections_count did not fail

	LPVOID secptr = NULL;
	//get the beginning of sections headers:
	if (is64bit(buffer)) {
		secptr = fetch_section_hdrs64_ptr(buffer, (IMAGE_NT_HEADERS64*)nt_hdrs);
	}
	else {
		secptr = fetch_section_hdrs32_ptr(buffer, (IMAGE_NT_HEADERS32*)nt_hdrs);
	}
	//get the section header of given number:
	PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)(
		(ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * section_num)
		);

	return next_sec;
}

DWORD translate_protect(DWORD sec_charact)
{
	if ((sec_charact & IMAGE_SCN_MEM_EXECUTE)
		&& (sec_charact & IMAGE_SCN_MEM_READ)
		&& (sec_charact & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_EXECUTE_READWRITE;
	}
	if ((sec_charact & IMAGE_SCN_MEM_EXECUTE)
		&& (sec_charact & IMAGE_SCN_MEM_READ))
	{
		return PAGE_EXECUTE_READ;
	}
	if (sec_charact & IMAGE_SCN_MEM_EXECUTE)
	{
		return PAGE_EXECUTE_READ;
	}

	if ((sec_charact & IMAGE_SCN_MEM_READ)
		&& (sec_charact & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_READWRITE;
	}
	if (sec_charact & IMAGE_SCN_MEM_READ) {
		return PAGE_READONLY;
	}

	return PAGE_READWRITE;
}
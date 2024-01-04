#pragma once
#include <Windows.h>


BYTE* get_nt_hdrs(BYTE* buffer);
SIZE_T get_sections_count(BYTE* buffer);
DWORD translate_protect(DWORD sec_charact);
PIMAGE_SECTION_HEADER get_section_hdr(BYTE* buffer, size_t section_num);



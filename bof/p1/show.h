#include <stdint.h>
void showLine(uint8_t asc, uint32_t count);
void showRawHex(void* coffdata, uint32_t offset, uint32_t size);
void showFileHeader(void* coffhdr);
void showSecHeader(void* coffsec);
void showRelocation(void* coffreloc);
void showSymbleTitle();
void showSymble(void* coffsym, char* stringtable, uint32_t index);
#include <Windows.h>

SIZE_T StringLengthA(_In_ LPCSTR String);
SIZE_T StringLengthW(_In_ LPCWSTR String);
INT32 HashStringMurmurW(_In_ LPCWSTR String);
INT32 HashStringMurmurA(_In_ LPCSTR String);

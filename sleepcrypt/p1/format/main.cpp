#include <stdio.h>
#include <windows.h>

#pragma warning(disable : 4996)

void write_text_section_to_file(const char* dll_path) {
    HANDLE file = CreateFileA(dll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("Error: Unable to open the file\n");
        return;
    }

    DWORD file_size = GetFileSize(file, NULL);
    BYTE* file_data = (BYTE*)malloc(file_size);

    DWORD bytes_read;
    if (!ReadFile(file, file_data, file_size, &bytes_read, NULL)) {
        printf("Error: Unable to read the file\n");
        CloseHandle(file);
        free(file_data);
        return;
    }
    CloseHandle(file);

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_data;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(file_data + dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)(nt_headers + 1);

    PIMAGE_SECTION_HEADER text_section = NULL;
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (memcmp(section_header->Name, ".text", 5) == 0) {
            text_section = section_header;
            break;
        }
        section_header++;
    }

    if (text_section == NULL) {
        printf("Error: .text section not found\n");
        free(file_data);
        return;
    }

    BYTE* text_data = file_data + text_section->PointerToRawData;
    DWORD text_size = text_section->SizeOfRawData;

    FILE* output_file = fopen("shellcode.bin", "wb");
    if (output_file == NULL) {
        printf("Error: Unable to create shellcode.bin file\n");
        free(file_data);
        return;
    }
    fwrite(text_data, sizeof(BYTE), text_size, output_file);
    fclose(output_file);

    printf("The content of the .text section has been written to shellcode.bin\n");

    free(file_data);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <dll_path>\n", argv[0]);
        return 1;
    }

    write_text_section_to_file(argv[1]);
    return 0;
}
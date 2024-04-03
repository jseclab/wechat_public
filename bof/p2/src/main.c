#include <Windows.h>
#include <stdio.h>
#include "coffldr.h"

unsigned char* unhexlify(unsigned char* value, int* outlen) {
	unsigned char* retval = NULL;
	char byteval[3] = { 0 };
	unsigned int counter = 0;
	int counter2 = 0;
	char character = 0;
	if (value == NULL) {
		return NULL;
	}
	if (strlen((char*)value) % 2 != 0) {
		goto errcase;
	}

	retval = calloc(strlen((char*)value) + 1, 1);
	if (retval == NULL) {
		goto errcase;
	}

	counter2 = 0;
	for (counter = 0; counter < strlen((char*)value); counter += 2) {
		memcpy(byteval, value + counter, 2);
		character = (char)strtol(byteval, NULL, 16);
		memcpy(retval + counter2, &character, 1);
		counter2++;
	}
	*outlen = counter2;

errcase:
	return retval;
}


int main(int argc, char* argv[])
{
	/*
	argv[0]: 执行文件
	argv[1]: coff文件路径
	argv[2]: 入口函数
	argv[3]: 参数
	*/
	if (argc < 2)
	{
		printf("error args count: %s path/to/obj { entry }{ arguments }\n", argv[0]);
		return -1;
	}
	uint32_t coffSize = 0;
	unsigned char* content = getContents(argv[1], &coffSize);
	unsigned char* arguments = NULL;
	int argumentSize = 0;
	arguments = unhexlify((unsigned char*)argv[3], &argumentSize);

	RunCoff(argv[2], content, arguments, argumentSize);
	system("pause");
}
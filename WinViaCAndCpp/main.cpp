#include <Windows.h>
#include <stdio.h>

extern "C" const IMAGE_DOS_HEADER __ImageBase;			//��������ĵ�ַ����hInstance��Ҳ����exe�ļ��ļ��ص�ַ

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR lpCmdLine, int nCmdShow)
{
	auto bAllocConsole = AllocConsole();
	HANDLE hin = GetStdHandle(STD_INPUT_HANDLE);
	HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
	char buf[256] = { 0 };
	char buf2[1024] = { 0 };
	sprintf_s(buf, 255,"hInstance:0x%x,&__ImageBase:0x%x\n", hInstance, &__ImageBase);			//����������ͬ��
	WriteConsole(hout, buf, strlen(buf), NULL, NULL);
	auto cmdLine = GetCommandLineW();			//��������exe·����
	DWORD cmdLineMultiByteSize = WideCharToMultiByte(CP_ACP, 0, cmdLine, -1, NULL, 0, NULL, FALSE);
	WideCharToMultiByte(CP_ACP, 0, cmdLine, -1, buf2, cmdLineMultiByteSize, NULL, FALSE);
	WriteConsoleA(hout, buf2, strlen(buf2), NULL, NULL);
	WriteConsole(hout, "\n", 2, NULL, NULL);
	int argc{ 0 };
	auto argvs = CommandLineToArgvW(cmdLine, &argc);			//argvs��ָ���ڴ����ڲ����䣬��Ҫ����Ҫ��ʱ���ֶ��ͷ�
	auto argvs2 = CommandLineToArgvW(cmdLine, &argc);			//ÿ�ε��ö����ٴη���
	if (argvs)
	{
		for (int i = 0; i < argc; ++i)
		{
			ZeroMemory(buf, 256);
			DWORD dBufSize = WideCharToMultiByte(CP_ACP, 0, argvs[i], -1, NULL, 0, NULL, FALSE);
			WideCharToMultiByte(CP_ACP, 0, argvs[i], -1, buf, dBufSize, NULL, FALSE);
			WriteConsoleA(hout, buf, strlen(buf), NULL, NULL);
		}
			
		LocalFree(argvs);
		argvs = nullptr;
	}
	if (argvs2)
	{
		LocalFree(argvs2);
		argvs2 = nullptr;
	}
	auto pEnvBlock = GetEnvironmentStrings();
	auto pEnvBlock4Print = pEnvBlock;
	while (*pEnvBlock4Print)
	{
		WriteConsole(hout, pEnvBlock4Print, strlen(pEnvBlock4Print), NULL, NULL);
		WriteConsole(hout, "\n", 2, NULL, NULL);
		pEnvBlock4Print += strlen(pEnvBlock4Print) + 1;
	}
	FreeEnvironmentStrings(pEnvBlock);

	FreeConsole();
	return 0;
}

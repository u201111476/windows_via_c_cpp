#include <Windows.h>
#include <stdio.h>
#include <assert.h>

extern "C" const IMAGE_DOS_HEADER __ImageBase;			//��������ĵ�ַ����hInstance��Ҳ����exe�ļ��ļ��ص�ַ

DWORD WINAPI ThreadFunc(LPVOID lpParam)
{
	while (1)
	{
		Sleep(3000);
	}
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR lpCmdLine, int nCmdShow)
{
	auto bAllocConsole = AllocConsole();		//һ������ֻ����һ������̨
	HANDLE hin = GetStdHandle(STD_INPUT_HANDLE);		//��ȡ��׼����ľ��������Ҫ�ֶ�Close
	HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);		//��ȡ��׼����ľ��������Ҫ�ֶ�Close
	char buf[256] = { 0 };
	char buf2[1024] = { 0 };
	sprintf_s(buf, 255,"hInstance:0x%x,&__ImageBase:0x%x\n", hInstance, &__ImageBase);			//����������ͬ��
	WriteConsole(hout, buf, strlen(buf), NULL, NULL);						//�����̨д������
	auto cmdLine = GetCommandLineW();			//��������exe·����
	DWORD cmdLineMultiByteSize = WideCharToMultiByte(CP_ACP, 0, cmdLine, -1, NULL, 0, NULL, FALSE);		//��ȡת������Ҫ�Ļ�������С
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
	//SetEnvironmentVariableA("TEST", "WJTEST");			//����Ķ�ֻ����Ե�ǰ���̣�Ҫ��Ӱ���������н��̣���Ҫ����ע���������WM_SETTINGCHANGE�㲥��Ϣ
	/*
	* ϵͳ����������HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
	* �û�����������HKEY_CURRENT_USER\Environment
	* �޸���󣬵��ã�SendMessage(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM) TEXT("Environment"));
	*/
	auto pEnvBlock = GetEnvironmentStrings();			//��ȡ���������ַ���
	auto pEnvBlock4Print = pEnvBlock;
	while (*pEnvBlock4Print)
	{
		WriteConsole(hout, pEnvBlock4Print, strlen(pEnvBlock4Print), NULL, NULL);
		WriteConsole(hout, "\n", 2, NULL, NULL);
		pEnvBlock4Print += strlen(pEnvBlock4Print) + 1;
	}
	FreeEnvironmentStrings(pEnvBlock);				//������������ַ���ʹ�õ��ڴ�
	pEnvBlock = nullptr;
	pEnvBlock4Print = nullptr;

	//����ַ���ʹ���˿��滻�Ļ�������������%USERPROFILE%\Documents,��Щ�ַ�������ͨ��ExpandEnvironmentStrings��չ����
	DWORD chValue = ExpandEnvironmentStrings("USERPROFILE\\Documents='%USERPROFILE%\\Documents'", NULL, 0);
	PTSTR pszBuf = new char[chValue];
	chValue = ExpandEnvironmentStrings(TEXT("USERPROFILE\\Documents='%USERPROFILE%\\Documents'"), pszBuf, chValue);
	WriteConsole(hout, pszBuf, chValue, NULL, NULL);
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	//CreateProcess("E:\\windows_via_c_cpp\\WinViaCAndCpp\\Debug\\token.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL,&si,&pi);		//�ӽ��̻�̳и��ĺ�Ļ�������
	////SetErrorMode����������û�����ף�����һ�£���˵���Է�ɳ�䣬����Ҫ�õ���ʱ���������
	ZeroMemory(buf, 256);
	GetCurrentDirectory(255, buf);			//��ȡ��ǰ����·��
	WriteConsole(hout, "CurrentDirectory:", strlen("CurrentDirectory:"), NULL, NULL);
	WriteConsole(hout, buf, strlen(buf), NULL, NULL);
	WriteConsole(hout, "\n", 2, NULL, NULL);
	SetCurrentDirectory("E:\\windows_via_c_cpp\\WinViaCAndCpp\\Debug");
	//Ҳ����ʹ��C����ʱ����_chdir�����ĵ�ǰ����·�������ڲ������SetCurrentDirectory,�������SetEnvironmentVariable�����治ͬ�������ĵ�ǰ·����
	WriteConsole(hout, "CurrentDirectory:", strlen("CurrentDirectory:"), NULL, NULL);
	WriteConsole(hout, buf, strlen(buf), NULL, NULL);
	WriteConsole(hout, "\n", 2, NULL, NULL);
	CreateProcess("token.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

	char szCurDir[MAX_PATH];
	DWORD cchLength= GetFullPathName(TEXT("E:"), MAX_PATH, szCurDir, NULL);			//�ɻ�ȡ�������ĵ�ǰ����·��
	WriteConsole(hout, szCurDir, strlen(szCurDir), nullptr, nullptr);
	OSVERSIONINFO ver;
	ver.dwOSVersionInfoSize = sizeof(ver);
	//GetVersionEx(&ver);			//������Ϊ�ѷ��

	//while (true)
	//{
	//	Sleep(5000);
	//}

	CreateThread(NULL, NULL, ThreadFunc, NULL, 0, NULL);
	FreeConsole();
	//ExitThread(1);			//������ExitThread�Ļ������߳�return�ˣ������exit,������һЩ��̬/ȫ�ֵ�C++����Ȼ�����ExitProcess,�������̾ͻ��˳�
								//������ExitThread�Ļ������ڲ���C/C++����ʱ�����˳������ˣ���Windowsϵͳ��֤һ������ֻ�е������߳��˳���֮��Ż��˳����������洴�����̻߳������ִ�У����̲��˳�
	return 0;
}

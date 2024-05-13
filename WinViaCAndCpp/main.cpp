#include <Windows.h>
#include <stdio.h>
#include <assert.h>

extern "C" const IMAGE_DOS_HEADER __ImageBase;			//这个变量的地址就是hInstance，也就是exe文件的加载地址

DWORD WINAPI ThreadFunc(LPVOID lpParam)
{
	while (1)
	{
		Sleep(3000);
	}
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR lpCmdLine, int nCmdShow)
{
	auto bAllocConsole = AllocConsole();		//一个进程只能由一个控制台
	HANDLE hin = GetStdHandle(STD_INPUT_HANDLE);		//获取标准输入的句柄，不需要手动Close
	HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);		//获取标准输出的句柄，不需要手动Close
	char buf[256] = { 0 };
	char buf2[1024] = { 0 };
	sprintf_s(buf, 255,"hInstance:0x%x,&__ImageBase:0x%x\n", hInstance, &__ImageBase);			//这两者是相同的
	WriteConsole(hout, buf, strlen(buf), NULL, NULL);						//向控制台写入内容
	auto cmdLine = GetCommandLineW();			//这个会包含exe路径名
	DWORD cmdLineMultiByteSize = WideCharToMultiByte(CP_ACP, 0, cmdLine, -1, NULL, 0, NULL, FALSE);		//获取转换后需要的缓冲区大小
	WideCharToMultiByte(CP_ACP, 0, cmdLine, -1, buf2, cmdLineMultiByteSize, NULL, FALSE);
	WriteConsoleA(hout, buf2, strlen(buf2), NULL, NULL);
	WriteConsole(hout, "\n", 2, NULL, NULL);
	int argc{ 0 };
	auto argvs = CommandLineToArgvW(cmdLine, &argc);			//argvs所指的内存由内部分配，需要在需要的时候手动释放
	auto argvs2 = CommandLineToArgvW(cmdLine, &argc);			//每次调用都会再次分配
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
	//SetEnvironmentVariableA("TEST", "WJTEST");			//这个改动只能针对当前进程，要想影响其他所有进程，需要更改注册表，并发送WM_SETTINGCHANGE广播消息
	/*
	* 系统环境变量：HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
	* 用户环境变量：HKEY_CURRENT_USER\Environment
	* 修改完后，调用：SendMessage(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM) TEXT("Environment"));
	*/
	auto pEnvBlock = GetEnvironmentStrings();			//获取环境变量字符串
	auto pEnvBlock4Print = pEnvBlock;
	while (*pEnvBlock4Print)
	{
		WriteConsole(hout, pEnvBlock4Print, strlen(pEnvBlock4Print), NULL, NULL);
		WriteConsole(hout, "\n", 2, NULL, NULL);
		pEnvBlock4Print += strlen(pEnvBlock4Print) + 1;
	}
	FreeEnvironmentStrings(pEnvBlock);				//清除环境变量字符串使用的内存
	pEnvBlock = nullptr;
	pEnvBlock4Print = nullptr;

	//许多字符串使用了可替换的环境变量，例如%USERPROFILE%\Documents,这些字符串可以通过ExpandEnvironmentStrings来展开。
	DWORD chValue = ExpandEnvironmentStrings("USERPROFILE\\Documents='%USERPROFILE%\\Documents'", NULL, 0);
	PTSTR pszBuf = new char[chValue];
	chValue = ExpandEnvironmentStrings(TEXT("USERPROFILE\\Documents='%USERPROFILE%\\Documents'"), pszBuf, chValue);
	WriteConsole(hout, pszBuf, chValue, NULL, NULL);
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	//CreateProcess("E:\\windows_via_c_cpp\\WinViaCAndCpp\\Debug\\token.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL,&si,&pi);		//子进程会继承更改后的环境变量
	////SetErrorMode函数的作用没搞明白，搜了一下，据说可以反沙箱，后面要用到的时候可以试试
	ZeroMemory(buf, 256);
	GetCurrentDirectory(255, buf);			//获取当前工作路径
	WriteConsole(hout, "CurrentDirectory:", strlen("CurrentDirectory:"), NULL, NULL);
	WriteConsole(hout, buf, strlen(buf), NULL, NULL);
	WriteConsole(hout, "\n", 2, NULL, NULL);
	SetCurrentDirectory("E:\\windows_via_c_cpp\\WinViaCAndCpp\\Debug");
	//也可以使用C运行时函数_chdir来更改当前工作路径，其内部会调用SetCurrentDirectory,还会调用SetEnvironmentVariable来保存不同驱动器的当前路径。
	WriteConsole(hout, "CurrentDirectory:", strlen("CurrentDirectory:"), NULL, NULL);
	WriteConsole(hout, buf, strlen(buf), NULL, NULL);
	WriteConsole(hout, "\n", 2, NULL, NULL);
	CreateProcess("token.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

	char szCurDir[MAX_PATH];
	DWORD cchLength= GetFullPathName(TEXT("E:"), MAX_PATH, szCurDir, NULL);			//可获取驱动器的当前工作路径
	WriteConsole(hout, szCurDir, strlen(szCurDir), nullptr, nullptr);
	OSVERSIONINFO ver;
	ver.dwOSVersionInfoSize = sizeof(ver);
	//GetVersionEx(&ver);			//被声明为已否决

	//while (true)
	//{
	//	Sleep(5000);
	//}

	CreateThread(NULL, NULL, ThreadFunc, NULL, 0, NULL);
	FreeConsole();
	//ExitThread(1);			//不调用ExitThread的话，主线程return了，会调用exit,先清理一些静态/全局的C++对象，然后调用ExitProcess,整个进程就会退出
								//调用了ExitThread的话，由于不走C/C++运行时那套退出机制了，而Windows系统保证一个进程只有当所有线程退出了之后才会退出，所以上面创建的线程还会继续执行，进程不退出
	return 0;
}

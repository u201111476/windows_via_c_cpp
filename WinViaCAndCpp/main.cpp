#include <Windows.h>
#include <stdio.h>
#include <assert.h>
#include <ShlObj.h>
#include <Pdh.h>
#include <iostream>

#include <IPHlpApi.h>
#pragma comment(lib, "IPHlpApi.lib")
#pragma comment(lib,"pdh.lib")

using namespace std;

extern "C" const IMAGE_DOS_HEADER __ImageBase;			//这个变量的地址就是hInstance，也就是exe文件的加载地址

HANDLE hin, hout;

DWORD WINAPI ThreadFunc(LPVOID lpParam)
{
	while (1)
	{
		Sleep(3000);
	}
}

BOOL GetProcessElevation(TOKEN_ELEVATION_TYPE* type, BOOL* bIsAdmin)
{
	//HANDLE tokenHandle;
	//if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
	//	return FALSE;
	//DWORD size;
	//if (GetTokenInformation(tokenHandle, TokenElevationType, type, sizeof(TOKEN_ELEVATION_TYPE), &size))
	//{
	//	BOOL b{TRUE};
	//	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	//	PSID AdministratorsGroup;
	//	b = AllocateAndInitializeSid(
	//		&NtAuthority,
	//		2,
	//		SECURITY_BUILTIN_DOMAIN_RID,
	//		DOMAIN_ALIAS_RID_ADMINS,
	//		0, 0, 0, 0, 0, 0,
	//		&AdministratorsGroup);
	//	if (b)
	//	{
	//		if (!CheckTokenMembership(NULL, AdministratorsGroup, &b))
	//		{
	//			b = FALSE;
	//		}
	//		FreeSid(AdministratorsGroup);
	//	}
	//	*bIsAdmin = b;
	//}
	//return TRUE;


	//书上的源码执行有问题，无论是不是管理员权限打开，都会判断成是管理员权限
	//把TokenLinkedToken去掉，然后CheckTokenMembership第一个参数设置为NULL，就行了
	HANDLE hToken = NULL;
	DWORD dwSize;

	// Get current process token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		return(FALSE);

	BOOL bResult = FALSE;

	// Retrieve elevation type information 
	if (GetTokenInformation(hToken, TokenElevationType,
		type, sizeof(TOKEN_ELEVATION_TYPE), &dwSize)) {
		// Create the SID corresponding to the Administrators group
		byte adminSID[SECURITY_MAX_SID_SIZE];
		dwSize = sizeof(adminSID);
		CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &adminSID,
			&dwSize);

		if (*type == TokenElevationTypeLimited) {
			// Get handle to linked token (will have one if we are lua)
			// //把这个去掉就行了
			//HANDLE hUnfilteredToken = NULL;
			//GetTokenInformation(hToken, TokenLinkedToken, (VOID*)
			//	&hUnfilteredToken, sizeof(HANDLE), &dwSize);

			// Check if this original token contains admin SID
			if (CheckTokenMembership(NULL, &adminSID, bIsAdmin)) {
				bResult = TRUE;
			}

			// Don't forget to close the unfiltered token
			//CloseHandle(hUnfilteredToken);
		}
		else {
			*bIsAdmin = IsUserAnAdmin();
			bResult = TRUE;
		}
	}

	// Don't forget to close the process token
	CloseHandle(hToken);

	return(bResult);
}


string getNetInterface() {
	ULONG ulSize = 0;
	IP_ADAPTER_INFO* pAdapter = nullptr;
	if (GetAdaptersInfo(pAdapter, &ulSize) == ERROR_BUFFER_OVERFLOW) {
		pAdapter = (IP_ADAPTER_INFO*)new char[ulSize];
	}
	else {
		cout << "GetAdaptersInfo fail" << endl;
		return "";
	}

	if (GetAdaptersInfo(pAdapter, &ulSize) != ERROR_SUCCESS) {
		cout << "GetAdaptersInfo fail" << endl;
		return "";
	}

	IPAddr ipAddr = { 0 };
	DWORD dwIndex = -1;
	DWORD nRet = GetBestInterface(ipAddr, &dwIndex);
	if (NO_ERROR != nRet) {
		cout << "GetBestInterface fail: " << nRet << endl;
	}

	string strInterface;
	for (auto* pCur = pAdapter; pCur != NULL; pCur = pCur->Next) {
		//if (pCur->Type != MIB_IF_TYPE_ETHERNET)
		//  continue;

		if (pCur->Index == dwIndex) {
			cout << "Best Interface!! ";
			strInterface = pCur->Description;
		}

		cout << "Descrip: " << pCur->Description;
		cout << ", Name: " << pCur->AdapterName << endl;
		cout << "IP: " << pCur->IpAddressList.IpAddress.String;
		cout << ", Gateway: " << pCur->GatewayList.IpAddress.String << endl << endl;
	}

	delete pAdapter;
	return strInterface;
}

//仅提供参考，表示可以通过PDH获取性能数据
void getResourceCounter()
{
	HQUERY query;
	PDH_STATUS status = PdhOpenQuery(NULL, NULL, &query);
	if (status != ERROR_SUCCESS)
		cout << "Open Query Error" << endl;

	HCOUNTER cpuCounter, memCounter;
	HCOUNTER recvCounter, sentCounter;

	//string strGet = getNetInterface();
	//wstring strInterface = L"\\Network Interface(" + xugd::clib::XuStr::str2wstr(strGet) + L")\\";
	//wcout << strInterface << endl;

	//可查看计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009
	status = PdhAddCounter(query, TEXT("\\Processor Information(_Total)\\% Processor Utility"), NULL, &cpuCounter);			//对应任务管理器的CPU利用率
	if (status != ERROR_SUCCESS)
		cout << "Add CPU Counter Error" << endl;
	status = PdhAddCounter(query, TEXT("\\Memory\\Available MBytes"), NULL, &memCounter);
	if (status != ERROR_SUCCESS)
		cout << "Add Memory Counter Error" << endl;

	//status = PdhAddCounter(query, (strInterface + L"Bytes Received/sec").c_str(), NULL, &recvCounter);
	//if (status != ERROR_SUCCESS)
	//	cout << "Add Received Counter Error" << endl;
	//status = PdhAddCounter(query, (strInterface + L"Bytes Sent/sec").c_str(), NULL, &sentCounter);
	//if (status != ERROR_SUCCESS)
	//	cout << "Add Sent Counter Error" << endl;


	int nIndex = 0;
	//cout << setiosflags(ios::fixed) << setprecision(4);
	char buf[256] = { 0 };
	while (true) {
		PdhCollectQueryData(query);
		Sleep(1000);

		PdhCollectQueryData(query);

		PDH_FMT_COUNTERVALUE pdhValue;
		DWORD dwValue;
		ZeroMemory(buf, 256);
		status = PdhGetFormattedCounterValue(cpuCounter, PDH_FMT_DOUBLE, &dwValue, &pdhValue);
		/*if (status != ERROR_SUCCESS)
			cout << "Get Value Error" << endl;*/
		//cout << setw(3) << ++nIndex << " - CPU: " << pdhValue.doubleValue << "%";
		sprintf_s(buf, 255, "CPU:%2.2f%%\n", pdhValue.doubleValue);
		WriteConsole(hout, buf, strlen(buf), NULL, NULL);
		status = PdhGetFormattedCounterValue(memCounter, PDH_FMT_LONG, &dwValue, &pdhValue);
		//if (status != ERROR_SUCCESS)
		//	cout << "Get Value Error" << endl;
		//cout << "; \tMemory: " << pdhValue.longValue << "MB";

		//status = PdhGetFormattedCounterValue(recvCounter, PDH_FMT_LONG, &dwValue, &pdhValue);
		//if (status != ERROR_SUCCESS)
		//	cout << "Get Value Error" << endl;
		//cout << "; \tRecv: " << pdhValue.longValue;
		//status = PdhGetFormattedCounterValue(sentCounter, PDH_FMT_LONG, &dwValue, &pdhValue);
		//if (status != ERROR_SUCCESS)
		//	cout << "Get Value Error" << endl;
		//cout << "; \tSent: " << pdhValue.longValue << endl;

		//Sleep(1000);
	}

	PdhCloseQuery(query);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR lpCmdLine, int nCmdShow)
{
	auto bAllocConsole = AllocConsole();		//一个进程只能由一个控制台
	hin = GetStdHandle(STD_INPUT_HANDLE);		//获取标准输入的句柄，不需要手动Close
	hout = GetStdHandle(STD_OUTPUT_HANDLE);		//获取标准输出的句柄，不需要手动Close
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
	BOOL bInJob = FALSE;
	IsProcessInJob(GetCurrentProcess(), NULL, &bInJob);
	ZeroMemory(buf, 256);
	if (bInJob)
		sprintf_s(buf, 255, "This process is in a job already!\n");
	else
		sprintf_s(buf, 255, "This process is not in any job!\n");
	WriteConsole(hout, buf, strlen(buf), NULL, NULL);
	HANDLE job = CreateJobObject(NULL, NULL);
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION Limits;
	memset(&Limits, 0, sizeof(Limits));
	Limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_TIME;
	Limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = 100;			//用户模式下只能跑100个100纳秒
	SetInformationJobObject(job, JobObjectExtendedLimitInformation, &Limits, sizeof(Limits));
	//CreateProcess("token.exe", NULL, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi);
	//CloseHandle(pi.hProcess);
	//CloseHandle(pi.hThread);

	//现在好像每个进程(至少普通进程是这样的)都会属于一个job
	CreateProcess("token.exe", NULL, NULL, NULL, TRUE,CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi);
	AssignProcessToJobObject(job, pi.hProcess);
	ResumeThread(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	char szCurDir[MAX_PATH];
	DWORD cchLength= GetFullPathName(TEXT("E:"), MAX_PATH, szCurDir, NULL);			//可获取驱动器的当前工作路径
	WriteConsole(hout, szCurDir, strlen(szCurDir), nullptr, nullptr);
	OSVERSIONINFO ver;
	ver.dwOSVersionInfoSize = sizeof(ver);
	//GetVersionEx(&ver);			//被声明为已否决
	bool bIsAdmin = IsUserAnAdmin();
	ZeroMemory(buf, 256);
	if (bIsAdmin)
		sprintf_s(buf, 255,"User is Admin!\n");
	else
		sprintf_s(buf, 255, "User is not Admin!\n");
	WriteConsole(hout, buf, strlen(buf), NULL, NULL);
	TOKEN_ELEVATION_TYPE teType;
	BOOL isAdmin;
	GetProcessElevation(&teType, &isAdmin);
	sprintf_s(buf, 255, "TOKEN_ELEVATION_TYPE is:%d,isAdmin is:%d\n", teType, isAdmin);
	WriteConsole(hout, buf, strlen(buf), NULL, NULL);
	//getResourceCounter();

	//PDH_HQUERY query;
	//if (PdhOpenQuery(NULL, NULL, &query) == ERROR_SUCCESS)
	//{
	//	PdhAddCounter(query,"Processor\\ % Total Processor Time")
	//}


	CreateThread(NULL, NULL, ThreadFunc, NULL, 0, NULL);
	//ExitThread(1);			//不调用ExitThread的话，主线程return了，会调用exit,先清理一些静态/全局的C++对象，然后调用ExitProcess,整个进程就会退出
	//调用了ExitThread的话，由于不走C/C++运行时那套退出机制了，而Windows系统保证一个进程只有当所有线程退出了之后才会退出，所以上面创建的线程还会继续执行，进程不退出
	while (true)
	{
		ZeroMemory(buf, 256);
		DWORD nRead;
		ReadConsole(hin, buf, 256, &nRead, NULL);
		if (strncmp(buf,"exit",4) == 0)
			break;
		if (strncmp(buf, "malloc", 6) == 0)
		{
			void* p = malloc(1024 * 1024);
		}
		if (strncmp(buf, "new", 3) == 0)
		{
			void* p1 = new char[1024 * 1024];
		}
		if (strncmp(buf, "HeapAlloc", 9) == 0)
		{
			if (strncmp(buf, "HeapAlloc0", 10) == 0)
			{
				void* p2 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024);
			}
			else
				void* p3 = HeapAlloc(GetProcessHeap(), 0, 1024 * 1024);
		}
		if (strncmp(buf, "VirtualAlloc", strlen("VirtualAlloc")) == 0)
		{
			void* p4{ nullptr };
			if (strncmp(buf, "VirtualAllocCommit", strlen("VirtualAllocCommit")) == 0)
				VirtualAlloc((LPVOID)p4, 1024 * 1024, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			else
				VirtualAlloc((LPVOID)p4, 1024 * 1024, MEM_RESERVE, PAGE_READWRITE);
			int i = 1;
		}
	}
	FreeConsole();
	TerminateJobObject(job, 0);
	CloseHandle(job);
	return 0;
}

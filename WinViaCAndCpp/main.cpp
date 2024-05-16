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

extern "C" const IMAGE_DOS_HEADER __ImageBase;			//��������ĵ�ַ����hInstance��Ҳ����exe�ļ��ļ��ص�ַ

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


	//���ϵ�Դ��ִ�������⣬�����ǲ��ǹ���ԱȨ�޴򿪣������жϳ��ǹ���ԱȨ��
	//��TokenLinkedTokenȥ����Ȼ��CheckTokenMembership��һ����������ΪNULL��������
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
			// //�����ȥ��������
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

//���ṩ�ο�����ʾ����ͨ��PDH��ȡ��������
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

	//�ɲ鿴�����\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009
	status = PdhAddCounter(query, TEXT("\\Processor Information(_Total)\\% Processor Utility"), NULL, &cpuCounter);			//��Ӧ�����������CPU������
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
	auto bAllocConsole = AllocConsole();		//һ������ֻ����һ������̨
	hin = GetStdHandle(STD_INPUT_HANDLE);		//��ȡ��׼����ľ��������Ҫ�ֶ�Close
	hout = GetStdHandle(STD_OUTPUT_HANDLE);		//��ȡ��׼����ľ��������Ҫ�ֶ�Close
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
	Limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = 100;			//�û�ģʽ��ֻ����100��100����
	SetInformationJobObject(job, JobObjectExtendedLimitInformation, &Limits, sizeof(Limits));
	//CreateProcess("token.exe", NULL, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi);
	//CloseHandle(pi.hProcess);
	//CloseHandle(pi.hThread);

	//���ں���ÿ������(������ͨ������������)��������һ��job
	CreateProcess("token.exe", NULL, NULL, NULL, TRUE,CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi);
	AssignProcessToJobObject(job, pi.hProcess);
	ResumeThread(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	char szCurDir[MAX_PATH];
	DWORD cchLength= GetFullPathName(TEXT("E:"), MAX_PATH, szCurDir, NULL);			//�ɻ�ȡ�������ĵ�ǰ����·��
	WriteConsole(hout, szCurDir, strlen(szCurDir), nullptr, nullptr);
	OSVERSIONINFO ver;
	ver.dwOSVersionInfoSize = sizeof(ver);
	//GetVersionEx(&ver);			//������Ϊ�ѷ��
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
	//ExitThread(1);			//������ExitThread�Ļ������߳�return�ˣ������exit,������һЩ��̬/ȫ�ֵ�C++����Ȼ�����ExitProcess,�������̾ͻ��˳�
	//������ExitThread�Ļ������ڲ���C/C++����ʱ�����˳������ˣ���Windowsϵͳ��֤һ������ֻ�е������߳��˳���֮��Ż��˳����������洴�����̻߳������ִ�У����̲��˳�
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

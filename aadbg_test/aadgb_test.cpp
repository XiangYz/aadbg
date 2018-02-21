#include <iostream>
#include <Windows.h>
#include <tchar.h>


int _tmain(int argc, TCHAR* argv[])
{
	char c;
	std::cin >> c;

	if (::IsDebuggerPresent())
	{
		std::cout << "Debugger detected!" << std::endl;
	}
	else
	{
		std::cout << "dbg test passed!" << std::endl;
	}

	TCHAR                   szPath[MAX_PATH] = {_T("C:\\Users\\Public\\share\\aadbg_dll\\Release\\aadbg_test2.exe")};
	STARTUPINFO				si = {sizeof(STARTUPINFO),};
	PROCESS_INFORMATION		pi = {0,};
	CONTEXT                 ctx = {0,};

	// Create Child Process
	if( !CreateProcess(
		szPath,
		NULL,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi) )
	{
		std::cout << "CreateProcess() failed: " <<  GetLastError() << std::endl;
		return -1;
	}

	std::cin >> c;

	return 0;
}
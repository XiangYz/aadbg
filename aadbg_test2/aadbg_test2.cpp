#include <iostream>
#include <Windows.h>
#include <tchar.h>


int _tmain(int argc, TCHAR* argv[])
{
	char c;
	std::cout << "aadbg_test2: pls input a key" << std::endl;
	std::cin >> c;

	BOOL bRet = IsDebuggerPresent();

	if (bRet)
	{
		std::cout << "being debugged" << std::endl;
	}

	return 0;
}
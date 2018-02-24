#include "func.h"

extern char g_szPluginName[];
extern HWND g_hWndMain;
extern HINSTANCE g_hModule;




BOOL IsVistaLater()
{
	OSVERSIONINFO osvi;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	GetVersionEx(&osvi);

	if( osvi.dwMajorVersion >= 6 )
		return TRUE;

	return FALSE;
}

HANDLE MyCreateRemoteThread
	(
	HANDLE hProcess, 
	LPTHREAD_START_ROUTINE pThreadProc, 
	LPVOID pRemoteBuf
	)
{
	HANDLE      hThread = NULL;
	FARPROC     pFunc = NULL;

	if( IsVistaLater() )    // Vista, 7, Server2008
	{
		pFunc = GetProcAddress(GetModuleHandle("ntdll.dll"), 
			"NtCreateThreadEx");
		if( pFunc == NULL )
		{
			return NULL;
		}

		char pfunc_str[64] = {0};
		sprintf(pfunc_str, "NtCreateThreadEx: %08X", pFunc);
		MessageBox(g_hWndMain, pfunc_str, g_szPluginName, MB_OK);

		__asm int 3

		//((PFNTCREATETHREADEX)pFunc)(&hThread,
		//	0x1FFFFF,
		//	NULL,
		//	hProcess,
		//	pThreadProc,
		//	pRemoteBuf,
		//	FALSE,
		//	NULL,
		//	NULL,
		//	NULL,
		//	NULL);

		hThread = CreateRemoteThread(hProcess, NULL, 0, 
			pThreadProc, pRemoteBuf, 0, NULL);
		
	}
	else                    // 2000, XP, Server2003
	{
		hThread = CreateRemoteThread(hProcess, NULL, 0, 
			pThreadProc, pRemoteBuf, 0, NULL);
		
	}

	return hThread;
}


int HookProcess(DWORD dwPID, BOOL bHook, HANDLE hProcess)
{

	
	// hook
	if (bHook)
	{
		// 打开远程进程
		if (NULL == hProcess)
		{
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
			if (hProcess == NULL)
			{
				return 0;
			}

			//MessageBox(g_hWndMain, "Process opened", g_szPluginName, MB_OK);
		}

		MessageBox(g_hWndMain, "Hook: process opened", g_szPluginName, MB_OK);

#if 1
		// 分配参数内存空间
		PTHREAD_PARAM mem_param = (PTHREAD_PARAM)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_PARAM), MEM_COMMIT, PAGE_READWRITE);
		if (mem_param == NULL)
		{
			return 0;
		}

		THREAD_PARAM param = {0};
		HMODULE hKernelMod = GetModuleHandleA("Kernel32.dll");
		param.pfn_loadlibrary = (PFN_LOADLIBRARYW)GetProcAddress(hKernelMod, "LoadLibraryW");
		param.pfn_getlasterror = (PFN_GETLASTERROR)GetProcAddress(hKernelMod, "GetLastError");

		char str_pfn[64] = {0};
		sprintf(str_pfn, "loadlibraryw: %08X, getlasterror: %08X"
			, param.pfn_loadlibrary
			, param.pfn_getlasterror);
		MessageBox(g_hWndMain, str_pfn, g_szPluginName, MB_OK);

		wcscpy(param.szDllPath, DLL_PATH_STRW);
		WriteProcessMemory(hProcess, mem_param, &param, sizeof(param), NULL);

		MessageBox(g_hWndMain, "Hook: param wrote", g_szPluginName, MB_OK);

		// 分配代码空间
		SIZE_T code_size = (ULONG)&SetPrivilege - (ULONG)&RemoteThreadProc;
		void* code_mem = VirtualAllocEx(hProcess, NULL, code_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (code_mem == NULL)
		{
			
			return 0;
		}
		WriteProcessMemory(hProcess, code_mem, &RemoteThreadProc, code_size, NULL);

		MessageBox(g_hWndMain, "Hook: code wrote", g_szPluginName, MB_OK);

		// 创建远程线程
		//HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)code_mem, mem_param, 0, 0);
		HANDLE hRemoteThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)code_mem, mem_param);
		if (hRemoteThread == NULL)
		{
			return 0;
		}

		MessageBox(g_hWndMain, "Hook: remote thread created", g_szPluginName, MB_OK);

		WaitForSingleObject(hRemoteThread, INFINITE);

		MessageBox(g_hWndMain, "Hook: remote thread finished", g_szPluginName, MB_OK);

		CloseHandle(hRemoteThread);
		VirtualFreeEx(hProcess, code_mem, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, mem_param, 0, MEM_RELEASE);
		CloseHandle(hProcess);



#else
		HMODULE hKernelMod = GetModuleHandleA("Kernel32.dll");

		//const wchar_t dll_path[] = DLL_PATH_STRW;
		//wchar_t* pRemoteBuf = (wchar_t*)VirtualAllocEx(hProcess, NULL, 512, MEM_COMMIT, PAGE_READWRITE);
		//WriteProcessMemory(hProcess, pRemoteBuf, dll_path, wcslen(dll_path) * 2 + 2, NULL);
		//PFN_LOADLIBRARYW pfn_loadlibrary = (PFN_LOADLIBRARYW)GetProcAddress(hKernelMod, "LoadLibraryW");

		const char dll_path[] = DLL_PATH_STRA;
		char* pRemoteBuf = (char*)VirtualAllocEx(hProcess, NULL, 512, MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(hProcess, pRemoteBuf, dll_path, strlen(dll_path) + 1, NULL);
		PFN_LOADLIBRARYA pfn_loadlibrary = (PFN_LOADLIBRARYA)GetProcAddress(hKernelMod, "LoadLibraryA");



		//HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfn_loadlibraryw, 
		//pRemoteBuf, 0, NULL);
		HANDLE hRemoteThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)pfn_loadlibrary, pRemoteBuf);
		if (!hRemoteThread) return 0;

		MessageBox(g_hWndMain, "hook: remote thread created", g_szPluginName, MB_OK);

		WaitForSingleObject(hRemoteThread, INFINITE);
		DWORD thr_ret = 0;
		if (!GetExitCodeThread(hRemoteThread, &thr_ret))
		{
			MessageBox(g_hWndMain, "hook: GetExitCodeThread failed!", g_szPluginName, MB_OK);
		}
		char thr_ret_str[32] = {0};
		sprintf(thr_ret_str, "loadlibrary ret: %08X", thr_ret);
		MessageBox(g_hWndMain, thr_ret_str, g_szPluginName, MB_OK);
		CloseHandle(hRemoteThread);
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);


#endif


		
	} // if hook
	else // unhook
	{
		// 打开远程进程
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
		if (hProcess == NULL)
		{
			return 0;
		}

		HMODULE hKernelMod = GetModuleHandleA("Kernel32.dll");
		FARPROC pfn_getmodulehandle = GetProcAddress(hKernelMod, "GetModuleHandleW");
		if (!pfn_getmodulehandle) return 0;
		const wchar_t dll_name[] = L"aadbg2_dll.dll";
		wchar_t* pRemoteBuf = (wchar_t*)VirtualAllocEx(hProcess, NULL, 512, MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(hProcess, pRemoteBuf, dll_name, wcslen(dll_name) * 2 + 2, NULL);
		//HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfn_getmodulehandlea, pRemoteBuf, 0, 0);

		HANDLE hRemoteThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)pfn_getmodulehandle, pRemoteBuf);
		if (hRemoteThread == NULL)
			return 0;

		//MessageBox(NULL, "unhook: remote thread created", g_szPluginName, MB_OK);

		WaitForSingleObject(hRemoteThread, INFINITE);
		HANDLE dwHandle = NULL;
		GetExitCodeThread(hRemoteThread, (DWORD*)&dwHandle);
		CloseHandle(hRemoteThread);
				
		//MessageBox(NULL, "unhook: module handle got", g_szPluginName, MB_OK);

		if (dwHandle == 0 || dwHandle == INVALID_HANDLE_VALUE)
		{
			return 0;
		}

		FARPROC pfn_freelib = GetProcAddress(hKernelMod, "FreeLibrary");
		if (!pfn_freelib) return 0;
		//hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfn_freelib, (void*)dwHandle, 0, 0);
		hRemoteThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)pfn_freelib, dwHandle);
		if (hRemoteThread == NULL)
		{
			return 0;
		}
		WaitForSingleObject(hRemoteThread, INFINITE);
		CloseHandle(hRemoteThread);
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);

	} // else unhook

	return 1;

}


int HookAllProcess(void)
{
	int cnt = 0;
	PROCESSENTRY32 pe;  // 进程信息
	pe.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // 获取系统进程列表
	if (Process32First(hSnapshot, &pe))      // 返回系统中第一个进程的信息
	{
		do
		{

			if (pe.th32ProcessID < 100)
				continue;

			//MessageBox(g_hWndMain, pe.szExeFile, g_szPluginName, MB_OK);

			if (0 == stricmp(pe.szExeFile, TARGET_PROCESS))
			{
				//MessageBox(g_hWndMain, "aadbg_test found", g_szPluginName, MB_OK);
				if (HookProcess(pe.th32ProcessID, TRUE) && 
					CheckDllInProcess(pe.th32ProcessID, _T(DLL_PATH_STRA)))
				{
					++cnt;
				}
				else
				{
					char msg[128] = "hook failed: ";
					strcat(msg, pe.szExeFile);
					MessageBox(g_hWndMain, msg, g_szPluginName, MB_OK);
				}

				break; // 只hook ollydbg
			}
			
		} while (Process32Next(hSnapshot, &pe));      // 下一个进程
	}
	CloseHandle(hSnapshot);     // 删除快照

	return cnt;
}

int UnhookAllProcess(void)
{
	int cnt = 0;
	PROCESSENTRY32 pe;  // 进程信息
	pe.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // 获取系统进程列表
	if (Process32First(hSnapshot, &pe))      // 返回系统中第一个进程的信息
	{
		do
		{
			if (pe.th32ProcessID < 100)
				continue;

			if (0 == stricmp(pe.szExeFile, TARGET_PROCESS))
			{
				if (HookProcess(pe.th32ProcessID, FALSE))
				{
					++cnt;
				}
				break;
			}

		} while (Process32Next(hSnapshot, &pe));      // 下一个进程
	}
	CloseHandle(hSnapshot);     // 删除快照

	return cnt;
}


DWORD WINAPI RemoteThreadProc(LPVOID pParam)
{
	__asm
	{
		int 3
		int 3
		int 3
		nop
		nop
		nop
	}


	PTHREAD_PARAM param = (PTHREAD_PARAM)pParam;
	
	HMODULE haadbg2 = param->pfn_loadlibrary(param->szDllPath);
	if (haadbg2 == NULL || haadbg2 == INVALID_HANDLE_VALUE)
	{
		DWORD err = param->pfn_getlasterror();
	}

	return 0;
}




BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		//std::cout << "OpenProcessToken error: " << GetLastError() << std::endl;
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL,
		lpszPrivilege, &luid))
	{
		//std::cout << "LookupPrivilegeValue error: " << GetLastError() << std::endl;
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;


	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		NULL, NULL))
	{
		//std::cout << "AdjustTokenPrivileges error: " << GetLastError() << std::endl;
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		//std::cout << "The token does not have the specified privilege." << std::endl;
		return FALSE;
	}

	return TRUE;
}

BOOL CheckDllInProcess(DWORD dwPID, LPCTSTR szDllPath)
{
	BOOL                    bMore = FALSE;
	HANDLE                  hSnapshot = INVALID_HANDLE_VALUE;
	MODULEENTRY32           me = { sizeof(me), };

	if( INVALID_HANDLE_VALUE == 
		(hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)) )
	{
		_tprintf(_T("CheckDllInProcess() : CreateToolhelp32Snapshot(%d) failed!!! [%d]\n"),
			dwPID, GetLastError());
		return FALSE;
	}

	bMore = Module32First(hSnapshot, &me);
	for( ; bMore ; bMore = Module32Next(hSnapshot, &me) )
	{
		if( !_tcsicmp(me.szModule, szDllPath) || 
			!_tcsicmp(me.szExePath, szDllPath) )
		{
			CloseHandle(hSnapshot);
			return TRUE;
		}
	}

	CloseHandle(hSnapshot);
	return FALSE;
}

DWORD GetThreadIDFromPID(DWORD dwPID)
{
	DWORD idThread = 0;
	THREADENTRY32 te;       // 线程信息
	te.dwSize = sizeof(THREADENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); // 系统所有线程快照
	if (Thread32First(hSnapshot, &te))       // 第一个线程
	{
		do
		{
			if (dwPID == te.th32OwnerProcessID)      // 认为找到的第一个该进程的线程为主线程
			{
				idThread = te.th32ThreadID;
				break;
			}
		} while (Thread32Next(hSnapshot, &te));           // 下一个线程
	}
	CloseHandle(hSnapshot); // 删除快照

	return idThread;
}
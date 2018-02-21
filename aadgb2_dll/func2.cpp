#include "func2.h"

unsigned char dbg_detec_old[64] = {0};
unsigned char dbg_detec_hooked_bytes[3] = {0x33, 0xc0, 0xc3};

BYTE g_pZWRT[5] = {0,};



int HookDbgDetec()
{
	HMODULE hKernelMod = GetModuleHandle(_T("Kernel32.dll"));
	FARPROC pfn_dbgdetec = GetProcAddress(hKernelMod, "IsDebuggerPresent");

	//TCHAR str_addr[64] = {0};
	//_stprintf(str_addr, _T("IsDebuggerPresent addr: %08X"), pfn_dbgdetec);
	//MessageBox(NULL, str_addr, _T("aadbg2"), MB_OK);

	HANDLE hCurr = GetCurrentProcess();

	DWORD old_protect;
	DWORD bytes_read, bytes_wrote;
	VirtualProtect(pfn_dbgdetec, 3, PAGE_EXECUTE_READWRITE, &old_protect);
	//memcpy(dbg_detec_old, pfn_dbgdetec, 3);
	BOOL bRet = ReadProcessMemory(hCurr, pfn_dbgdetec, dbg_detec_old, 3, &bytes_read);
	if (!bRet || bytes_read == 0)
	{
		MessageBox(NULL, _T("ReadProcessMemory failed"), _T("aadbg2"), MB_OK);
	}
	TCHAR old_head_str[32] = {0};
	_stprintf(old_head_str, _T("dbg_detec_old head: %02X %02X %02X"), dbg_detec_old[0], dbg_detec_old[1], dbg_detec_old[2]);
	MessageBox(NULL, old_head_str, _T("aadbg2"), MB_OK);

	//memcpy(pfn_dbgdetec, dbg_detec_hooked_bytes, 3);
	bRet = WriteProcessMemory(hCurr, pfn_dbgdetec, dbg_detec_hooked_bytes, 3, &bytes_wrote);
	if (!bRet || bytes_wrote == 0)
	{
		MessageBox(NULL, _T("WriteProcessMemory failed"), _T("aadbg2"), MB_OK);
	}
	VirtualProtect(pfn_dbgdetec, 3, old_protect, &old_protect);

	return 1;

}

int HookResumeThr()
{
	return hook_by_code(_T("ntdll.dll"), "ZwResumeThread", (PROC)NewZwResumeThread, g_pZWRT);
}

int UnhookDbgDetec()
{
	HMODULE hKernelMod = GetModuleHandle(_T("Kernel32.dll"));
	FARPROC pfn_dbgdetec = GetProcAddress(hKernelMod, "IsDebuggerPresent");

	DWORD old_protect;
	VirtualProtect(pfn_dbgdetec, 3, PAGE_EXECUTE_READWRITE, &old_protect);
	memcpy(pfn_dbgdetec, dbg_detec_old, 3);
	VirtualProtect(pfn_dbgdetec, 3, old_protect, &old_protect);

	return 1;
}

int UnhookResumeThr()
{
	return unhook_by_code(_T("ntdll.dll"), "ZwResumeThread", g_pZWRT);
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


void DebugLog(const TCHAR *format, ...)
{
	va_list vl;
	TCHAR szLog[512] = {0,};

	va_start(vl, format);
	_stprintf(szLog, format, vl);
	va_end(vl);

	OutputDebugString(szLog);
}


BOOL hook_by_code(LPCTSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
	FARPROC pFunc = NULL;
	DWORD dwOldProtect = 0, dwAddress = 0;
	BYTE pBuf[5] = {0xE9, 0, };
	PBYTE pByte = NULL;
	HMODULE hMod = NULL;

	hMod = GetModuleHandle(szDllName);
	if( hMod == NULL )
	{
		DebugLog(_T("hook_by_code() : GetModuleHandle(\"%s\") failed!!! [%d]\n"),
			szDllName, GetLastError());
		return FALSE;
	}

	pFunc = (FARPROC)GetProcAddress(hMod, szFuncName);
	if( pFunc == NULL )
	{
		DebugLog(_T("hook_by_code() : GetProcAddress(\"%s\") failed!!! [%d]\n"),
			szFuncName, GetLastError());
		return FALSE;
	}

	pByte = (PBYTE)pFunc;
	if( pByte[0] == 0xE9 )
	{
		DebugLog(_T("hook_by_code() : The API is hooked already!!!\n"));
		return FALSE;
	}

	if( !VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect) )
	{
		DebugLog(_T("hook_by_code() : VirtualProtect(#1) failed!!! [%d]\n"), GetLastError());
		return FALSE;
	}

	memcpy(pOrgBytes, pFunc, 5);

	dwAddress = (DWORD)pfnNew - (DWORD)pFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	memcpy(pFunc, pBuf, 5);

	if( !VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect) )
	{
		DebugLog(_T("hook_by_code() : VirtualProtect(#2) failed!!! [%d]\n"), GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL unhook_by_code(LPCTSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
	FARPROC pFunc = NULL;
	DWORD dwOldProtect = 0;
	PBYTE pByte = NULL;
	HMODULE hMod = NULL;

	hMod = GetModuleHandle(szDllName);
	if( hMod == NULL )
	{
		DebugLog(_T("unhook_by_code() : GetModuleHandle(\"%s\") failed!!! [%d]\n"),
			szDllName, GetLastError());
		return FALSE;
	}

	pFunc = (FARPROC)GetProcAddress(hMod, szFuncName);
	if( pFunc == NULL )
	{
		DebugLog(_T("unhook_by_code() : GetProcAddress(\"%s\") failed!!! [%d]\n"),
			szFuncName, GetLastError());
		return FALSE;
	}

	pByte = (PBYTE)pFunc;
	if( pByte[0] != 0xE9 )
	{
		DebugLog(_T("unhook_by_code() : The API is unhooked already!!!"));
		return FALSE;
	}

	if( !VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect) )
	{
		DebugLog(_T("unhook_by_code() : VirtualProtect(#1) failed!!! [%d]\n"), GetLastError());
		return FALSE;
	}

	memcpy(pFunc, pOrgBytes, 5);

	if( !VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect) )
	{
		DebugLog(_T("unhook_by_code() : VirtualProtect(#2) failed!!! [%d]\n"), GetLastError());
		return FALSE;
	}

	return TRUE;
}

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
		pFunc = GetProcAddress(GetModuleHandle(_T("ntdll.dll")), 
			"NtCreateThreadEx");
		if( pFunc == NULL )
		{
			return NULL;
		}

		TCHAR pfunc_str[64] = {0};
		_stprintf(pfunc_str, _T("NtCreateThreadEx: %08X"), pFunc);
		//MessageBox(NULL, pfunc_str, _T("aadbg2_dll"), MB_OK);

		((PFNTCREATETHREADEX)pFunc)(&hThread,
			0x1FFFFF,
			NULL,
			hProcess,
			pThreadProc,
			pRemoteBuf,
			FALSE,
			NULL,
			NULL,
			NULL,
			NULL);

	}
	else                    // 2000, XP, Server2003
	{
		hThread = CreateRemoteThread(hProcess, NULL, 0, 
			pThreadProc, pRemoteBuf, 0, NULL);

	}

	return hThread;
}



NTSTATUS WINAPI NewZwResumeThread(HANDLE ThreadHandle, PULONG SuspendCount)
{
	

	NTSTATUS status, statusThread;
	FARPROC pFunc = NULL, pFuncThread = NULL;
	DWORD dwPID = 0;
	static DWORD dwPrevPID = 0;
	THREAD_BASIC_INFORMATION tbi;
	HMODULE hMod = NULL;
	TCHAR szModPath[MAX_PATH] = {0,};

	DebugLog(_T("NewZwResumeThread() : start!!!\n"));
	MessageBox(NULL, _T("NewZwResumeThread start"), _T("aadbg2_dll"), MB_OK);

	hMod = GetModuleHandle(_T("ntdll.dll"));
	if( hMod == NULL )
	{
		DebugLog(_T("NewZwResumeThread() : GetModuleHandle() failed!!! [%d]\n"),
			GetLastError());
		MessageBox(NULL, _T("ntdll handle got failed!"), _T("aadbg2_dll"), MB_OK);
		return NULL;
	}

	// call ntdll!ZwQueryInformationThread()
	pFuncThread = GetProcAddress(hMod, "ZwQueryInformationThread");
	if( pFuncThread == NULL )
	{
		DebugLog(_T("NewZwResumeThread() : GetProcAddress() failed!!! [%d]\n"),
			GetLastError());
		MessageBox(NULL, _T("ZwQueryInformationThread got failed!"), _T("aadbg2_dll"), MB_OK);
		return NULL;
	}

	statusThread = ((PFZWQUERYINFORMATIONTHREAD)pFuncThread)
		(ThreadHandle, 0, &tbi, sizeof(tbi), NULL);
	if( statusThread != STATUS_SUCCESS )
	{
		DebugLog(_T("NewZwResumeThread() : pFuncThread() failed!!! [%d]\n"), 
			GetLastError());
		MessageBox(NULL, _T("ZwQueryInformationThread call failed!"), _T("aadbg2_dll"), MB_OK);
		return NULL;
	}

	dwPID = (DWORD)tbi.ClientId.UniqueProcess;
	if ( (dwPID != GetCurrentProcessId()) && (dwPID != dwPrevPID) )
	{
		DebugLog(_T("NewZwResumeThread() => call InjectDll()\n"));

		dwPrevPID = dwPID;

		// change privilege
		if( !SetPrivilege(SE_DEBUG_NAME, TRUE) )
			DebugLog(_T("NewZwResumeThread() : SetPrivilege() failed!!!\n"));

		// get injection dll path
		GetModuleFileName(GetModuleHandle(_T(DLL_PATH_STRA)), 
			szModPath, 
			MAX_PATH);

		TCHAR str_pid[32] = {0};
		_stprintf(str_pid, _T("target pid: %08X, mod path: %s")
			, dwPID, szModPath);
		MessageBox(NULL, str_pid, _T("aadbg2_dll"), MB_OK);

		if( !InjectDll(dwPID, szModPath) )
		{
			DebugLog(_T("NewZwResumeThread() : InjectDll(%d) failed!!!\n"), dwPID);
			MessageBox(NULL, _T("InjectDll failed!"), _T("aadbg2_dll"), MB_OK);
		}
	}
	else
	{
		MessageBox(NULL, _T("dwPID wrong"), _T("aadbg2_dll"), MB_OK);
	}

	// call ntdll!ZwResumeThread()
	if( !unhook_by_code(_T("ntdll.dll"), "ZwResumeThread", g_pZWRT) )
	{
		DebugLog(_T("NewZwResumeThread() : unhook_by_code() failed!!!\n"));
		MessageBox(NULL, _T("unhook failed!"), _T("aadbg2_dll"), MB_OK);
		return NULL;
	}

	pFunc = GetProcAddress(hMod, "ZwResumeThread");
	if( pFunc == NULL )
	{
		DebugLog(_T("NewZwResumeThread() : GetProcAddress() failed!!! [%d]\n"),
			GetLastError());
		MessageBox(NULL, _T("Old ZwResumeThread failed!"), _T("aadbg2_dll"), MB_OK);
		goto __NTRESUMETHREAD_END;
	}

	status = ((PFZWRESUMETHREAD)pFunc)(ThreadHandle, SuspendCount);
	if( status != STATUS_SUCCESS )
	{
		DebugLog(_T("NewZwResumeThread() : pFunc() failed!!! [%d]\n"), GetLastError());
		MessageBox(NULL, _T("Old ZwResumeThread call failed!"), _T("aadbg2_dll"), MB_OK);
		goto __NTRESUMETHREAD_END;
	}

__NTRESUMETHREAD_END:

	if( !hook_by_code(_T("ntdll.dll"), "ZwResumeThread", 
		(PROC)NewZwResumeThread, g_pZWRT) )
	{
		DebugLog(_T("NewZwResumeThread() : hook_by_code() failed!!!\n"));
		MessageBox(NULL, _T("ZwResumeThread hook failed!"), _T("aadbg2_dll"), MB_OK);
	}

	DebugLog(_T("NewZwResumeThread() : end!!!\n"));

	return status;
}

DWORD WINAPI RemoteThreadProc(LPVOID pParam)
{

	__asm
	{
		nop
		nop
		nop
		int 3
		int 3
		int 3
		nop
		nop
		nop
	}
	PTHREAD_PARAM param = (PTHREAD_PARAM)pParam;

	//param->pfn_msgbox(NULL, param->szMsgBoxParam, param->szMsgBoxParam, MB_OK);

	HMODULE haadbg2 = param->pfn_loadlibrary(param->szDllPath);
	if (haadbg2 == NULL || haadbg2 == INVALID_HANDLE_VALUE)
	{
		DWORD err = param->pfn_getlasterror();
		//param->pfn_msgbox(NULL, param->szDllPath, param->szMsgBoxParam, MB_OK);
		return 1;
	}

	return 0;
}


BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE                  hProcess = NULL;
	LPVOID                  pRemoteBuf = NULL;
	DWORD                   dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE  pThreadProc = NULL;
	BOOL                    bRet = FALSE;
	HMODULE                 hMod = NULL;

	if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )
	{
		DebugLog(_T("InjectDll() : OpenProcess(%d) failed!!! [%d]\n"), dwPID, GetLastError());
		MessageBox(NULL, _T("InjectDll() : OpenProcess failed"), _T("aadbg2_dll"), MB_OK);
		return 0;
	}

#if 1
	// 分配参数内存空间
	PTHREAD_PARAM mem_param = (PTHREAD_PARAM)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_PARAM), MEM_COMMIT, PAGE_READWRITE);
	if (mem_param == NULL)
	{
		return 0;
	}

	THREAD_PARAM param = {0};
	HMODULE hKernelMod = GetModuleHandle(_T("Kernel32.dll"));
	//HMODULE hUserMod = LoadLibrary(_T("User32.dll"));
	param.pfn_loadlibrary = (PFN_LOADLIBRARYW)GetProcAddress(hKernelMod, "LoadLibraryW");
	param.pfn_getlasterror = (PFN_GETLASTERROR)GetProcAddress(hKernelMod, "GetLastError");
	//param.pfn_msgbox = (PFN_MSGBOXW)GetProcAddress(hUserMod, "MessageBoxW");
	//wcscpy(param.szMsgBoxParam, L"msgbox: thread running");
	wcscpy(param.szDllPath, DLL_PATH_STRW);
	WriteProcessMemory(hProcess, mem_param, &param, sizeof(param), NULL);

	// 分配代码空间
	SIZE_T code_size = (ULONG)&InjectDll - (ULONG)&RemoteThreadProc;
	void* code_mem = VirtualAllocEx(hProcess, NULL, code_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (code_mem == NULL)
	{
		return 0;
	}
	WriteProcessMemory(hProcess, code_mem, &RemoteThreadProc, code_size, NULL);


	// 创建远程线程
	//HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)code_mem, mem_param, 0, 0);
	HANDLE hRemoteThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)code_mem, mem_param);
	if (hRemoteThread == NULL)
	{
		return 0;
		MessageBox(NULL, _T("hook: remote thread created"), _T("aadbg2_dll"), MB_OK);
	}

	WaitForSingleObject(hRemoteThread, INFINITE);
	CloseHandle(hRemoteThread);
	VirtualFreeEx(hProcess, code_mem, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess, mem_param, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	bRet = TRUE;

#else
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, 
		MEM_COMMIT, PAGE_READWRITE);
	if( pRemoteBuf == NULL )
	{
		DebugLog(_T("InjectDll() : VirtualAllocEx() failed!!! [%d]\n"), GetLastError());
		MessageBox(NULL, _T("InjectDll() : VirtualAllocEx failed"), _T("aadbg2_dll"), MB_OK);
		goto INJECTDLL_EXIT;
	}

	char szDllPathA[] = DLL_PATH_STRA;
	DWORD dwBufSizeA = strlen(szDllPathA) + 1;
	if( !WriteProcessMemory(hProcess, pRemoteBuf, 
		(LPVOID)szDllPath, dwBufSize, NULL) )
	{
		DebugLog(_T("InjectDll() : WriteProcessMemory() failed!!! [%d]\n"), GetLastError());
		MessageBox(NULL, _T("InjectDll() : WriteProcessMemory failed"), _T("aadbg2_dll"), MB_OK);
		goto INJECTDLL_EXIT;
	}

	hMod = GetModuleHandle(_T("kernel32.dll"));
	if( hMod == NULL )
	{
		DebugLog(_T("InjectDll() : GetModuleHandle() failed!!! [%d]\n"), GetLastError());
		MessageBox(NULL, _T("InjectDll() : GetModuleHandle failed"), _T("aadbg2_dll"), MB_OK);
		goto INJECTDLL_EXIT;
	}

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
	if( pThreadProc == NULL )
	{
		DebugLog(_T("InjectDll() : GetProcAddress() failed!!! [%d]\n"), GetLastError());
		MessageBox(NULL, _T("InjectDll() : GetProcAddress failed"), _T("aadbg2_dll"), MB_OK);
		goto INJECTDLL_EXIT;
	}

	HANDLE hRemoteThread = MyCreateRemoteThread(hProcess, pThreadProc, pRemoteBuf);
	if( NULL ==  hRemoteThread)
	{
		DebugLog(_T("InjectDll() : MyCreateRemoteThread() failed!!!\n"));
		MessageBox(NULL, _T("InjectDll() : MyCreateRemoteThread failed"), _T("aadbg2_dll"), MB_OK);
		goto INJECTDLL_EXIT;
	}



	bRet = TRUE;

INJECTDLL_EXIT:

	if( pRemoteBuf )
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	if( hRemoteThread )
		CloseHandle(hRemoteThread);

	if( hProcess )
		CloseHandle(hProcess);

#endif

	return bRet;
}




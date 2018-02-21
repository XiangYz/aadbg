#ifndef _FUNC_H_
#define _FUNC_H_

#include <Windows.h>
#include <tchar.h>
#include <string.h>
#include <stdio.h>
#include <TlHelp32.h>

#define TARGET_PROCESS "ollydbg.exe"

#define DLL_PATH_STRW L"C:\\Users\\Public\\share\\aadbg_dll\\Release\\aadbg2_dll.dll"
#define DLL_PATH_STRA "C:\\Users\\Public\\share\\aadbg_dll\\Release\\aadbg2_dll.dll"

typedef HMODULE(WINAPI *PFN_LOADLIBRARYA)(LPCSTR);
typedef HMODULE(WINAPI *PFN_LOADLIBRARYW)(LPCWSTR);
typedef FARPROC(WINAPI *PFN_GETPROCADDRESS)(HMODULE hModule,LPCSTR lpProcName);
typedef BOOL (WINAPI *PFN_DBGDETEC)(void);
typedef BOOL (WINAPI *PFN_VIRTUALPROTECT)(LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect);
typedef DWORD (WINAPI *PFN_GETLASTERROR)(void);

typedef DWORD (WINAPI *PFNTCREATETHREADEX)
	( 
	PHANDLE                 ThreadHandle,	
	ACCESS_MASK             DesiredAccess,	
	LPVOID                  ObjectAttributes,	
	HANDLE                  ProcessHandle,	
	LPTHREAD_START_ROUTINE  lpStartAddress,	
	LPVOID                  lpParameter,	
	BOOL	                CreateSuspended,	
	DWORD                   dwStackSize,	
	DWORD                   dw1, 
	DWORD                   dw2, 
	LPVOID                  Unknown 
	);

typedef struct stParam
{
	PFN_LOADLIBRARYW pfn_loadlibrary;
	wchar_t szDllPath[512];

	PFN_GETLASTERROR pfn_getlasterror;

}THREAD_PARAM, *PTHREAD_PARAM;

int HookAllProcess(void);
int UnhookAllProcess(void);
int HookProcess(DWORD dwPID, BOOL bHook, HANDLE hProcess = NULL);
BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
DWORD WINAPI RemoteThreadProc(LPVOID pParam);
BOOL CheckDllInProcess(DWORD dwPID, LPCTSTR szDllPath);

BOOL IsVistaLater();
HANDLE MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf);

#endif
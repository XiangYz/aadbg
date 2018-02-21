#ifndef _FUNC_H_
#define _FUNC_H_

#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>

#define DLL_PATH_STRW L"C:\\Users\\Public\\share\\aadbg_dll\\Release\\aadbg2_dll.dll"
#define DLL_PATH_STRA "C:\\Users\\Public\\share\\aadbg_dll\\Release\\aadbg2_dll.dll"


#define STATUS_SUCCESS						(0x00000000L) 

typedef LONG NTSTATUS;

typedef NTSTATUS (WINAPI *PFZWRESUMETHREAD)
	(
	HANDLE ThreadHandle, 
	PULONG SuspendCount
	);



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

typedef NTSTATUS (WINAPI *PFZWQUERYINFORMATIONTHREAD)
	(
	HANDLE ThreadHandle, 
	ULONG ThreadInformationClass, 
	PVOID ThreadInformation, 
	ULONG ThreadInformationLength, 
	PULONG ReturnLength
	);

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION;


typedef DWORD (WINAPI *PFN_GETLASTERROR)(void);
typedef HMODULE(WINAPI *PFN_LOADLIBRARYA)(LPCSTR);
typedef HMODULE(WINAPI *PFN_LOADLIBRARYW)(LPCWSTR);

typedef int (WINAPI *PFN_MSGBOXW)(HWND hWnd,LPCWSTR lpText,LPCWSTR lpCaption, UINT uType);

typedef struct stParam
{
	PFN_LOADLIBRARYW pfn_loadlibrary;
	wchar_t szDllPath[512];
	PFN_MSGBOXW pfn_msgbox;
	wchar_t szMsgBoxParam[256];
	PFN_GETLASTERROR pfn_getlasterror;

}THREAD_PARAM, *PTHREAD_PARAM;

int HookDbgDetec();
int HookResumeThr();
int UnhookDbgDetec();
int UnhookResumeThr();

void DebugLog(const TCHAR *format, ...);
BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL IsVistaLater();
BOOL unhook_by_code(LPCTSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes);
BOOL hook_by_code(LPCTSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes);
HANDLE MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf);

NTSTATUS WINAPI NewZwResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);
BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath);

DWORD WINAPI RemoteThreadProc(LPVOID pParam);

#endif
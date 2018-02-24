#ifndef _FUNC_H_
#define _FUNC_H_

#include <Windows.h>
#include <tchar.h>
#include <string.h>
#include <stdio.h>
#include <TlHelp32.h>

#define TARGET_PROCESS "ollydbg.exe"

#define DLL_PATH_STRW L"D:\\xiang\\github_space\\aadbg\\Release\\aadbg2_dll.dll"
#define DLL_PATH_STRA "D:\\xiang\\github_space\\aadbg\\Release\\aadbg2_dll.dll"

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



typedef NTSTATUS (WINAPI *PFN_NTQIP)(HANDLE ProcessHandle, ULONG ProcessInformationClass, 
	PVOID ProcessInformation, UINT32 ProcessInformationLength, UINT32* ReturnLength);


int HookAllProcess(void);
int UnhookAllProcess(void);
int HookProcess(DWORD dwPID, BOOL bHook, HANDLE hProcess = NULL);
BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
DWORD WINAPI RemoteThreadProc(LPVOID pParam);
BOOL CheckDllInProcess(DWORD dwPID, LPCTSTR szDllPath);

BOOL IsVistaLater();
HANDLE MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf);

DWORD GetThreadIDFromPID(DWORD dwPID);






typedef struct _PROCESS_BASIC_INFORMATION32 {
	NTSTATUS ExitStatus;
	UINT32 PebBaseAddress;
	UINT32 AffinityMask;
	UINT32 BasePriority;
	UINT32 UniqueProcessId;
	UINT32 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32;


#define NT_SUCCESS(x) ((x) >= 0)  
#define ProcessBasicInformation 0

template <typename T>
struct _UNICODE_STRING_T
{
	WORD Length;
	WORD MaximumLength;
	T Buffer;
};

template <typename T>
struct _LIST_ENTRY_T
{
	T Flink;
	T Blink;
};

template <typename T, typename NGF, int A>
struct _PEB_T
{
	typedef T type;

	union
	{
		struct
		{
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE BitField;
		};
		T dummy01;
	};
	T Mutant;
	T ImageBaseAddress;     //进程加载基地址  
	T Ldr;
	T ProcessParameters;    //各种信息，环境变量，命令行等等  
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T AtlThunkSListPtr;
	T IFEOKey;
	T CrossProcessFlags;
	T UserSharedInfoPtr;
	DWORD SystemReserved;
	DWORD AtlThunkSListPtr32;
	T ApiSetMap;
	T TlsExpansionCounter;
	T TlsBitmap;
	DWORD TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T HotpatchInformation;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union
	{
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	T ProcessHeaps;
	T GdiSharedHandleTable;
	T ProcessStarterHelper;
	T GdiDCAttributeList;
	T LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	T ImageSubsystemMinorVersion;
	T ActiveProcessAffinityMask;
	T GdiHandleBuffer[A];
	T PostProcessInitRoutine;
	T TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	T SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	T pShimData;
	T AppCompatInfo;
	_UNICODE_STRING_T<T> CSDVersion;
	T ActivationContextData;
	T ProcessAssemblyStorageMap;
	T SystemDefaultActivationContextData;
	T SystemAssemblyStorageMap;
	T MinimumStackCommit;
	T FlsCallback;
	_LIST_ENTRY_T<T> FlsListHead;
	T FlsBitmap;
	DWORD FlsBitmapBits[4];
	T FlsHighIndex;
	T WerRegistrationData;
	T WerShipAssertPtr;
	T pContextData;
	T pImageHeaderHash;
	T TracingFlags;
	T CsrServerReadOnlySharedMemoryBase;
};

template <typename T>
struct _STRING_T
{
	WORD Length;
	WORD MaximumLength;
	T    Buffer;
};

template <typename T>
struct _RTL_DRIVE_LETTER_CURDIR_T
{
	WORD         Flags;
	WORD         Length;
	ULONG        TimeStamp;
	_STRING_T<T> DosPath;
};

template <typename T>
struct _CURDIR_T
{
	_UNICODE_STRING_T<T> DosPath;
	T                    Handle;
};

template <typename T>
struct _RTL_USER_PROCESS_PARAMETERS_T
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	T ConsoleHandle;
	ULONG  ConsoleFlags;
	T StandardInput;
	T StandardOutput;
	T StandardError;
	_CURDIR_T<T> CurrentDirectory;
	_UNICODE_STRING_T<T> DllPath;
	_UNICODE_STRING_T<T> ImagePathName; //进程完整路径  
	_UNICODE_STRING_T<T> CommandLine;   //进程命令行  
	T Environment;             //环境变量（地址）  
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	_UNICODE_STRING_T<T> WindowTitle;
	_UNICODE_STRING_T<T> DesktopInfo;
	_UNICODE_STRING_T<T> ShellInfo;
	_UNICODE_STRING_T<T> RuntimeData;
	_RTL_DRIVE_LETTER_CURDIR_T<T> CurrentDirectores[32];
	ULONG EnvironmentSize;
};

typedef _PEB_T<DWORD, DWORD64, 34> _PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> _PEB64;
typedef _RTL_USER_PROCESS_PARAMETERS_T<UINT32> _RTL_USER_PROCESS_PARAMETERS32;
typedef _RTL_USER_PROCESS_PARAMETERS_T<UINT64> _RTL_USER_PROCESS_PARAMETERS64;



#endif
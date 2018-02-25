#ifndef _AADBG_SYS_H_
#define _AADBG_SYS_H_

#include <ntddk.h>

#define IOCTL_AADBG_HOOK	CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AADBG_UNHOOK	CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE02, METHOD_BUFFERED, FILE_ANY_ACCESS)



#define NT_DEVICE_NAME		L"\\Device\\aadbg_sys"
#define DOS_DEVICE_NAME		L"\\DosDevices\\aadbg_sys"


// type definition

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PULONG_PTR ServiceTableBase;// SSDT (System Service Dispatch Table)的基地址
	PULONG ServiceCounterTableBase;// 用于 checked builds, 包含 SSDT 中每个服务被调用的次数
	ULONG NumberOfService;// 服务函数的个数, NumberOfService * 4 就是整个地址表的大小
	PUCHAR ParamTableBase;// SSPT(System Service Parameter Table)的基地址
} KSERVICE_TABLE_OBJ, *PKSERVICE_TABLE_OBJ;

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
	KSERVICE_TABLE_DESCRIPTOR ntoskrnl;// ntoskrnl.exe 的服务函数
	KSERVICE_TABLE_DESCRIPTOR win32k;// win32k.sys 的服务函数(GDI32.dll/User32.dll 的内核支持)
	KSERVICE_TABLE_DESCRIPTOR Reserved1;
	KSERVICE_TABLE_DESCRIPTOR Reserved2;
}KSERVICE_DESCRIPTOR_TABLE, *PKSERVICE_DESCRIPTOR_TABLE;


// var declarations
extern PKSERVICE_TABLE_DESCRIPTOR	KeServiceDescriptorTable;



extern ULONG	g_ulBuildNum;
extern ULONG	g_ulMajorVer;
extern ULONG	g_ulMinorVer;


// function declarations
NTSTATUS CommDispatch(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
VOID DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);


#endif
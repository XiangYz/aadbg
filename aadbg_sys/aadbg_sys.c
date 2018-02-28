#include "aadbg_sys.h"


#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, CommDispatch)
#pragma alloc_text(PAGE, DriverUnload)
#endif

ULONG	g_ulBuildNum;
ULONG	g_ulMajorVer;
ULONG	g_ulMinorVer;

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING	unNtDevName, unDosDevName;
	PDEVICE_OBJECT	pDevObj = NULL;

	PsGetVersion(&g_ulMajorVer, &g_ulMinorVer, &g_ulBuildNum, NULL);

	RtlInitUnicodeString(&unNtDevName, NT_DEVICE_NAME);
	
	status = IoCreateDevice(pDriverObject,
							4,			// not used
							&unNtDevName,
							FILE_DEVICE_UNKNOWN,
							FILE_DEVICE_SECURE_OPEN,
							0,
							&pDevObj);

	if(NT_SUCCESS(status))
	{
		RtlInitUnicodeString(&unDosDevName, DOS_DEVICE_NAME);
		status = IoCreateSymbolicLink(&unDosDevName, &unNtDevName);
		if(!NT_SUCCESS(status))
		{
			IoDeleteDevice(pDevObj);
		}

		pDriverObject->MajorFunction[IRP_MJ_CREATE] = CommDispatch;
		pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CommDispatch;
		pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CommDispatch;
		pDriverObject->DriverUnload = DriverUnload;
	}

	//g_dwCsrssProcId = (DWORD)GetCsrssProcId();
	//g_dwExplorerProcId = (DWORD)GetProcIdByName(L"explorer.exe");

	pSerDesTable = (PSERVICE_DESCRIPTOR_TABLE)GetServiceDescriptorTableShadowAddr();

	KdPrint(("DriverEntry:g_dwCsrssProcId = %d, g_dwExplorerProcId = %d, pSerDesTable = %08x\n", 
					g_dwCsrssProcId, g_dwExplorerProcId, pSerDesTable));

	if(pSerDesTable != NULL)
	{
		win32k.Base = pSerDesTable->win32k.Base;
		win32k.Count = pSerDesTable->win32k.Count;
		win32k.Limit = pSerDesTable->win32k.Limit;
		win32k.Number = pSerDesTable->win32k.Number;

		RtlCopyMemory(&KeServiceDescriptorTableShadow, pSerDesTable, sizeof(KeServiceDescriptorTableShadow));
	}

	g_dwRefCount = 0;
	g_IsINT1Hooked = 0;
	g_dwIsSSDTHooked = 0;
	g_dwIsHidenProcess = 0;
	g_dwIsHidenWindow = 0;
	g_dwIsProtectProcess = 0;
	g_hForegroundWindow = NULL;

	RtlZeroMemory(g_ProcList, sizeof(g_ProcList));
	KeInitializeSpinLock(&g_SpinLock);
	
	PsSetCreateProcessNotifyRoutine(ProcCreateNotify, FALSE);
	g_pDriverStart = pDriverObject->DriverStart;
	g_ulDriverSize = pDriverObject->DriverSize;

	SSDTHookInit();

	return status;
}

NTSTATUS CommDispatch(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
/*++

Routine Description:

	The driver dispatch routine, handle IRP_MJ_CREATE, IRP_MJ_CLOSE and IRP_MJ_DEVICE_CONTROL.

	IRP_MJ_DEVICE_CONTROL InputBuffer Layout

		|				   |                 |                    |  				  |	                     |                |              |                 |  
		| g_CommunicateKey | g_dwCsrssProcId | g_dwIsHidenProcess | g_dwIsHidenWindow | g_dwIsProtectProcess | g_IsSupportLBR | g_IsEnableLBR| g_dwBlackProcId | 
offset	|		0		   |        4        |          8         |          12       |           16         |        20      |      24      |       28        |			

--*/
{
	NTSTATUS	status;
	PVOID pBuffer = pIrp->AssociatedIrp.SystemBuffer;
	PIO_STACK_LOCATION	pIoStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG ulInputBufferLen = pIoStack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG ulOutputBufferLen = pIoStack->Parameters.DeviceIoControl.OutputBufferLength;

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	if(pIoStack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		EncAndDecBuffer(pBuffer, ulInputBufferLen);
		switch (pIoStack->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_SOD_ADD_WHITE_PROC:
			{
				if( g_CommunicateKey == *(PULONG)pBuffer )
				{
					if(AddProcInfoToList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS))
					{
						if(0 != *((PULONG)pBuffer + 1))
						{
							InterlockedExchange(&g_dwCsrssProcId, *((PULONG)pBuffer + 1));
							InterlockedExchange(&g_IsSupportLBR, *((PULONG)pBuffer + 5));
							InterlockedExchange(&g_IsEnableLBR, *((PULONG)pBuffer + 6));
							InterlockedExchange(&g_dwIsHidenWindow, *((PULONG)pBuffer + 3));
							InterlockedExchange(&g_dwIsHidenProcess, *((PULONG)pBuffer + 2));
							InterlockedExchange(&g_dwIsProtectProcess, *((PULONG)pBuffer + 4));
							if(GetProcCount(SOD_WHITE_PROCESS))
							{
								HookSSDT();
								pIrp->IoStatus.Status = STATUS_SUCCESS;
							}
							else
							{
								KdPrint(("null white process\n"));
							}
						}
					}
					else
					{
						KdPrint(("add white process failed: %X\n", IoGetCurrentProcess()));
					}
				}
				else
				{
					KdPrint(("Invalid Key! RealKey = [%08X], BufferKey = [%08X]\n", 
						g_CommunicateKey, *(PULONG)pBuffer));
				}
			}
			break;
		case IOCTL_SOD_DEL_WHITE_PROC:
			{
				if(g_CommunicateKey == *(PULONG)pBuffer)
				{
					DelProcInfoFromList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS);
					*(PULONG)pBuffer = GetProcCount(SOD_WHITE_PROCESS);

					if(*(PULONG)pBuffer == 0)
					{
						UnhookSSDT();
					}
					
					pIrp->IoStatus.Information = 4;
					pIrp->IoStatus.Status = STATUS_SUCCESS;
				}
				else
				{
					KdPrint(("Invalid Key! RealKey = [%08X], BufferKey = [%08X]\n", 
						g_CommunicateKey, *(PULONG)pBuffer));
				}
			}
			break;
		case IOCTL_SOD_ADD_BLACK_PROC:
			{
				if(g_CommunicateKey == *(PULONG)pBuffer)
				{
					if(*((PULONG)pBuffer + 7) != 0)
					{
						if(AddProcInfoToList(NULL, *((PULONG)pBuffer + 7), SOD_BLACK_PROCESS) == -1)	// [Warning:]
						{
							*(PULONG)pBuffer = 0;
						}
						else
						{
							// return user mode shared memory addr
							*(PULONG)pBuffer = (ULONG)(GetProcInfoFromList(NULL, *((PULONG)pBuffer + 7)))->pUserAddrOfSharedMem;
						}
					}

					pIrp->IoStatus.Information = 4;
					pIrp->IoStatus.Status = STATUS_SUCCESS;					
				}
				else
				{
					KdPrint(("Invalid Key! RealKey = [%08X], BufferKey = [%08X]\n", 
						g_CommunicateKey, *(PULONG)pBuffer));
				}
			}
			break;
		case IOCTL_SOD_DEL_BLACK_PROC:
			{
				if(g_CommunicateKey == *(PULONG)pBuffer)
				{
					if(*((PULONG)pBuffer + 7) != 0)
					{
						DelProcInfoFromList(NULL, *((PULONG)pBuffer + 7), SOD_BLACK_PROCESS);
						if(0 == GetProcCount(SOD_BLACK_PROCESS))
						{
							UnhookINT1();
						}
					}
					pIrp->IoStatus.Status = STATUS_SUCCESS;
				}
				else
				{
					KdPrint(("Invalid Key! RealKey = [%08X], BufferKey = [%08X]\n", 
						g_CommunicateKey, *(PULONG)pBuffer));
				}
			}	
			break;
		case IOCTL_SOD_HOOK_INT1:
			{
				if(GetProcCount(SOD_BLACK_PROCESS) != 0)
				{
					HookINT1();
				}
				pIrp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;
		case IOCTL_SOD_UNHOOK_INT1:
			{
				if(0 == GetProcCount(SOD_BLACK_PROCESS))
				{
					UnhookINT1();
				}
				pIrp->IoStatus.Status = STATUS_SUCCESS;
			}
			break;
		default:
			pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			break;
		}

		if(pIrp->IoStatus.Status == STATUS_SUCCESS)
		{
			EncAndDecBuffer(pBuffer, pIrp->IoStatus.Information);
		}
	}

	status = pIrp->IoStatus.Status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
/*++

Routine Description:

	The driver unload routine, do some clean work.

--*/
{
	UNICODE_STRING	unDosDevName;
	LARGE_INTEGER liTimeout;
	int	nCount = 0;

	KdPrint(("Begin Unhook!\n"));
	//UnhookSSDT();
	KdPrint(("Unhook Done!\n"));

	PsSetCreateProcessNotifyRoutine(ProcCreateNotify, TRUE);

	liTimeout.QuadPart = -10 * 1000;	// one millisecond
	KdPrint(("KeDelayExecutionThread\n"));

	do 
	{
		KeDelayExecutionThread(KernelMode, FALSE, &liTimeout);
		if(0 == g_dwRefCount)
		{
			break;
		}
		nCount++;
	} while (nCount < 10);

	RtlInitUnicodeString(&unDosDevName, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&unDosDevName);
	IoDeleteDevice(pDriverObject->DeviceObject);

	KdPrint(("UNLOAD SUCCESS!\n"));
}
















void shDisableWriteProtect(ULONG *old)
{
	ULONG cr0_old;
	_asm
	{
		cli
		// 取出当前cr0的值放入eax并备份到变量中
		mov eax,cr0 
		mov cr0_old,eax
		// 将eax与上0fffeffffh
		and eax,0fffeffffh
		mov cr0,eax;
	};
	*old = cr0_old;
}

void shEnableWriteProtect(ULONG old)
{
	_asm {
		mov eax,old
		mov cr0,eax
		sti
	};
}



void* SSDTHook(
		 void *func_to_hook,
		 void *new_func,
         void **old_func)
{
	ULONG service_id;
	void *function = NULL;
	ULONG cr0_old;
	void* old_function = NULL;

	ASSERT(func_to_hook != NULL);
	ASSERT(new_func != NULL);
	if(func_to_hook == NULL || new_func == NULL)
		return NULL;


	service_id = *(PULONG)(((PUCHAR)func_to_hook)+1);
	old_function = (void *)KeServiceDescriptorTable.ServiceTableBase[service_id];


    if(old_func != NULL)
        *old_func = old_function;

	shDisableWriteProtect(&cr0_old);
	KeServiceDescriptorTable.ServiceTableBase[service_id] = (unsigned int)new_func;
	shEnableWriteProtect(cr0_old);

	
	return old_function;
}

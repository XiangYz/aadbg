#include <Windows.h>
#include "func2.h"

BOOL APIENTRY DllMain(
	HINSTANCE hModule,
	DWORD reason,
	LPVOID lpReserved)
{
	if (DLL_PROCESS_ATTACH == reason)
	{
		MessageBox(NULL, _T("aadbg2_dll dllmain: process attach"), _T("aadbg2"), MB_OK);
		if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
		{
			MessageBox(NULL, _T("SetPrivilege failed!"), _T("aadbg2"), MB_OK);
			return FALSE;
		}
		HookDbgDetec();
		HookResumeThr();
	}
	else if (DLL_PROCESS_DETACH == reason)
	{
		//MessageBox(NULL, _T("aadbg2_dll dllmain: process detach"), _T("aadbg2"), MB_OK);
		UnhookDbgDetec();
		UnhookResumeThr();
	}

	return TRUE;
}

__declspec(dllexport)
void dummy(void)
{
	return;
}

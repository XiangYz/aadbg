#include <Windows.h>


char KillIsDebuggerPresent(PROCESS_INFORMATION pi)
{
	DWORD tib, pib;
	LDT_ENTRY segselector;
	CONTEXT TempContext;

	// 把段相关的地址转换为线性地址
	// ReadProcessMemory和WriteProcessMemory用的是线性地址
	TempContext.ContextFlags = CONTEXT_SEGMENTS;
	GetThreadContext(pi.hThread, &TempContext);
	GetThreadSelectorEntry(pi.hThread, TempContext.SegFs, &segselector);
	tib = ((segselector.HighWord.Bytes.BaseHi) << 24) +
		((segselector.HighWord.Bytes.BaseMid) << 16) +
		(segselector.BaseLow);

	//printf ("TIB @ %X\n", tib);

	if (ReadProcessMemory(pi.hProcess, (void *)(tib + 0x30), &pib, sizeof(pib), NULL) == 0)
	{
		//printf("Could not get PIB from TIB !\n";
		return 0;
	}
	else
	{
		char debug_info = 0xFF;
		//printf ("PIB @ %X\n", pib);
		pib += 2;
		if (ReadProcessMemory(pi.hProcess, (void *)pib, &debug_info, sizeof(debug_info), NULL) == 0)
		{
			//printf("Unable to read from PIB !\n";
			return 0;
		}
		else
		{
			//printf ("Old debug value in PIB: %X\n", debug_info);
			if (debug_info != 0x01)
			{
				//printf("PB value unexpected. Aborting!";
				return 0;
			}
			else
			{
				debug_info = 0;
				if (WriteProcessMemory(pi.hProcess, (void *)pib, &debug_info, sizeof(debug_info), NULL) == 0)
				{
					//printf("Could not write new value into PIB !\n";
					return 0;
				}
				else
				{
					//printf ("PIB debug value override ok!\n";
					return 1;
				}

			} // debug info
		} // read pib
	} // read tib
}
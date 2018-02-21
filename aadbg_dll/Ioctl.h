/*++

Copyright (c) Bombs

Module Name:
	
	Ioctl.h

Author  :Bombs
Time    :2014-5-8 10:01:51
Abstract:
   
	IOCTLs used by the app interacts with the driver

--*/

#ifndef _IOCTL_H
#define _IOCTL_H

#define IOCTL_HOOK_SSDT				CTL_CODE(FILE_DEVICE_UNKNOWN, 0xe01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNHOOK_SSDT		  	CTL_CODE(FILE_DEVICE_UNKNOWN, 0xe02, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif
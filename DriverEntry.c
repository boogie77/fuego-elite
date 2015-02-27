// Note: Read device name from registry
#include "Main.h"
#include "Toolset.h"
#include "ServicePatch.h"
#include "Offset.h"
#include "Cheat.h"

// Global declarations
const wchar_t DeviceName[] = L"\\Device\\null";
const wchar_t DosDeviceName[] = L"\\DosDevices\\msdirectx";
static PDEVICE_OBJECT g_Device = NULL;
static ULONG g_uProcessNameOffset = 0;
PVOID g_pKrnlBase = NULL;
char szKernelName[256] = { 0 };
syscall_offsets_t gTableOffsets;

typedef NTSTATUS (*OnDispatch_t)( IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp );

VOID DriverUnload( IN PDRIVER_OBJECT pDriverObject );
NTSTATUS OnDispatch( IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp );

OnDispatch_t pOrigOnDispatch = NULL;

BOOLEAN GetProcessNameOffset( void )
{
	ULONG uCount = 0;
	ULONG uCurrentProc = (ULONG)PsGetCurrentProcess( );
	for( ; uCount < PAGE_SIZE*3; uCount++ )
	{
		if( !strncmp("System", (PCCHAR)uCurrentProc+uCount, strlen("System")) )
		{
			// We found the offset
			g_uProcessNameOffset = uCount;
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN GetProcessName( OUT PCHAR pszName, IN PEPROCESS peProcess )
{
	if( g_uProcessNameOffset != 0 && pszName && peProcess )
	{
		PCHAR pszProcessName = (PCHAR)peProcess+g_uProcessNameOffset;
		strncpy( pszName, pszProcessName, 16 );
		pszName[16] = '\0';
		return TRUE;
	}
	return FALSE;
}

BOOLEAN GetProcessNameByPid( OUT PCHAR pszName, DWORD dwPid )
{
	PEPROCESS peProcess = NULL;

	PsLookupProcessByProcessId( (HANDLE)dwPid, &peProcess );
	if( g_uProcessNameOffset != 0 && pszName && peProcess )
	{
		PCHAR pszProcessName = (PCHAR)peProcess+g_uProcessNameOffset;
		strncpy( pszName, pszProcessName, 16 );
		pszName[16] = '\0';
		ObDereferenceObject(peProcess);
		return TRUE;
	}

	return FALSE;
}

VOID InitializeThread( PVOID Unused )
{
	bPatchThreadFunctions();
	InitializeOffsetScanner();
}

NTSTATUS DriverEntry( IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryString )
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING uDeviceName, uDosDeviceName;
	unsigned int iCount = 0;
	PVOID pStackAttach = NULL;
	HANDLE hThreadHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;

	SCOPE(__FUNCTION__);
	RtlInitUnicodeString( &uDeviceName, DeviceName );
	RtlInitUnicodeString( &uDosDeviceName, DosDeviceName );

	// We are assigned to the device of null.sys and create a new symbolic link
	//ntStatus = IoCreateSymbolicLink( &uDosDeviceName, &uDeviceName );
	//if( !NT_SUCCESS(ntStatus) )
	//{
	//	KdPrint(("Fail on IoCreateSymbolicLink. ntStatus: 0x%08x", ntStatus));
	//	return ntStatus;
	//}

	KdPrint(("Loading driver. pDriverObject 0x%08x\n pRegistryString %wZ\n Build at "__TIME__" "__DATE__"\n",
		pDriverObject, pRegistryString));

	/* Only for testing purposes */
	IoCreateDevice( pDriverObject, 0,
		&uDeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &g_Device );
	IoCreateSymbolicLink( &uDosDeviceName, &uDeviceName );

	// Set new major functions
	for( iCount = 0; iCount < IRP_MJ_MAXIMUM_FUNCTION; iCount++ )
		pDriverObject->MajorFunction[iCount] = OnDispatch;

	pDriverObject->DriverUnload = DriverUnload;

	// Retrieve process offset in EPROCESS
	if( !GetProcessNameOffset() )
	{
		KdPrint(("Error getting process name offset!\n"));
		ntStatus = STATUS_UNSUCCESSFUL;
		return ntStatus;
	}

	// Retrieve kernel base pointer
	pStackAttach = (PVOID)&KeStackAttachProcess;
	g_pKrnlBase = KernelGetModuleBaseByPtr( pStackAttach, "KeStackAttachProcess" );
	if( !g_pKrnlBase )
	{
		KdPrint(("Error getting ntoskrnl base!\n"));
		ntStatus = STATUS_UNSUCCESSFUL;
		return ntStatus;
	}
	KdPrint(("Kernel base: 0x%08x\n", g_pKrnlBase));

	// Retrieve kernel name (differs from system to system)
	if( !GetModuleNameByBase( g_pKrnlBase, szKernelName, NULL ) )
	{
		KdPrint(("Error getting kernel name by base\n"));
		ntStatus = STATUS_UNSUCCESSFUL;
		return ntStatus;
	}
	KdPrint(("NT OS Kernel Name: %s\n", szKernelName));

	/* We ignore errors here. Cheat just won't work if something fails */
	InitializeObjectAttributes( &ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL );
	PsCreateSystemThread( &hThreadHandle, GENERIC_ALL, &ObjectAttributes, NULL, NULL,
		InitializeThread, NULL );
	ZwClose( hThreadHandle );

	DESCOPE();
	return ntStatus;
}

NTSTATUS OnDispatch( IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp )
{
	PIO_STACK_LOCATION irpStack = NULL;
	PVOID ioBuffer = NULL;
	ULONG inputBufferLength = 0, outputBufferLength = 0;

	SCOPE(__FUNCTION__);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	irpStack = IoGetCurrentIrpStackLocation( pIrp );
	switch( irpStack->MajorFunction )
	{
	case IRP_MJ_DEVICE_CONTROL:
		if( irpStack->Parameters.DeviceIoControl.IoControlCode ==
			IOCTL_FELITE_INITIALIZE )
		{
			KdPrint(("IOCTL_FELITE_INITIALIZE issued - Copying offsets and initializing hooks...\n"));
			inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
			ioBuffer = pIrp->AssociatedIrp.SystemBuffer;

			if( inputBufferLength < sizeof(syscall_offsets_t) )
			{
				pIrp->IoStatus.Status = STATUS_INVALID_BUFFER_SIZE;
				return STATUS_INVALID_BUFFER_SIZE;
			}

			pIrp->IoStatus.Status = STATUS_SUCCESS;
			return STATUS_SUCCESS;
		}
		break;
	default:
		break;
	}

	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	DESCOPE();
	// Call original function
	return pOrigOnDispatch(pDeviceObject, pIrp);
}

VOID DriverUnload( IN PDRIVER_OBJECT pDriverObject )
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE hThreadHandle;
	KdPrint(("Unloading Driver"));
}

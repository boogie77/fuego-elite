#include "Main.h"
#include "Toolset.h"
#include "ServicePatch.h"

ServiceDescriptorTableEntry_t tHookedTable;
PServiceDescriptorTableEntry_t tHookedShadow = NULL;
PServiceDescriptorTableEntry_t pServiceDescriptorTable = NULL;
DWORD dwPsConvertToGuiThreadAddr = 0, dwPsConvertToGuiThreadAddr2 = 0, dwKeInitThreadAddr = 0;
BOOLEAN bIsReady = FALSE;

PVOID ExchangeServiceTablePointer( DWORD Index, PVOID NewPointer )
{
	PVOID pRet = NULL;

	if( !bIsReady )
		return FALSE;

	/* Exchange in ServiceDescriptorTable */
	pRet = (PVOID)InterlockedExchange( (PLONG)&tHookedTable.ServiceTable[Index], (LONG)NewPointer );

	/* Exchange in first array of ServiceDescriptorTableShadow */
	InterlockedExchange( (PLONG)&tHookedShadow[0].ServiceTable[Index], (LONG)NewPointer );
	return pRet;
}

PVOID ExchangeServiceTableShadowPointer( DWORD Index, PVOID NewPointer )
{
	if( !bIsReady )
		return FALSE;

	/* Exchange in ServiceDescriptorTableShadow */
	return (PVOID)InterlockedExchange( (PLONG)&tHookedShadow[1].ServiceTable[Index], (LONG)NewPointer );
}

BOOLEAN bPatchThreadFunctions( VOID )
{
	DWORD dwKernelSize = 0;

	/*
	80583c7e 3b c3					cmp     eax,ebx
	80583c80 0f	85 8f fd 07 00		jne     nt!PsConvertToGuiThread+0xd1 (80603a15)
	80583c86 6a 01					push    1
	80583c88 ff 75 e0				push    dword ptr [ebp-20h]
	80583c8b ff 15 94 a2 69 80		call    dword ptr [nt!PspW32ProcessCallout (8069a294)]
	80583c91 3b c3					cmp     eax,ebx
	80583c93 7c 1a					jl      nt!PsConvertToGuiThread+0x147 (80583caf)
	*/
	BYTE pPsConvertToGuiThread_sig[] = { 0x3B, 0xC3, 0x0F, 0x85, 0xFF, 0xFF, 0xFF, 0xFF, 0x6A, 0x01,
		0xFF, 0x75, 0xE0, 0xFF, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0x3B,
		0xC3, 0x7C, 0x1A }; // XP SP2/SP3

	/*
	80583bfb 8b f0					mov     esi,eax
	80583bfd 33 db					xor     ebx,ebx
	80583bff 38 9e 40 01 00 00		cmp     byte ptr [esi+140h],bl
	80583c05 0f 84 b8 fd 07 00		je      nt!PsConvertToGuiThread+0x1e (806039c3)
	80583c0b 39 1d 94 a2 69 80		cmp     dword ptr [nt!PspW32ProcessCallout (8069a294)],ebx
	80583c11 0f 84 b6 fd 07 00		je      nt!PsConvertToGuiThread+0x30 (806039cd)
	*/
	BYTE pPsConvertToGuiThread_sig2[] = { 0x8B, 0xF0, 0x33, 0xDB, 0x38, 0x9E, 0x40, 0x01, 0x00, 0x00,
		0x0F, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x39, 0x1D, 0xFF, 0xFF,
		0xFF, 0xFF, 0x0F, 0x84, 0xFF, 0xFF, 0xFF, 0xFF }; // XP SP2/SP3

	/*
	057553d 49						dec     ecx
	8057553e 75 f8					jne     nt!KeInitThread+0x30 (80575538)
	80575540 8b 7d 24				mov     edi,dword ptr [ebp+24h]
	80575543 8a 47 64				mov     al,byte ptr [edi+64h]
	80575546 88 86 67 01 00 00		mov     byte ptr [esi+167h],al
	8057554c c6 86 41 01 00 00 01	mov     byte ptr [esi+141h],1
	80575553 c6 86 2a 01 00 00 01	mov     byte ptr [esi+12Ah],1
	*/
	BYTE pKeInitThread_sig[] = { 0x49, 0x75, 0xf8, 0x8b, 0xFF, 0x24, 0x8a, 0xFF, 0x64, 0x88, 0x86,
		0x67, 0x01, 0x00, 0x00, 0xC6, 0x86, 0x41, 0x01, 0x00, 0x00, 0x01,
		0xC6, 0x86, 0x2A, 0x01, 0x00, 0x00, 0x01 }; // XP SP2/SP3

	IMAGE_DOS_HEADER* pMz = (IMAGE_DOS_HEADER*)g_pKrnlBase;
	IMAGE_NT_HEADERS32* pNt;
	PVOID pMem = NULL;
	HANDLE hCsrssPid = GetCsrPid();
	PEPROCESS pCsrssEproc = NULL;
	KAPC_STATE ApcState;

	SCOPE(__FUNCTION__);

	// Get the size of the kernel image
	if( !pMz || pMz->e_magic != IMAGE_DOS_SIGNATURE )
		return FALSE;

	pNt = (IMAGE_NT_HEADERS32*)(((DWORD)g_pKrnlBase)+pMz->e_lfanew);
	if( !pNt || pNt->Signature != IMAGE_NT_SIGNATURE )
		return FALSE;

	dwKernelSize = pNt->OptionalHeader.SizeOfImage;
	KdPrint(("dwKernelSize: 0x%08x\n", dwKernelSize));

	if( !hCsrssPid || !dwKernelSize )
		return FALSE;

	// Get location of tables [0] = SSDT [1] = SSDT Shadow
	if( !GetServiceDescriptorTableShadow(&pServiceDescriptorTable) )
		return FALSE;

	// Copy KeServiceDescriptorTable
	tHookedTable.ServiceTable = ExAllocatePool( NonPagedPool,
		KeServiceDescriptorTable.NumberOfServices*sizeof(ULONG) );
	if( !tHookedTable.ServiceTable )
		return FALSE;

	RtlCopyMemory( tHookedTable.ServiceTable,
		KeServiceDescriptorTable.ServiceTable,
		KeServiceDescriptorTable.NumberOfServices*sizeof(ULONG) );
	tHookedTable.ParamTable = KeServiceDescriptorTable.ParamTable;
	tHookedTable.ServiceCounterTableBase = KeServiceDescriptorTable.ServiceCounterTableBase;
	tHookedTable.NumberOfServices = KeServiceDescriptorTable.NumberOfServices;

	KdPrint(("tHookedTable 0x%08x with %d services\n", &tHookedTable, tHookedTable.NumberOfServices));

	// Copy KeServiceDescriptorTableShadow which also inherits the normal SSDT
	PsLookupProcessByProcessId( (PVOID)hCsrssPid, &pCsrssEproc );
	if( !pCsrssEproc )
		return FALSE;

	tHookedShadow = (PServiceDescriptorTableEntry_t)ExAllocatePool( NonPagedPool,
		sizeof(ServiceDescriptorTableEntry_t)*2 );
	if( !tHookedShadow )
		return FALSE;

	KeStackAttachProcess( (PKPROCESS)pCsrssEproc, &ApcState );

	tHookedShadow[0].ServiceTable = ExAllocatePool( NonPagedPool,
		pServiceDescriptorTable[0].NumberOfServices*sizeof(ULONG) );
	tHookedShadow[1].ServiceTable = ExAllocatePool( NonPagedPool,
		pServiceDescriptorTable[1].NumberOfServices*sizeof(ULONG) );
	if( !tHookedShadow[0].ServiceTable || !tHookedShadow[1].ServiceTable )
		return FALSE;

	RtlCopyMemory( tHookedShadow[0].ServiceTable,
		pServiceDescriptorTable[0].ServiceTable,
		pServiceDescriptorTable[0].NumberOfServices*sizeof(ULONG) );
	RtlCopyMemory( tHookedShadow[1].ServiceTable,
		pServiceDescriptorTable[1].ServiceTable,
		pServiceDescriptorTable[1].NumberOfServices*sizeof(ULONG) );

	tHookedShadow[0].ParamTable = pServiceDescriptorTable[0].ParamTable;
	tHookedShadow[0].ServiceCounterTableBase = pServiceDescriptorTable[0].ServiceCounterTableBase;
	tHookedShadow[0].NumberOfServices = pServiceDescriptorTable[0].NumberOfServices;

	tHookedShadow[1].ParamTable = pServiceDescriptorTable[1].ParamTable;
	tHookedShadow[1].ServiceCounterTableBase = pServiceDescriptorTable[1].ServiceCounterTableBase;
	tHookedShadow[1].NumberOfServices = pServiceDescriptorTable[1].NumberOfServices;

	KdPrint(("tHookedShadow[0]: 0x%08x with %d services\n", &tHookedShadow[0], tHookedShadow[0].NumberOfServices));
	KdPrint(("tHookedShadow[1]: 0x%08x with %d services\n", &tHookedShadow[1], tHookedShadow[1].NumberOfServices));

	KeUnstackDetachProcess( &ApcState );
	ObDereferenceObject( pCsrssEproc );

	// Get addresses
	KdPrint(("Starting pattern scan\n"));
	pMem = ExAllocatePool( NonPagedPool, sizeof(pKeInitThread_sig) );
	RtlCopyMemory( pMem, pKeInitThread_sig, sizeof(pKeInitThread_sig) );
	dwKeInitThreadAddr = FindPattern( (DWORD)g_pKrnlBase, (DWORD)dwKernelSize, (BYTE*)pMem, sizeof(pKeInitThread_sig), 0x23 );
	ExFreePool( pMem );

	pMem = ExAllocatePool( NonPagedPool, sizeof(pPsConvertToGuiThread_sig) );
	RtlCopyMemory( pMem, pPsConvertToGuiThread_sig, sizeof(pPsConvertToGuiThread_sig) );
	dwPsConvertToGuiThreadAddr = FindPattern( (DWORD)g_pKrnlBase, (DWORD)dwKernelSize, (BYTE*)pMem,
		sizeof(pPsConvertToGuiThread_sig), 0x1D );
	ExFreePool( pMem );

	pMem = ExAllocatePool( NonPagedPool, sizeof(pPsConvertToGuiThread_sig2) );
	RtlCopyMemory( pMem, pPsConvertToGuiThread_sig2, sizeof(pPsConvertToGuiThread_sig2) );
	dwPsConvertToGuiThreadAddr2 = FindPattern( (DWORD)g_pKrnlBase, (DWORD)dwKernelSize,
		(BYTE*)pMem, sizeof(pPsConvertToGuiThread_sig2), 0x22 );
	ExFreePool( pMem );
	KdPrint(("Pattern scan finished\n"));

	if( !dwKeInitThreadAddr || !dwPsConvertToGuiThreadAddr || !dwPsConvertToGuiThreadAddr2 )
		return FALSE;

	// Enable write-bit
	_asm
	{
			push eax
			mov eax, CR0
			and eax, 0FFFEFFFFh
			mov CR0, eax
			pop eax
			cli
	}

	KdPrint(("Going to patch functions\n"));
	KdPrint(("dwKeInitThreadAddr: 0x%08x\ndwPsConvertToGuiThreadAddr: 0x%08x\ndwPsConvertToGuiThreadAddr2: 0x%08x\n",
		dwKeInitThreadAddr, dwPsConvertToGuiThreadAddr, dwPsConvertToGuiThreadAddr2));

	// Patch that shit!
	InterlockedExchangePointer( (PVOID)dwKeInitThreadAddr, &tHookedTable ); // mov _KTHREAD.ServiceTable, tHookedTable
	InterlockedExchangePointer( (PVOID)dwPsConvertToGuiThreadAddr2, &tHookedTable ); // cmp _KTHREAD.ServiceTable, tHookedTable
	InterlockedExchangePointer( (PVOID)dwPsConvertToGuiThreadAddr, tHookedShadow ); // mov _KTHREAD.ServiceTable, tHookedShadow

	// Disable write-bit
	_asm
	{
			sti
			push eax
			mov eax, CR0
			or eax, NOT 0FFFEFFFFh
			mov CR0, eax
			pop eax
	}


	bIsReady = TRUE;
	DESCOPE();
	return bIsReady;
}

BOOLEAN bUnpatchThreadFunctions( VOID )
{

	SCOPE(__FUNCTION__);
	// Enable write-bit
	_asm
	{
			push eax
			mov eax, CR0
			and eax, 0FFFEFFFFh
			mov CR0, eax
			pop eax
			cli
	}

	// Unpatch
	InterlockedExchangePointer( (PVOID)dwKeInitThreadAddr, &KeServiceDescriptorTable );
	InterlockedExchangePointer( (PVOID)dwPsConvertToGuiThreadAddr2, &KeServiceDescriptorTable );
	InterlockedExchangePointer( (PVOID)dwPsConvertToGuiThreadAddr, pServiceDescriptorTable );

	// Disable write-bit
	_asm
	{
			sti
			push eax
			mov eax, CR0
			or eax, NOT 0FFFEFFFFh
			mov CR0, eax
			pop eax
	}

	bIsReady = FALSE;
	DESCOPE();
	return bIsReady;
}

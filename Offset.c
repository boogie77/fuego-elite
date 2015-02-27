#include "Main.h"
#include "Toolset.h"
#include "Offset.h"
#include "Cheat.h"

WORD wSetPixel, wExtEscape, wGetPixel, wCreateCompatibleDC;
BOOLEAN bGotIndexes = FALSE;
BOOLEAN bGotOffsets = FALSE;
cheat_offsets_t tCheatOffsets;

BYTE pInfoString_sig[] = { 0x83, 0xC4, 0x04, 0x8D, 0x44, 0xED, 0x00 };

/*
HUD_GetStudioModelInterface (client.dll)
097BADFE   56				  push esi
097BADFF   8B 74 24 10        mov esi,dword ptr ss:[esp+10]
097BAE03   57				  push edi
097BAE04   B9 2E 00 00 00	  mov ecx,2E
097BAE09   BF 508D8A09		  mov edi,client.098A8D50 <- Our address
[....]
*/
BYTE pPlayerInfo_sig[] = { 0x56, 0x8B, 0x74, 0x24, 0x10, 0x57, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xBF };

/*
GetEntityByIndex (hw.dll)
0363959F   83 C4 04				add esp,4
036395A2   85 C0				test eax,eax
036395A4   7C 1E				jl short hw.036395C4
036395A6   3B 05 C0 BD 64 04    cmp eax,dword ptr ds:[464BDC0]
036395AC   7D 16				jge short hw.036395C4
036395AE   8D 04 40				lea eax,dword ptr ds:[eax+eax*2]
036395B1   8B 15 FCFB7C03		mov edx,dword ptr ds:[37CFBFC] <- Our address
[....]
*/
BYTE ppEntity_sig[] = { 0x83, 0xC4, 0x04, 0x85, 0xC0, 0x7C, 0xFF, 0x3B, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x7D, 0xFF,
						0x8D, 0xFF, 0xFF, 0x8B, 0x15 };
/*
(hw.dll)
03639066   8B 8C CA 48 0B 00 00		mov ecx,dword ptr ds:[edx+ecx*8+B48]
0363906D   89 4C 24 04				mov dword ptr ss:[esp+4],ecx
03639071   8B 90 4C 0B 00 00		mov edx,dword ptr ds:[eax+B4C]
03639077   8B 0D E4 74 79 03		mov ecx,dword ptr ds:[37974E4] <- Our address
[....]
*/
BYTE pFov_sig[] = { 0x8B, 0x8C, 0xCA, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x4C, 0x24, 0x04, 0x8B, 0x90,
						0xFF, 0xFF, 0xFF, 0xFF, 0x8B, 0x0D };

/*
(hw.dll)
03637972   85 C0				test eax,eax
03637974   75 01				jnz short hw.03637977
03637976   C3					retn
03637977   81 38 14 02 00 00	cmp dword ptr ds:[eax],214
0363797D   74 03				je short hw.03637982
0363797F   33 C0				xor eax,eax
03637981   C3					retn
03637982   8B 0D BC 36 0A 04    mov ecx,dword ptr ds:[40A36BC] <- ScreenX
03637988   89 48 04				mov dword ptr ds:[eax+4],ecx
0363798B   8B 54 24 04			mov edx,dword ptr ss:[esp+4]
0363798F   A1 C0360A04			mov eax,dword ptr ds:[40A36C0] <- ScreenY
*/
BYTE pScreen_sig[] = { 0x85, 0xC0, 0x75, 0xFF, 0xC3, 0x81, 0x38, 0xFF, 0xFF, 0xFF, 0xFF,
						 0x74, 0xFF, 0x33, 0xC0, 0xC3, 0x8B, 0x0D };


WORD GetGdiServiceOffset( PVOID pGdiDllBase, char* szFunction)
{
	/* This gets the system call offset for a GDI function.
	   The system call stub is always a few bytes under the
	   exported function, so we go to the end of the function
	   through searching for 'retn' and then search for the
	   first occurence of 'mov eax'.
   */
	DWORD dwFunction = 0;
	BOOLEAN bFoundRetn = FALSE, bFoundMov = FALSE;

	if( !ReadEAT(pGdiDllBase, szFunction, &dwFunction) )
		return 0;

	// We assume a function is not bigger than one page
	while( dwFunction < dwFunction+PAGE_SIZE )
	{
		// Search for the first occurence of 'retn'
		if( *(BYTE*)dwFunction == 0xC2 )
		{
			bFoundRetn = TRUE;
			break;
		}

		dwFunction++;
	}

	if( bFoundRetn == FALSE )
		return 0;

	// Search for the first occurence of 'mov eax'
	while( dwFunction < dwFunction+0xFF )
	{
		if( *(BYTE*)dwFunction == 0xB8 )
		{
			bFoundMov = TRUE;
			break;
		}

		dwFunction++;
	}

	if( bFoundMov )
	{
		dwFunction += sizeof(BYTE); // Skip mov opcode
		return ( (*(WORD*)dwFunction)-0x1000 ); // Return offset
	}

	return 0;
}

WORD GetNtServiceOffset( PVOID pNtDllBase, char* szFunction )
{
	DWORD dwFunction = 0;

	if( !ReadEAT(pNtDllBase, szFunction, &dwFunction) )
		return 0;

	return *(WORD*)(dwFunction+sizeof(BYTE)); // Skip mov opcode and return offset
}

VOID GetIndexes( DWORD ImageBase, DWORD ImageSize )
{
	PMDL Mdl = NULL;
	PVOID pSecureAddress = NULL;
	SYSTEM_OFFSETS tOffsets;

	if( bGotIndexes )
		return;

	/* TODO: Do this through mapping the file into a process and without an image notify routine */
	SCOPE(__FUNCTION__);
	__try
	{
		Mdl = ( (PVOID)ImageBase, ImageSize, FALSE, FALSE, NULL );
		if( !Mdl )
		{
			KdPrint(("Allocating MDL failed\n"));
			return;
		}
		MmProbeAndLockPages( Mdl, KernelMode, IoReadAccess );
		pSecureAddress = MmGetSystemAddressForMdlSafe( Mdl, HighPagePriority );
		if( !pSecureAddress )
		{
			KdPrint(("Getting secure address failed\n"));
			MmUnlockPages( Mdl );
			IoFreeMdl( Mdl );
		}

		tOffsets.wSetPixel = GetGdiServiceOffset( pSecureAddress, "SetPixel" );
		tOffsets.wExtEscape = GetGdiServiceOffset( pSecureAddress, "ExtEscape" );
		tOffsets.wCreateCompatibleDC = GetGdiServiceOffset( pSecureAddress, "CreateCompatibleDC" );
		tOffsets.wGetPixel = GetGdiServiceOffset( pSecureAddress, "GetPixel" );

		MmUnlockPages( Mdl );
		IoFreeMdl( Mdl );

		KdPrint(("wSetPixel: 0x%2X wExtEscape: 0x%02X wCreateCompatibleDC: 0x%02X wGetPixel: 0x%02X\n",
			tOffsets.wSetPixel, tOffsets.wExtEscape, tOffsets.wCreateCompatibleDC, tOffsets.wGetPixel));
		if( !tOffsets.wSetPixel || !tOffsets.wExtEscape || !tOffsets.wCreateCompatibleDC || !tOffsets.wGetPixel )
			return;
		/* Now as we have the indexes, hook! */
		HookSystemFunctions( &tOffsets );
		bGotIndexes = TRUE;
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		KdPrint(("Exception! Code: 0x%08x\n", GetExceptionCode()));
		return;
	}
	DESCOPE();
}

VOID OfReadOffsets( VOID )
{
	/* TODO: This should be way more safe */

	DWORD dwAddress = 0;
	PTEB Teb = NULL;
	PLDR_MODULE pModule = NULL;
	PLIST_ENTRY pNext, pList;

	_asm
	{
		push eax
		mov eax, fs:[18h]
		mov dwAddress, eax
		pop eax
	}
	KdPrint(("TEB: 0x%08x", dwAddress));
	Teb = (PTEB)dwAddress;
	pList = &(Teb->Peb->LoaderData->InLoadOrderModuleList);
	pNext = pList->Flink;
	while( pNext != pList )
	{
		pModule = CONTAINING_RECORD(pNext, LDR_MODULE, InLoadOrderModuleList);
		KdPrint(("Found module %wZ", &pModule->BaseDllName));
		if( !wcscmp(pModule->BaseDllName.Buffer, L"hw.dll") &&
			(!tCheatOffsets.dwEntity || !tCheatOffsets.dwFov || !tCheatOffsets.dwRefParams) /* Don't scan twice */ )
		{
			KdPrint(("Scanning in hw.dll"));
			tCheatOffsets.dwEntity = FindPattern( (DWORD)pModule->BaseAddress, pModule->SizeOfImage, (BYTE*)ppEntity_sig, sizeof(ppEntity_sig), 0x14 );
			tCheatOffsets.dwFov = FindPattern( (DWORD)pModule->BaseAddress, pModule->SizeOfImage, (BYTE*)pFov_sig, sizeof(pFov_sig), 0x13 );
			tCheatOffsets.dwRefParams = (DWORD)(((DWORD)pModule->BaseAddress)+0x1A2BF); // TODO: Replace with pattern
		}
		else if( !wcscmp(pModule->BaseDllName.Buffer, L"client.dll") &&
				  !tCheatOffsets.dwHudInfo /* Don't scan twice */ )
		{
			KdPrint(("Scanning in client.dll"));
			tCheatOffsets.dwHudInfo = FindPattern( (DWORD)pModule->BaseAddress, pModule->SizeOfImage, (BYTE*)pPlayerInfo_sig, sizeof(pPlayerInfo_sig), 0xC );
		}
		pModule = NULL;
		pNext = pNext->Flink;
	}

	KdPrint(("dwRefParams: 0x%08x dwEntity: 0x%08x dwFov: 0x%08x dwHudInfo: 0x%08x\n",
		tCheatOffsets.dwRefParams, tCheatOffsets.dwEntity, tCheatOffsets.dwFov, tCheatOffsets.dwHudInfo));

	if( tCheatOffsets.dwEntity != 0 &&
		tCheatOffsets.dwFov != 0 &&
		tCheatOffsets.dwRefParams != 0 &&
		tCheatOffsets.dwHudInfo != 0 )
	{
		bGotOffsets = TRUE;
	}
}

VOID ImageNotify( PUNICODE_STRING FullImageName, HANDLE TargetProcessId, IMAGE_INFO* ImageInfo )
{
	PEPROCESS pProcess = NULL;
	char szName[32];

	//KdPrint(("FullImageName: %wZ TargetProcessId: %d ImageBase: 0x%08x ImageSize: 0x%08x\n",
	//	FullImageName, TargetProcessId, ImageInfo->ImageBase, ImageInfo->ImageSize));
	if( wcsstr(FullImageName->Buffer, L"gdi32.dll") )
		GetIndexes( (DWORD)ImageInfo->ImageBase, (DWORD)ImageInfo->ImageSize );
}

BOOLEAN InitializeOffsetScanner( VOID )
{
	NTSTATUS ntRet = PsSetLoadImageNotifyRoutine( ImageNotify );
	return (ntRet==STATUS_SUCCESS)?TRUE:FALSE;
}

BOOLEAN DestroyOffsetScanner( VOID )
{
	NTSTATUS ntRet = PsRemoveLoadImageNotifyRoutine( ImageNotify );
	return (ntRet==STATUS_SUCCESS)?TRUE:FALSE;
}

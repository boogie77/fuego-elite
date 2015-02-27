#include "Main.h"
#include "Toolset.h"
#include "Offset.h"
#include "Cheat.h"
#include "ServicePatch.h"
#include "Sdk.h"
#include "Calcscreen.h"
#include "Math.h"

NtGdiExtEscape_t ogNtGdiExtEscape = NULL;
NtGdiSetPixel_t NtGdiSetPixel = NULL;

#define MAX_PLAYERS 32
#define OFFSET_WAIT 8000

HANDLE hProcessId = NULL;
BOOLEAN bInitialized = FALSE;

/* Required values to draw */
float fCurrentFov = 90.0;
int iScreenX = 1152;
int iScreenY = 864;
vec3_t fLocalViewAngles;
vec3_t fLocalViewOrigin;
ref_params_t *tRefParams = NULL;
/* Required structures containing player information */
hud_player_info_t *tPlayerInfo = NULL;
cl_entity_t *tEntities = NULL;

#define RGB(r,g,b) ((COLORREF)(((BYTE)(r)|((WORD)((BYTE)(g))<<8))|(((DWORD)(BYTE)(b))<<16)))

/* From xept :o */
void DrawBox(HDC DCcs, int x, int y, int size,COLORREF colors)
{
	int l1;
	int linesize = size/2;

	for (l1=0;l1<size;l1++)
		NtGdiSetPixel(DCcs,(x-linesize)+l1,y-linesize,colors);
	for(l1=0;l1<size;l1++)
		NtGdiSetPixel(DCcs,(x-linesize)+l1,y+linesize,colors);
	for(l1=0;l1<size;l1++)
		NtGdiSetPixel(DCcs,x-linesize,(y-linesize)+l1,colors);
	for (l1=0;l1<size;l1++)
		NtGdiSetPixel(DCcs,x+linesize,(y-linesize)+l1,colors);
}

BOOLEAN SecureCopyMemory( PVOID pAddress, PVOID pDestination, SIZE_T SizeOfCopy )
{
	PMDL pMdl = NULL;
	PVOID pSafeAddress = NULL;

	pMdl = IoAllocateMdl( pAddress, SizeOfCopy, FALSE, FALSE, NULL );
	if( !pMdl )
		return FALSE;

	__try
	{
		MmProbeAndLockPages( pMdl, KernelMode, IoReadAccess );
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl( pMdl );
		return FALSE;
	}

	pSafeAddress = MmGetSystemAddressForMdlSafe( pMdl, NormalPagePriority );
	if( !pSafeAddress )
		return FALSE;

	RtlCopyMemory( pDestination, pSafeAddress, SizeOfCopy );
	MmUnlockPages( pMdl );
	IoFreeMdl( pMdl );
	return TRUE;
}

INT NTAPI hkNtGdiExtEscape( HDC hDC,
							IN OPTIONAL PWCHAR pDriver,
							IN INT nDriver,
							INT Escape,
							INT InSize,
						    OPTIONAL LPSTR UnsafeInData,
							INT OutSize,
							OPTIONAL LPSTR UnsafeOutData
						   )
{
	/* This gets called by HUD_Redraw so if the calling process
	   is hl.exe we're in the right context */

	NTSTATUS ntRet = STATUS_SUCCESS;
	char szName[32];
	int iCounter = 0, iLocalEntity = 0;
	static LONGLONG lStart = 0;
	LONGLONG lElapsed = 0;
	DWORD dwAddress;
	cl_entity_t *pEnt = NULL;
	ref_params_t *pRefParams = NULL;
	KFLOATING_SAVE FloatSave;


	__try
	{

	SCOPE(__FUNCTION__);
	ntRet = ogNtGdiExtEscape( hDC, pDriver, nDriver, Escape, InSize, UnsafeInData, OutSize, UnsafeOutData );
	GetProcessName(szName, PsGetCurrentProcess());

	if( !strcmp(szName, GAME_EXECUTABLE) )
	{
		//KeSaveFloatingPointState( &kSave );
		KdPrint(("ExtEscape call from CS."));

		/* Get Process ID */
		//hProcessId = PsGetCurrentProcessId();

		DrawBox( hDC, 250, 320, 100, RGB(255,0,0) );

		if( bGotOffsets )
		{
			pEnt = *(cl_entity_t**)(*(DWORD*)tCheatOffsets.dwEntity);
			pRefParams = (ref_params_t*)(*(DWORD*)tCheatOffsets.dwRefParams);
			fCurrentFov = *(float*)(*(DWORD*)tCheatOffsets.dwFov);

			KeSaveFloatingPointState(&FloatSave);
			for( iCounter = 0; iCounter < MAX_PLAYERS; iCounter++ )
				KdPrint(("Ent %d %d", pEnt[iCounter].index, (int)pEnt[iCounter].origin[0]));
			if( OsrProbeForRead((PUCHAR)pRefParams, sizeof(ref_params_t)) )
			{
				KdPrint(("ref %d %d", pRefParams->health, (int)pRefParams->viewangles[0]));
			}
			KdPrint(("Fov: %d", (int)fCurrentFov));

			KeRestoreFloatingPointState(&FloatSave);

		}

		if( !bGotOffsets && !lStart )
			lStart = GetTickCount(); // Initialize timer

		lElapsed = GetTickCount()-lStart;
		if( !bGotOffsets && lElapsed >= OFFSET_WAIT )
		{
			KdPrint((""__FUNCTION__": Going to do offset scan..."));
			OfReadOffsets();
			lStart = 0; // Reset timer
			return ntRet; // Before we don't have offsets, don't do anything
		}

		/* Get local entity */
		for( iCounter = 0; iCounter < MAX_PLAYERS; iCounter++ )
		{
			if( tPlayerInfo[iCounter].thisplayer == 1 )
			{
				iLocalEntity = iCounter;
				break;
			}
			KdPrint(("Ent.x %d", tEntities[iCounter].origin[0]));
		}


		/* Loop through all entities and draw/aim */
		for( iCounter = 0; iCounter < sizeof(tEntities); iCounter++ )
		{
			/* Verifiy that this entity is valid */
			if( iCounter != iLocalEntity &&
				tEntities[iCounter].player &&
				tEntities[iCounter].curstate.solid &&
				!tEntities[iCounter].curstate.spectator &&
				tEntities[iCounter].curstate.messagenum >= tEntities[iLocalEntity].curstate.messagenum )
			{
				KdPrint(("Drawing on valid entity number %d\n", iCounter));

				/* Calculate drawing coordinates */
				if( WorldToScreen(tEntities[iCounter].origin, fDraw, fLocalViewAngles, fLocalViewOrigin, fCurrentFov,
					iScreenX, iScreenY) )
				{
					KdPrint(("Calculated coordinates: %f %f\n", fDraw[0], fDraw[1]));
					DrawBox( hDC, fDraw[0], fDraw[1], 50, RGB(0, 0, 0) );
				}
			}
		}
		KeRestoreFloatingPointState( &kSave );
	}

	DESCOPE();
	return ntRet;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("BadBad Fail"));
		return ntRet;
	}
}

VOID HookSystemFunctions( PSYSTEM_OFFSETS pOffsets )
{
	ogNtGdiExtEscape = (NtGdiExtEscape_t)ExchangeServiceTableShadowPointer( pOffsets->wExtEscape, hkNtGdiExtEscape );
	NtGdiSetPixel = (NtGdiSetPixel_t)tHookedShadow[1].ServiceTable[pOffsets->wSetPixel];
}

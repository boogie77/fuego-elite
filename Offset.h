#ifndef __OFFSET__H
#define __OFFSET__H

typedef struct cheat_offsets_s
{
	DWORD dwEntity;
	DWORD dwHudInfo;
	DWORD dwRefParams;
	DWORD dwFov;
	DWORD dwScreenX;
	DWORD dwScreenY;
}cheat_offsets_t;

typedef struct _SYSTEM_OFFSETS
{
	WORD wExtEscape;
	WORD wSetPixel;
	WORD wGetPixel;
	WORD wCreateCompatibleDC;
} SYSTEM_OFFSETS, *PSYSTEM_OFFSETS;

BOOLEAN InitializeOffsetScanner( VOID );
BOOLEAN DestroyOffsetScanner( VOID );
extern cheat_offsets_t tCheatOffsets;
extern BOOLEAN bGotOffsets;
VOID OfReadOffsets( VOID );

#endif

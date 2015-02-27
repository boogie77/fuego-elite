#ifndef __CHEAT__H
#define __CHEAT__H

typedef INT ( NTAPI *NtGdiExtEscape_t )(HDC hDC,
										IN OPTIONAL PWCHAR pDriver,
										IN INT nDriver,
										INT Escape,
										INT InSize,
										OPTIONAL LPSTR UnsafeInData,
										INT OutSize,
										OPTIONAL LPSTR UnsafeOutData
										);

typedef COLORREF ( NTAPI *NtGdiSetPixel_t )(IN HDC hdcDst,
											 IN INT x,
											 IN INT y,
											 IN COLORREF crColor
											);

VOID HookSystemFunctions( PSYSTEM_OFFSETS pOffsets );

#endif

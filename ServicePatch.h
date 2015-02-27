#ifndef __SDTHOOK__H
#define __SDTHOOK__H

PVOID ExchangeServiceTablePointer( DWORD Index, PVOID NewPointer );
PVOID ExchangeServiceTableShadowPointer( DWORD Index, PVOID NewPointer );
BOOLEAN bPatchThreadFunctions( VOID );
BOOLEAN bUnpatchThreadFunctions( VOID );

extern ServiceDescriptorTableEntry_t tHookedTable;
extern PServiceDescriptorTableEntry_t tHookedShadow;

#endif

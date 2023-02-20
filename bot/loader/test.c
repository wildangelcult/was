#include <Windows.h>
#include <ntdef.h>
#include <winternl.h>
#include "ntpsapi.h"

int main()
{
	// Path to the image file from which the process will be created
	UNICODE_STRING NtImagePath;
	RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Windows\\System32\\calc.exe");

	// Create the process parameters
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

	// Initialize the PS_CREATE_INFO structure
	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;

	PS_ATTRIBUTE_LIST AttributeList;
	//memset(&AttributeList, 0, sizeof(PS_ATTRIBUTE_LIST));
	AttributeList.TotalLength = sizeof(PS_ATTRIBUTE_LIST);
	AttributeList.Attributes.Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList.Attributes.Size = NtImagePath.Length;
	AttributeList.Attributes.Value = (ULONG_PTR)NtImagePath.Buffer;
	AttributeList.Attributes.ReturnLength = 0;

	// Create the process
	HANDLE hProcess, hThread = NULL;
	NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, ProcessParameters, &CreateInfo, &AttributeList);

	// Clean up
	RtlDestroyProcessParameters(ProcessParameters);
}


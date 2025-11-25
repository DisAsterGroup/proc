#pragma once

#include <Windows.h>
#include <winternl.h>

PPEB GetLocalPeb()
{
    HANDLE hProcess = GetCurrentProcess();

    PROCESS_BASIC_INFORMATION* pBasicInfo = new PROCESS_BASIC_INFORMATION();

    DWORD dwReturnLength = 0;

    HMODULE hNTDLL = LoadLibraryA("ntdll");

    if (!hNTDLL)
        return 0;

    FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");

    if (!fpNtQueryInformationProcess)
        return 0;

    typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        DWORD ProcessInformationLength,
        PDWORD ReturnLength
        );

    _NtQueryInformationProcess ntQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;

    ntQueryInformationProcess(hProcess, ProcessBasicInformation, pBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);

    return pBasicInfo->PebBaseAddress;
}

PPEB GetRemotePeb(HANDLE hProcess)
{
    PROCESS_BASIC_INFORMATION* pBasicInfo = new PROCESS_BASIC_INFORMATION();

    DWORD dwReturnLength = 0;

    HMODULE hNTDLL = LoadLibraryA("ntdll");

    if (!hNTDLL)
        return 0;

    FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");

    if (!fpNtQueryInformationProcess)
        return 0;

    typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        DWORD ProcessInformationLength,
        PDWORD ReturnLength
        );

    _NtQueryInformationProcess ntQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;

    ntQueryInformationProcess(hProcess, ProcessBasicInformation, pBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);

    return pBasicInfo->PebBaseAddress;
}

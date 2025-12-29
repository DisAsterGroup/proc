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

BOOL KillProc(DWORD dwPid)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, dwPid);
    if (!hProcess) {
        printf("[KillProc] OpenProcess failed: %lu\n", GetLastError());
        return false;
    }

    BOOL ok = TerminateProcess(hProcess, 1);
    if (!ok) {
        printf("[KillProc] TerminateProcess failed: %lu\n", GetLastError());
    }

    CloseHandle(hProcess);
    return ok;
}
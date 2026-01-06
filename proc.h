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

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
};

struct THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    TEB* Teb;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
};

PTEB GetRemoteTeb(HANDLE hProcess, HANDLE hThread)
{
    HMODULE hNTDLL = LoadLibraryA("ntdll");

    if (!hNTDLL)
        return 0;

    FARPROC fpNtQueryInformationThread = GetProcAddress(hNTDLL, "NtQueryInformationThread");

    if (!fpNtQueryInformationThread)
        return 0;

    typedef NTSTATUS(WINAPI* _NtQueryInformationThread)(
        HANDLE          ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID           ThreadInformation,
        ULONG           ThreadInformationLength,
        PULONG          ReturnLength
    );

    _NtQueryInformationThread ntQueryInformationThread = (_NtQueryInformationThread)fpNtQueryInformationThread;

    THREAD_BASIC_INFORMATION* tbi = new THREAD_BASIC_INFORMATION();
    ntQueryInformationThread(
        hThread,
        (THREADINFOCLASS)0, /* ThreadBasicInformation */
        tbi,
        sizeof(THREAD_BASIC_INFORMATION),
        nullptr
    );

    return tbi->Teb;
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

NTSTATUS NtSuspendProcess(HANDLE hProcess)
{
    HMODULE hNTDLL = LoadLibraryA("ntdll");

    if (!hNTDLL)
        return -1;

    FARPROC fpNtSuspendProcess = GetProcAddress(hNTDLL, "NtSuspendProcess");

    if (!fpNtSuspendProcess)
        return -1;

    typedef NTSTATUS(NTAPI* _NtSuspendProcess)(
        HANDLE          ProcessHandle
    );

    _NtSuspendProcess ntSuspendProcess = (_NtSuspendProcess)fpNtSuspendProcess;

    return ntSuspendProcess(hProcess);
}
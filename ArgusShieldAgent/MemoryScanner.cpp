
// MemoryScanner.cpp — Manual Mapping & Process Hollowing Detection Engine
//
// Implements all 10 steps of the detection specification:
//   Step 1:  Process enumeration
//   Step 2:  Safe process open
//   Step 3:  Memory region scanning (VirtualQueryEx)
//   Step 4:  PE header scan (MZ detection in private memory)
//   Step 5:  Process hollowing detection (entry point check)
//   Step 6:  Thread start address analysis
//   Step 7:  Module list vs memory comparison
//   Step 8:  Heuristic engine (combine signals → score)
//   Step 9:  Real-time logging
//   Step 10: Detection score

#include "MemoryScanner.h"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

// Dynamically loaded ntdll functions 

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef NTSTATUS(NTAPI* pfnNtQueryInformationThread)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static pfnNtQueryInformationProcess g_NtQueryInformationProcess = nullptr;
static pfnNtQueryInformationThread  g_NtQueryInformationThread = nullptr;

static void InitNtFunctions()
{
    static bool initialized = false;
    if (initialized) return;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll)
    {
        g_NtQueryInformationProcess = (pfnNtQueryInformationProcess)
            GetProcAddress(hNtdll, "NtQueryInformationProcess");
        g_NtQueryInformationThread = (pfnNtQueryInformationThread)
            GetProcAddress(hNtdll, "NtQueryInformationThread");
    }
    initialized = true;
}

// Processes to skip (system + our own services) 

static const std::unordered_set<std::string> g_SkipProcesses = {
    // Windows core
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe",
    "taskhostw.exe", "runtimebroker.exe", "searchindexer.exe",
    "securityhealthservice.exe", "msmpeng.exe", "nissrv.exe",
    // Windows shell & UI
    "explorer.exe", "sihost.exe", "fontdrvhost.exe", "ctfmon.exe",
    "conhost.exe", "applicationframehost.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "searchui.exe", "searchapp.exe",
    "textinputhost.exe", "dllhost.exe", "taskmgr.exe", "mmc.exe",
    // Windows services & tools
    "spoolsv.exe", "lsm.exe", "wuauclt.exe", "audiodg.exe",
    "wmiprvse.exe", "wmi.exe", "trustedinstaller.exe",
    "tiworker.exe", "msiexec.exe", "consent.exe",
    "smartscreen.exe", "sgrmbroker.exe", "registry.exe",
    "dashost.exe", "devicecensus.exe", "compattelrunner.exe",
    "musnotification.exe", "backgroundtaskhost.exe",
    // Browsers (heavy private memory usage is normal)
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
    // Dev tools
    "devenv.exe", "msvsmon.exe", "windbg.exe", "windbgx.exe",
    "x64dbg.exe", "x32dbg.exe", "code.exe", "vscode.exe",
    "msbuild.exe", "dotnet.exe",
    // Common apps known to use RWX memory legitimately
    "teams.exe", "slack.exe", "discord.exe", "zoom.exe",
    "spotify.exe", "steam.exe",
    // ArgusShield own processes
    "argusshieldservice.exe", "argusshieldagent.exe",
    "argusshielddashboard.exe"
};

// String helpers 

static std::string ToLowerStr(const std::string& s)
{
    std::string r = s;
    for (auto& c : r) c = (char)tolower((unsigned char)c);
    return r;
}

static std::string GetFilenameFromPath(const std::string& path)
{
    auto pos = path.find_last_of("\\/");
    if (pos != std::string::npos)
        return path.substr(pos + 1);
    return path;
}

// Technique / severity string conversion 

const char* DetectionTypeToTechnique(DetectionType type)
{
    switch (type)
    {
    case DetectionType::ManualMapping:    return "Manual Mapping Injection";
    case DetectionType::ProcessHollowing: return "Process Hollowing";
    case DetectionType::SuspiciousThread: return "Suspicious Thread";
    case DetectionType::HiddenModule:     return "Hidden Module";
    case DetectionType::RWXMemory:        return "RWX Memory";
    default:                              return "Unknown";
    }
}

const char* DetectionTypeToSeverity(DetectionType type)
{
    switch (type)
    {
    case DetectionType::ManualMapping:    return "Critical";
    case DetectionType::ProcessHollowing: return "Critical";
    case DetectionType::SuspiciousThread: return "High";
    case DetectionType::HiddenModule:     return "High";
    case DetectionType::RWXMemory:        return "Medium";
    default:                              return "Medium";
    }
}

// STEP 1 — Process Enumeration

struct ProcessInfo
{
    DWORD       pid = 0;
    DWORD       parentPid = 0;
    std::string name;
};

static std::vector<ProcessInfo> EnumerateProcesses()
{
    std::vector<ProcessInfo> procs;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return procs;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe))
    {
        do
        {
            ProcessInfo pi;
            pi.pid = pe.th32ProcessID;
            pi.parentPid = pe.th32ParentProcessID;
            
            char narrowName[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, narrowName, MAX_PATH, NULL, NULL);
            pi.name = narrowName;
            
            procs.push_back(pi);
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return procs;
}

// STEP 3 — Memory Region Scanning

struct SuspiciousRegion
{
    ULONG_PTR baseAddress;
    SIZE_T    regionSize;
    DWORD     protect;
    DWORD     type;         // MEM_PRIVATE, MEM_IMAGE, MEM_MAPPED
    bool      isExecutable;
    bool      isRWX;
    bool      isPrivate;
    bool      hasMZHeader;  // Filled in Step 4
};

static bool IsExecutableProtection(DWORD protect)
{
    return (protect & PAGE_EXECUTE) ||
           (protect & PAGE_EXECUTE_READ) ||
           (protect & PAGE_EXECUTE_READWRITE) ||
           (protect & PAGE_EXECUTE_WRITECOPY);
}

static bool IsRWXProtection(DWORD protect)
{
    return (protect & PAGE_EXECUTE_READWRITE) != 0;
}

static std::string ProtectionToString(DWORD protect)
{
    if (protect & PAGE_EXECUTE_READWRITE)  return "EXECUTE_READWRITE";
    if (protect & PAGE_EXECUTE_WRITECOPY)  return "EXECUTE_WRITECOPY";
    if (protect & PAGE_EXECUTE_READ)       return "EXECUTE_READ";
    if (protect & PAGE_EXECUTE)            return "EXECUTE";
    if (protect & PAGE_READWRITE)          return "READWRITE";
    if (protect & PAGE_READONLY)           return "READONLY";
    if (protect & PAGE_WRITECOPY)          return "WRITECOPY";
    if (protect & PAGE_NOACCESS)           return "NOACCESS";
    return "UNKNOWN";
}

static std::vector<SuspiciousRegion> ScanMemoryRegions(HANDLE hProcess)
{
    std::vector<SuspiciousRegion> regions;

    MEMORY_BASIC_INFORMATION mbi = {};
    ULONG_PTR addr = 0;

    while (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        // Only interested in committed memory
        if (mbi.State == MEM_COMMIT)
        {
            bool isExec = IsExecutableProtection(mbi.Protect);
            bool isPriv = (mbi.Type == MEM_PRIVATE);

            // Key detection rule: executable AND private memory is suspicious
            if (isExec && isPriv)
            {
                SuspiciousRegion reg;
                reg.baseAddress = (ULONG_PTR)mbi.BaseAddress;
                reg.regionSize  = mbi.RegionSize;
                reg.protect     = mbi.Protect;
                reg.type        = mbi.Type;
                reg.isExecutable = true;
                reg.isRWX       = IsRWXProtection(mbi.Protect);
                reg.isPrivate   = true;
                reg.hasMZHeader = false;
                regions.push_back(reg);
            }
        }

        // Move to next region
        ULONG_PTR nextAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (nextAddr <= addr)
            break;  // Overflow guard
        addr = nextAddr;
    }

    return regions;
}

// STEP 4 — PE Header Scan (MZ Detection in Private Memory)

static bool CheckMZHeader(HANDLE hProcess, ULONG_PTR address)
{
    BYTE header[2] = {};
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(hProcess, (LPCVOID)address, header, 2, &bytesRead))
        return false;

    if (bytesRead < 2)
        return false;

    // Check for "MZ" — DOS signature
    return (header[0] == 'M' && header[1] == 'Z');
}

// Extended PE validation: verify it's a real PE, not just "MZ" coincidence
static bool ValidatePEHeader(HANDLE hProcess, ULONG_PTR address, SIZE_T regionSize)
{
    if (regionSize < 0x200)  // Minimum for a valid PE
        return false;

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader = {};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)address, &dosHeader, sizeof(dosHeader), &bytesRead))
        return false;

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    // Verify e_lfanew is reasonable
    if (dosHeader.e_lfanew < sizeof(IMAGE_DOS_HEADER) || (DWORD)dosHeader.e_lfanew > regionSize - sizeof(IMAGE_NT_HEADERS))
        return false;

    // Read NT headers
    IMAGE_NT_HEADERS ntHeaders = {};
    if (!ReadProcessMemory(hProcess, (LPCVOID)(address + dosHeader.e_lfanew),
        &ntHeaders, sizeof(ntHeaders), &bytesRead))
        return false;

    // Verify PE signature
    return (ntHeaders.Signature == IMAGE_NT_SIGNATURE);
}

// STEP 5 — Process Hollowing Detection (Entry Point Check)

struct EntryPointInfo
{
    bool        valid = false;
    ULONG_PTR   pebImageBase = 0;
    DWORD       entryPointRVA = 0;
    ULONG_PTR   expectedEntryPoint = 0;
    ULONG_PTR   actualEntryPoint = 0;
    bool        mismatch = false;
};

static EntryPointInfo CheckEntryPoint(HANDLE hProcess)
{
    EntryPointInfo info;

    if (!g_NtQueryInformationProcess)
        return info;

    // Query PEB address
    struct PROCESS_BASIC_INFORMATION_LOCAL
    {
        PVOID     Reserved1;
        PVOID     PebBaseAddress;
        PVOID     Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID     Reserved3;
    };

    PROCESS_BASIC_INFORMATION_LOCAL pbi = {};
    ULONG returnLength = 0;

    NTSTATUS status = g_NtQueryInformationProcess(
        hProcess, 0 /* ProcessBasicInformation */,
        &pbi, sizeof(pbi), &returnLength);

    if (status != 0 || !pbi.PebBaseAddress)
        return info;

    // Read ImageBase from PEB
#ifdef _WIN64
    SIZE_T imageBaseOffset = 0x10;
#else
    SIZE_T imageBaseOffset = 0x08;
#endif

    PVOID imageBase = nullptr;
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + imageBaseOffset,
        &imageBase, sizeof(imageBase), &bytesRead))
        return info;

    info.pebImageBase = (ULONG_PTR)imageBase;

    // Read PE headers from the process's image base
    IMAGE_DOS_HEADER dosHeader = {};
    if (!ReadProcessMemory(hProcess, imageBase, &dosHeader, sizeof(dosHeader), &bytesRead))
        return info;

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        // If we can't even read a valid DOS header at the PEB image base,
        // that's a strong indicator of hollowing (image was unmapped)
        info.valid = true;
        info.mismatch = true;
        return info;
    }

    IMAGE_NT_HEADERS ntHeaders = {};
    if (!ReadProcessMemory(hProcess, (PBYTE)imageBase + dosHeader.e_lfanew,
        &ntHeaders, sizeof(ntHeaders), &bytesRead))
        return info;

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
    {
        info.valid = true;
        info.mismatch = true;
        return info;
    }

    info.valid = true;
    info.entryPointRVA = ntHeaders.OptionalHeader.AddressOfEntryPoint;
    info.expectedEntryPoint = (ULONG_PTR)imageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint;

    // Check if the entry point region is MEM_PRIVATE (not MEM_IMAGE)
    // For a legitimate process, the entry point should be in MEM_IMAGE memory
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQueryEx(hProcess, (LPCVOID)info.expectedEntryPoint, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if (mbi.Type == MEM_PRIVATE)
        {
            // Entry point is in private memory — strong hollowing indicator
            info.mismatch = true;
        }
    }

    info.actualEntryPoint = info.expectedEntryPoint;
    return info;
}

// STEP 6 — Thread Start Address Analysis

struct ThreadInfo
{
    DWORD     threadId;
    ULONG_PTR startAddress;
    bool      startsInPrivateMemory;
};

static std::vector<ThreadInfo> AnalyzeThreads(HANDLE hProcess, DWORD pid)
{
    std::vector<ThreadInfo> results;

    if (!g_NtQueryInformationThread)
        return results;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return results;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);

    if (Thread32First(hSnap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID != pid)
                continue;

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread)
                continue;

            // Query thread start address
            // ThreadQuerySetWin32StartAddress = 9
            PVOID startAddr = nullptr;
            ULONG returnLength = 0;
            NTSTATUS status = g_NtQueryInformationThread(
                hThread, 9 /* ThreadQuerySetWin32StartAddress */,
                &startAddr, sizeof(startAddr), &returnLength);

            CloseHandle(hThread);

            if (status != 0 || !startAddr)
                continue;

            ThreadInfo ti;
            ti.threadId = te.th32ThreadID;
            ti.startAddress = (ULONG_PTR)startAddr;
            ti.startsInPrivateMemory = false;

            // Check if thread start address is in private memory
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQueryEx(hProcess, startAddr, &mbi, sizeof(mbi)) == sizeof(mbi))
            {
                if (mbi.Type == MEM_PRIVATE && IsExecutableProtection(mbi.Protect))
                {
                    ti.startsInPrivateMemory = true;
                }
            }

            if (ti.startsInPrivateMemory)
                results.push_back(ti);

        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    return results;
}

// STEP 7 — Module List vs Memory Comparison

struct ModuleRegion
{
    ULONG_PTR base;
    SIZE_T    size;
};

static std::vector<ModuleRegion> GetLoadedModules(HANDLE hProcess)
{
    std::vector<ModuleRegion> modules;

    HMODULE hMods[1024];
    DWORD cbNeeded = 0;

    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
    {
        DWORD count = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++)
        {
            MODULEINFO modInfo = {};
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
            {
                ModuleRegion mr;
                mr.base = (ULONG_PTR)modInfo.lpBaseOfDll;
                mr.size = modInfo.SizeOfImage;
                modules.push_back(mr);
            }
        }
    }

    return modules;
}

static bool IsAddressInModuleList(ULONG_PTR address, const std::vector<ModuleRegion>& modules)
{
    for (const auto& mod : modules)
    {
        if (address >= mod.base && address < mod.base + mod.size)
            return true;
    }
    return false;
}

// STEPS 8-10 — Heuristic Engine + Scoring + Scan Orchestration

std::vector<MemoryScanResult> ScanProcess(DWORD pid, const std::string& processName)
{
    std::vector<MemoryScanResult> results;
    InitNtFunctions();

    // STEP 2: Open process safely 
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (!hProcess)
        return results;

    // STEP 3: Scan memory regions 
    std::vector<SuspiciousRegion> suspiciousRegions = ScanMemoryRegions(hProcess);

    if (suspiciousRegions.empty())
    {
        // No suspicious regions — check entry point only (for hollowing)
        // then clean up
    }

    // STEP 7: Get module list 
    std::vector<ModuleRegion> modules = GetLoadedModules(hProcess);

    // STEP 4 + STEP 7 combined: Check each suspicious region 
    for (auto& region : suspiciousRegions)
    {
        // Check if this region is backed by a known module
        bool inModuleList = IsAddressInModuleList(region.baseAddress, modules);

        // Check for MZ/PE header
        bool hasMZ = CheckMZHeader(hProcess, region.baseAddress);
        bool validPE = false;
        if (hasMZ)
        {
            validPE = ValidatePEHeader(hProcess, region.baseAddress, region.regionSize);
        }

        region.hasMZHeader = validPE;

        // STEP 8: Heuristic rules 

        // RULE 1: Manual Mapping Detection
        // PE header found in private memory AND not in module list
        if (validPE && !inModuleList)
        {
            MemoryScanResult result;
            result.type = DetectionType::ManualMapping;
            result.pid = pid;
            result.processName = processName;
            result.address = region.baseAddress;
            result.regionSize = region.regionSize;
            result.score = 9;  // Very high confidence

            std::ostringstream ss;
            ss << "PE header found in private memory at 0x"
               << std::hex << region.baseAddress
               << " (Size: 0x" << region.regionSize
               << ", Protection: " << ProtectionToString(region.protect)
               << ") — not in module list. Possible manually mapped DLL.";
            result.description = ss.str();
            results.push_back(result);
            continue;  // Don't double-count this region
        }

        // RULE 2: Hidden Module
        // Executable private region not in module list (no PE header)
        if (!inModuleList && !validPE)
        {
            // Only flag larger regions to reduce noise — small allocations
            // are common in JIT compilers, etc.
            if (region.regionSize >= 0x1000)  // At least one page
            {
                MemoryScanResult result;
                result.type = DetectionType::HiddenModule;
                result.pid = pid;
                result.processName = processName;
                result.address = region.baseAddress;
                result.regionSize = region.regionSize;
                result.score = 5;

                std::ostringstream ss;
                ss << "Executable private memory at 0x"
                   << std::hex << region.baseAddress
                   << " (Size: 0x" << region.regionSize
                   << ", Protection: " << ProtectionToString(region.protect)
                   << ") — not backed by any module.";
                result.description = ss.str();

                // Boost score for RWX memory
                if (region.isRWX)
                {
                    result.score += 2;
                    result.type = DetectionType::RWXMemory;
                    result.description += " [RWX — high risk]";
                }

                results.push_back(result);
            }
        }
    }

    // STEP 5: Process Hollowing Detection
    EntryPointInfo epInfo = CheckEntryPoint(hProcess);
    if (epInfo.valid && epInfo.mismatch)
    {
        MemoryScanResult result;
        result.type = DetectionType::ProcessHollowing;
        result.pid = pid;
        result.processName = processName;
        result.address = epInfo.pebImageBase;
        result.regionSize = 0;
        result.score = 8;

        std::ostringstream ss;
        ss << "Entry point in private memory detected. PEB ImageBase: 0x"
           << std::hex << epInfo.pebImageBase
           << ", EntryPoint RVA: 0x" << epInfo.entryPointRVA
           << " — possible process hollowing.";
        result.description = ss.str();
        results.push_back(result);
    }

    // STEP 6: Thread Start Address Analysis
    std::vector<ThreadInfo> suspiciousThreads = AnalyzeThreads(hProcess, pid);
    for (const auto& thread : suspiciousThreads)
    {
        // Check if the thread start address overlaps with a known suspicious region
        bool overlapsManualMap = false;
        for (const auto& r : results)
        {
            if (r.type == DetectionType::ManualMapping &&
                thread.startAddress >= r.address &&
                thread.startAddress < r.address + r.regionSize)
            {
                overlapsManualMap = true;
                break;
            }
        }

        if (overlapsManualMap)
        {
            // Already flagged as manual mapping, boost score
            for (auto& r : results)
            {
                if (r.type == DetectionType::ManualMapping &&
                    thread.startAddress >= r.address &&
                    thread.startAddress < r.address + r.regionSize)
                {
                    r.score += 2;  // Thread executing in mapped PE → very high risk
                    r.description += " [Thread executing in this region — confirmed active injection]";
                    break;
                }
            }
        }
        else
        {
            // Standalone suspicious thread finding
            MemoryScanResult result;
            result.type = DetectionType::SuspiciousThread;
            result.pid = pid;
            result.processName = processName;
            result.address = thread.startAddress;
            result.regionSize = 0;
            result.score = 7;

            std::ostringstream ss;
            ss << "Thread " << thread.threadId
               << " starts in private executable memory at 0x"
               << std::hex << thread.startAddress
               << " — possible shellcode execution.";
            result.description = ss.str();
            results.push_back(result);
        }
    }

    CloseHandle(hProcess);
    return results;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 1 (orchestration): Scan All Processes
// ═══════════════════════════════════════════════════════════════════════════════

std::vector<MemoryScanResult> ScanAllProcesses()
{
    std::vector<MemoryScanResult> allResults;

    DWORD myPid = GetCurrentProcessId();

    std::vector<ProcessInfo> processes = EnumerateProcesses();

    for (const auto& proc : processes)
    {
        // Skip PID 0 (System Idle) and PID 4 (System)
        if (proc.pid == 0 || proc.pid == 4)
            continue;

        // Skip our own process
        if (proc.pid == myPid)
            continue;

        // Skip known safe processes
        std::string lowerName = ToLowerStr(proc.name);
        if (g_SkipProcesses.count(lowerName))
            continue;

        // Scan this process
        auto results = ScanProcess(proc.pid, proc.name);

        // Assign the parentPid to all results and filter by score
        for (auto& r : results)
        {
            r.parentPid = proc.parentPid;
            if (r.score >= 5)  // Score threshold for reporting
            {
                allResults.push_back(std::move(r));
            }
        }
    }

    return allResults;
}

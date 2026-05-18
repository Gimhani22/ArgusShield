// ============================================================================
// MemoryScanner.h — Manual Mapping & Process Hollowing Detection
//
// Scans all running processes for signs of:
//   1. Manual Mapping  — PE header in private executable memory, not in module list
//   2. Process Hollowing — entry point mismatch, PEB image base discrepancy
//   3. Suspicious Threads — threads starting in private executable memory
//   4. Hidden Modules — executable regions not backed by any loaded module
//
// This module runs inside ArgusShieldAgent and produces MemoryScanResult
// entries that the Agent scores, logs, and (optionally) blocks.
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <vector>

// ── Detection types ─────────────────────────────────────────────────────────

enum class DetectionType
{
    ManualMapping,      // PE header found in private memory, not in module list
    ProcessHollowing,   // Entry point mismatch or PEB image base altered
    SuspiciousThread,   // Thread start address in private executable memory
    HiddenModule,       // Executable private region not backed by a module
    RWXMemory           // Private read-write-execute memory (generic signal)
};

// ── Scan result ─────────────────────────────────────────────────────────────

struct MemoryScanResult
{
    DetectionType   type           = DetectionType::RWXMemory;
    DWORD           pid            = 0;
    DWORD           parentPid      = 0;
    std::string     processName;
    ULONG_PTR       address        = 0;
    SIZE_T          regionSize     = 0;
    int             score          = 0;     // Heuristic score for this finding
    std::string     description;            // Human-readable detail
};

// ── Public API ──────────────────────────────────────────────────────────────

// Scan every non-excluded process on the system.
// Returns a list of suspicious findings.
std::vector<MemoryScanResult> ScanAllProcesses();

// Scan a single process by PID.
std::vector<MemoryScanResult> ScanProcess(DWORD pid, const std::string& processName);

// Convert DetectionType to the technique string used in events.log / pipe
const char* DetectionTypeToTechnique(DetectionType type);

// Convert DetectionType to a severity string
const char* DetectionTypeToSeverity(DetectionType type);

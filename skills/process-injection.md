# Process Injection Detection (MITRE T1055)

## Injection Techniques
- **Classic DLL Injection** (T1055.001): CreateRemoteThread + LoadLibraryA
- **PE Injection** (T1055.002): WriteProcessMemory + manual PE mapping
- **Process Hollowing** (T1055.012): Create suspended → NtUnmapViewOfSection → write new PE
- **Thread Execution Hijacking** (T1055.003): SuspendThread → SetThreadContext → ResumeThread
- **APC Injection** (T1055.004): QueueUserAPC to target thread
- **NTFS Transaction** (T1055.013): Process Doppelganging via transactional NTFS

## Detection with Volatility
1. `windows.malfind` — finds PAGE_EXECUTE_READWRITE regions with MZ headers
2. Compare `windows.pslist` vs `windows.psscan` — hollowed processes show discrepancies
3. `windows.vadinfo` — VAD tree analysis for suspicious memory regions
4. `windows.handles` — check for cross-process handles (OpenProcess with PROCESS_ALL_ACCESS)

## Key Indicators
- Non-image-backed executable memory (no file on disk)
- MZ/PE header in non-file-mapped region
- Process with wrong parent (hollowed svchost.exe with explorer.exe parent)
- Thread start address outside any known module
- Unbacked executable pages in legitimate processes

## False Positive Considerations
- .NET JIT compilation creates RWX pages legitimately
- Some AV products inject monitoring DLLs
- Browser JIT engines (V8, SpiderMonkey) use RWX memory

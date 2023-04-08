import ctypes as ct
from ctypes import wintypes as wt

__k32 = ct.WinDLL("kernel32", use_last_error=True)

class SYSTEM_INFO(ct.Structure):
    _fields_ = [
        ("dwOemId", wt.DWORD),
        ("dwPageSize", wt.DWORD),
        ("lpMinimumApplicationAddress", wt.LPVOID),
        ("lpMaximumApplicationAddress", wt.LPVOID),
        ("dwActiveProcessorMask", wt.PDWORD),
        ("dwNumberOfProcessors", wt.DWORD),
        ("dwProcessorType", wt.DWORD),
        ("dwAllocationGranularity", wt.DWORD),
        ("wProcessorLevel", wt.WORD),
        ("wProcessorRevision", wt.WORD),
    ]

class MEMORY_BASIC_INFORMATION(ct.Structure):
    _fields_ = [
        ("BaseAddress", wt.LPVOID),
        ("AllocationBase", wt.LPVOID),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD),
        ("RegionSize", ct.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]

GetLastError = __k32.GetLastError
GetLastError.restype = wt.DWORD

FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000

FormatMessageW = __k32.FormatMessageW
FormatMessageW.argtypes = wt.DWORD, ct.c_void_p, wt.DWORD, wt.DWORD, ct.c_wchar_p, wt.DWORD, ct.c_void_p
FormatMessageW.restype = wt.DWORD

LocalFree = __k32.LocalFree
LocalFree.argtypes = ct.c_void_p,
LocalFree.restype = ct.c_void_p

CloseHandle = __k32.CloseHandle
CloseHandle.argtypes = wt.HANDLE,
CloseHandle.restype = wt.BOOL

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

OpenProcess = __k32.OpenProcess
OpenProcess.argtypes = wt.DWORD, wt.BOOL, wt.DWORD
OpenProcess.restype = wt.HANDLE

ReadProcessMemory = __k32.ReadProcessMemory
ReadProcessMemory.argtypes = wt.HANDLE, wt.LPCVOID, wt.LPVOID, ct.c_size_t, ct.POINTER(ct.c_size_t)
ReadProcessMemory.restype = wt.BOOL

GetSystemInfo = __k32.GetSystemInfo
GetSystemInfo.argtypes = ct.POINTER(SYSTEM_INFO),
GetSystemInfo.restype = None

PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000

VirtualQueryEx = __k32.VirtualQueryEx
VirtualQueryEx.argtypes = wt.HANDLE, wt.LPCVOID, ct.POINTER(MEMORY_BASIC_INFORMATION), ct.c_size_t
VirtualQueryEx.restype = ct.c_size_t

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = -1

CreateToolhelp32Snapshot = __k32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = wt.DWORD, wt.DWORD
CreateToolhelp32Snapshot.restype = wt.HANDLE

class PROCESSENTRY32(ct.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", wt.PULONG),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ct.c_char * wt.MAX_PATH),
    ]

Process32First = __k32.Process32First
Process32First.argtypes = wt.HANDLE, ct.POINTER(PROCESSENTRY32)
Process32First.restype = wt.BOOL

Process32Next = __k32.Process32Next
Process32Next.argtypes = wt.HANDLE, ct.POINTER(PROCESSENTRY32)
Process32Next.restype = wt.BOOL

class WinApiError(Exception):
    def __init__(self):
        super().__init__()
        self.code = GetLastError()
        self._get_message()

    def _get_message(self):
        buffer = ct.c_wchar_p()
        buffer_ref = ct.cast(ct.byref(buffer), ct.c_wchar_p)
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, None, self.code, 0, buffer_ref, 0, None)
        self.message = buffer.value
        LocalFree(buffer)

    def __str__(self):
        return f"WinApiError({self.code}): {self.message}"

import struct
from typing import Optional, Any

from .winapi import *
from .memory_region import MemoryRegion

class Process:
    def __init__(self, handle: int, close_handle: bool = True) -> None:
        """
        :param handle: Windows process handle, requires PROCESS_QUERY_INFORMATION and PROCESS_VM_READ access rights
        :param close_handle: Whether to close the handle when the object is destroyed
        """
        self.handle = handle
        self.close_handle = close_handle
        self.memory_regions = list[MemoryRegion]()

    def detect_memory_regions(self) -> None:
        """
        Detects all memory regions that are readable for the process.
        Call this method before using find_pattern.

        :raises WinApiError: If failed to retrieve memory region information
        """
        self.memory_regions.clear()

        sys_info = SYSTEM_INFO()
        GetSystemInfo(ct.byref(sys_info))

        mem_basic_info = MEMORY_BASIC_INFORMATION()
        mem_basic_info_size = ct.sizeof(mem_basic_info)
        current_address = sys_info.lpMinimumApplicationAddress
        max_address = sys_info.lpMaximumApplicationAddress

        while current_address < max_address:
            size = VirtualQueryEx(self.handle, current_address, ct.byref(mem_basic_info), mem_basic_info_size)
            if size != mem_basic_info_size:
                raise WinApiError
            if mem_basic_info.Protect & PAGE_EXECUTE_READWRITE > 0 and mem_basic_info.State == MEM_COMMIT:
                self.memory_regions.append(MemoryRegion(self.handle, mem_basic_info))
            current_address += mem_basic_info.RegionSize

    def clear_cache(self) -> None:
        """
        Clears the cache buffer of all memory regions.
        Use this method if you want to read new values from the process memory
        in the subsequent find_pattern call.
        """
        for region in self.memory_regions:
            region.clear_cache()

    def find_pattern(self, pattern: bytes, mask: Optional[bytes] = None, offset: int = 0) -> Optional[int]:
        """
        Searches for a pattern in the memory regions of the process.

        Process memory is read only once and cached between subsequent calls.
        Use clear_cache to clear the cache.

        Call detect_memory_regions before using this method.

        :param pattern: Byte pattern to search for
        :param mask: Optional mask for the pattern, 0 for bytes that should be ignored
        :param offset: Optional offset to add to the address of the pattern
        :return: Address of the pattern or None if the pattern was not found
        :raises ValueError: If the pattern and mask have different lengths
        :raises WinApiError: If the memory at one of the regions could not be read
        """
        if mask is None:
            for region in self.memory_regions:
                address = region.buffer.raw.find(pattern)
                if address != -1:
                    return region.base_address + address + offset
            return None

        pattern_size = len(pattern)
        if len(mask) != pattern_size:
            raise ValueError("Pattern and mask have different lengths")

        for region in self.memory_regions:
            raw_bytes = region.buffer.raw
            for i in range(region.region_size - pattern_size):
                if all(mask[j] == 0 or raw_bytes[i+j] == pattern[j] for j in range(pattern_size)):
                    return region.base_address + i + offset

        return None

    def read_bytes(self, address: int, size: int) -> bytes:
        """
        Reads raw bytes from the process memory.

        :param address: Starting address to read from
        :param size: Number of bytes to read
        :return: Bytes read from the process memory
        :raises WinApiError: If the memory at the specified address could not be read
        """
        buffer = ct.create_string_buffer(size)
        bytes_read = ct.c_size_t()
        success = ReadProcessMemory(self.handle, address, buffer, size, ct.byref(bytes_read))
        if not success or bytes_read.value != size:
            raise WinApiError
        return buffer.raw

    def read_values(self, address: int, format: str | bytes) -> tuple[Any, ...]:
        """
        Reads values from the process memory. Number of bytes to read is determined by the format string.

        :param address: Starting address to read from
        :param format: Format string for struct.unpack
        :return: Tuple of values
        :raises WinApiError: If the memory at the specified address could not be read
        """
        size = struct.calcsize(format)
        data = self.read_bytes(address, size)
        return struct.unpack(format, data)

    def __del__(self) -> None:
        if self.close_handle:
            CloseHandle(self.handle)

    @staticmethod
    def from_pid(pid: int) -> "Process":
        """
        Creates a Process object from a process ID.

        :param pid: Process ID
        :return: Process object
        :raises WinApiError: If the process could not be opened
        """
        handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if handle == 0:
            raise WinApiError
        return Process(handle)

    @staticmethod
    def from_name(name: str) -> Optional["Process"]:
        """
        Creates a Process object from a process name.

        :param name: Process name
        :return: Process object or None if the process is not running
        :raises WinApiError: If the process list could not be retrieved
        """
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            raise WinApiError
        process = PROCESSENTRY32()
        process.dwSize = ct.sizeof(process)
        try:
            if not Process32First(snapshot, ct.byref(process)):
                raise WinApiError
            while process.szExeFile != name.encode():
                if not Process32Next(snapshot, ct.byref(process)):
                    return None
            return Process.from_pid(process.th32ProcessID)
        finally:
            CloseHandle(snapshot)

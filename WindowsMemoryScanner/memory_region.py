from .winapi import *

class MemoryRegion:
    def __init__(self, handle: int, mem_basic_info: MEMORY_BASIC_INFORMATION) -> None:
        """
        :param handle: Windows process handle, requires PROCESS_VM_READ access right
        :param mem_basic_info: Memory region information
        """
        self.handle = handle
        self.base_address = mem_basic_info.BaseAddress
        self.region_size = mem_basic_info.RegionSize
        self._buffer = None

    @property
    def buffer(self) -> ct.Array[ct.c_char]:
        """
        :return: Cached buffer of the memory region
        :raises WinApiError: If failed to read memory region
        """
        if self._buffer is None:
            self._buffer = ct.create_string_buffer(self.region_size)
            self._read_buffer()

        return self._buffer

    def clear_cache(self) -> None:
        """
        Clears the cache buffer.
        """
        self._buffer = None

    def _read_buffer(self) -> None:
        """
        Reads the memory region into the buffer.

        :raises WinApiError: If failed to read memory region
        """
        bytes_read = ct.c_size_t()
        success = ReadProcessMemory(self.handle, self.base_address, self.buffer, self.region_size, ct.byref(bytes_read))
        if not success or bytes_read.value != self.region_size:
            raise WinApiError

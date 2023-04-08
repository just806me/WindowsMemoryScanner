# WindowsMemoryScanner

Basic python library for scanning and reading process memory in Windows.

## Usage

```python
from WindowsMemoryScanner import Process

# Open a process by name
process = Process.from_name("notepad.exe")

# Open a process by PID
process = Process.from_pid(1234)

# Find a pattern in the process memory
process.detect_memory_regions() # First, we need to detect the memory regions in the process

pattern = b"\x68\x65\x00\x00\x6f" # Byte pattern to search for
mask    = b"\xFF\xFF\x00\x00\xFF" # Optional mask for the pattern: 0x00 = ignore byte, other = match byte
offset  = 8 # Optional offset to add to the address
address = process.find_pattern(pattern, mask, offset)

# Find pattern is designed to be called multiple times, reading the memory only once. To force a re-read, clear the cache:
process.clear_cache()

# Read n bytes at the address
data = process.read_bytes(address, 8)

# Read primitive values at the address, refer to the struct module for format characters
a, b = process.read_values(address, 'ld')
```

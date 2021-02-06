#!/usr/bin/env python3
from pwn import *

# Notes:
# - for every binary challenge, write a script in python using pwntools to automate the process
# - first solve the binary locally, then solve it remotely on the given server to get the flag
# - to connect to the remote server in the terminal, use netcat to open a TCP connection with: nc IP PORT
# - the flag will generally be in a file called flag on the remote server, needing to read this file to receive the flag.
# - this usually involves hacking a program to get a shell, from there running cat flag to read the contents
# - to run this file, we use chmod +x pwn-challenge.py
# - using log.info() is just like a print statement, yet is seperated so you know it came from pwntools. Helpful for debugging.
# - when reading the binary data b'7\x13', we can tell this is two bytes as x13 is what the terminal prints for 0x13, and 7 is simply the ascii for 0x37.
# - the UNIX command strings takes a file as an argument and outputs all the redable text within the raw binary

# To solve the challenge locally, we do the following, which attaches 'p' to the binary file 'intro'.
#p = process("./intro")

# However, to connect to the remote server, we do the following, which creates a TCP
# connection to the given remote server
p = remote("plsdonthaq.me", 1025)

# From the binary's output, we then want to strip out the address value from within the curly braces.
# To do so, we do the following, which reads through the binary's ouput until it sees the first opening curly brace.
p.recvuntil("{")

# Now that we are up to the position directly after the opening curly brace,
# we read everything until the closing curly brace. However, since it reads up to 
# and including the closing curly brace, we use the python string modifier to remove 
# the last element from the string. Also, since we want this as an integer, we use the Python
# int wrapper, with the second paramater defining the base. We assign this result to 'a'.
a = int(p.recvuntil("}")[:-1], 0)

# We then finish reading the rest of the output and simply discard it
p.recvuntil("form!")

# To send this value 'a' as input to the binary, we use the following, making sure to convert it back to a string
p.sendline(str(a))

# Next, to extract the hex value from the binary output, we use the same strategy as before.
p.recvuntil("MINUS ")
b = int(p.recvuntil("!")[:-1], 0)

# Since it asks to enter the first value minus this value in hexadecimal form, we use 
# the Python hex wrapper.
p.sendline(hex(a-b))

# We now want to extract another address from the binary output.
p.recvuntil("me ")
c = int(p.recvuntil(" "), 0)

# We then want to simply discard the rest of the output. Another way of doing so is
# the following, which simply reads until the next '\n'. Hence it's the same as p.recvuntil("\n")
#p.recvline()

# Then we have to send this 16 bit address value as 2 bytes in little endian form.
# We do the following, which converts the address into a byte sequence in binary data,
# rather than in plain text. This is in little endian by default since the system is,
# yet there is a parameter in p16 which allows you to specify endianness.
#p.sendline(p16(c)) 

# Also, a way to simplify the above two lines is to write the following. This reads up
# until the first string, and then sends the second string.
p.sendlineafter("\n", p16(c))

# Next we are given the 4 byte value xV$\x12. We can tell this is 4 bytes as the
# bytes are x, V, 4 and \x12. Also, all the challenge binaries will be 32 bits,
# which have 4 byte addresses. We do the following to get the integer value for this
# 32 bit binary, and then use the Python str wrapper.
p.recvuntil("next line)\n")
d = str(u32(p.recv(4)))
p.sendline(d)

# Then we want to send this value in hex form. We extract the value from the output,
# discard the rest of the output and then send this value using the Python hex wrapper.
p.recvuntil("sent: ")
e = int(p.recvline()[:-1])

p.recvuntil("form!\n")
p.sendline(hex(e))

# Finally we want to do addition to two numbers. We simply have to extract them
# and then send back a string with the result of their sum.
p.recvuntil("is ")
f = int(p.recvuntil(" "))

p.recvuntil(" ")
g = int(p.recvuntil("?")[:-1])
p.recvline()

p.sendline(str(f+g))

# It then asks for the secret flag hidden in this file. By using strings,
# we found this was password, so we simply send this to get shell access
p.sendline("password")

# We keep this at the end of our script, so that once it is done we can have control 
# of the input and output the same way as if we ran the binary in the terminal.
p.interactive()

#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# When we first load up the program, it asks for a password. Since the source code
# is provided, we can see it compares our input to 'trivial', and if equal it then
# displays several 'photos' to display. 

# Looking at option 3, we can see the filename is determine by #define FLAG, whereas
# the other photos are simply strings for their filenames. If I try to view this
# photo, it simply exits.

# I then tried to access the fourth (non-existent) item in the struct by giving
# input as '4', and it displayed 'Image id must be -143358560, but supplied id is 4'
# Hence, this suggests we can access memory outside of this struct to try and read
# the flag file (instead of viewing a photo as intended).

# So, I determined that if we give a negative number, we will be able to access a
# part of the buffer we are passing input to. I determined this was -16, ensuring that
# we add an extra byte to align the buffer. At this location in the buffer, since it
# wants an address for a filename, we can simply give it another address in this
# buffer, and at this address we can put the file we want to read. Since we know the 
# flag is always stored in a file called 'flag', we can simply use './flag\x00'.

# However, when giving the program this payload, it states 'Image id must be 3551533, 
# but supplied id is -16'. What this is doing is comparing the ascii value '61-' with
# the value '-16'. This is because the system is little endian, and it is simply
# reading the first four bytes of the buffer to compare to '-16'. Hence, we need
# these values to be equal.Unfortunately, I was unable to figure out how to achieve 
# this. Whilst changing the value of the fourth byte given as input can change the
# result, it was still too difficult to produce something remotely close to '-16'.

# The script:

p = remote("plsdonthaq.me", 5003)

# Since the password is trivial, we simply send this as input.
p.sendline(b"trivial")

# Then when asking to view a photo, we send our payload, which consists of'-16', 
# followed by any byte to align the buffer, then an address in the buffer, and finally
# at this address the string './flag\x00' as the filename.
p.sendline(b"-16"+ b"\0" + p32(0x804c068) + b"./flag\x00")

p.interactive()
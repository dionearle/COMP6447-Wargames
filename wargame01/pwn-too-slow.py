#!/usr/bin/env python3
from pwn import *

# While debugging, we want to solve the challenge locally
#p = process("./too-slow")

# To get the flag, we connect to the remote server
p = remote("plsdonthaq.me", 1026)

# the binary asks us 10 consecutive math questions, so we simply enter a loop
# since the process for entering each one is the same
i = 0
while(i < 10):

    # First we get the first line of output
    p.recvline()  

    # We then scan in the first number on the line
    a = int(p.recvuntil(" ")[:-1])

    # Next we scan the second number following it
    p.recvuntil(" ")
    b = int(p.recvuntil(" ")[:-1])

    # We then send the sum of these two numbers as a string
    p.sendline(str(a + b))

    i += 1

# Allows us to control input and output in the terminal
p.interactive()
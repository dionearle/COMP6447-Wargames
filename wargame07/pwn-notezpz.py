#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# The script:
PROGNAME = "challenges/./notezpz"
REMOTEIP = "plsdonthaq.me"
REMOTEPORT = 7003

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


p.interactive()
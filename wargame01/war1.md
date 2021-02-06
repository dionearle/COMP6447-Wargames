intro
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMS1pbnRybyIsImlhdCI6MTU5MTMyOTQ3MCwiaXAiOiIxOTMuODIuMjI1LjEwMSJ9.tj4KfV7T1a0mHrqVwiyqBT1Aj7OhhFFyQYT4z4mzpOk}

General overview of problems faced
-------------------------------------
For this challenge, I had to create a Python script that utilised pwntools to automate the process.

Whilst I was debugging the problem, I simply connected to the binary locally, however to receive the flag I had to connect to the remote server.

To begin, I had to take the binary's output and strip the address value from within the curly braces. This is done using the recvuntil method provided by pwntools. Using the Python int and str wrappers, I then simply sent this value back in the intended format through sendline.

Next, I had to do a similar thing to extract the hex value from the binary output. By using the Python hex wrapper, I sent back the value of the first value minus the second in hexadecimal as required.

It then asked me to extract another address from the binary output. I then had to send this 16 bit address value as 2 bytes in little endian form. This is done using p16, which converts the address into a byte sequence in binary data, rather than in plain text.

I was then given a 4 byte address value, and asked to return the integer value for this. I did so using the u32 method, which takes a 32 bit binary and returns it in decimal.

It then asked to send this value in hexadecimal form, which simply involves applying the hex Python wrapper to the value.

Finally it asked to add two given numbers. This involved extracting the two numbers from the binary output, and sending back a string with the result of their sum.

Once all of this was completed, the output asked for a secret flag hidden somewhere in the file. By using the UNIX command strings, I was able to see all the readable text within the raw binary. From this I found the text 'password', which seemed unusual and worth entering.

Upon doing so, I was provided shell access. Whilst not useful when testing locally, when I connected to the remote server, this gave me access to the remote shell. From there, I used ls to see all of the files available, and found one named flag. Using cat flag allowed me to read the contents of this file, and hence provided me with the flag.

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 1025)

p.recvuntil("{")

a = int(p.recvuntil("}")[:-1], 0)

p.recvuntil("form!")

p.sendline(str(a))

p.recvuntil("MINUS ")
b = int(p.recvuntil("!")[:-1], 0)

p.sendline(hex(a-b))

p.recvuntil("me ")
c = int(p.recvuntil(" "), 0)

p.sendlineafter("\n", p16(c))

p.recvuntil("next line)\n")
d = str(u32(p.recv(4)))
p.sendline(d)

p.recvuntil("sent: ")
e = int(p.recvline()[:-1])

p.recvuntil("form!\n")
p.sendline(hex(e))

p.recvuntil("is ")
f = int(p.recvuntil(" "))

p.recvuntil(" ")
g = int(p.recvuntil("?")[:-1])
p.recvline()

p.sendline(str(f+g))

p.sendline("password")

p.interactive()
```

too-slow
=============
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMS10b3Nsb3ciLCJpYXQiOjE1OTEzMzI0NjYsImlwIjoiMTkzLjgyLjIyNS4xMDEifQ.Izyysi9G5HBk8I5SsdFBzP01uT-5_04gCC1dI7woqCE}

General overview of problems faced
-------------------------------------
Like the last challenge, I created a Python script which utilises pwntools to complete this challenge.

When running this binary, it asks you to solve a math addition very quickly. Upon completing it, it then asks another in the same format multiple times.

Using this information, I knew I could use a loop to answer each question. Through slowly increasing the number of times the loop occurs, I was able to determine that it asked a total of ten questions in a row before providing shell access.

Hence, I create a while loop that executed ten times, and within each one I started by discarding the first line of output. Then, I extracted the first and second number on the line using recvuntil.

With these two values, I could then simply use sendline to send a string of the sum of the two.

Once this loop was complete, I was given shell access and like the earlier challenge, I could simply use cat flag to read the flag for this challenge.

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 1026)

i = 0
while(i < 10):

    p.recvline()

    a = int(p.recvuntil(" ")[:-1])

    p.recvuntil(" ")
    b = int(p.recvuntil(" ")[:-1])

    p.sendline(str(a + b))

    i += 1

p.interactive()
```

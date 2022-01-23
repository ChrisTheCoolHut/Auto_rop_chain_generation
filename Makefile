
RAND_BUF_LEN=$(shell python -c 'from random import randint; print(randint(40, 80));')
RAND_READ_LEN=$(shell python -c 'from random import randint; print(randint(120, 250));')

all: overflow dlresolve

overflow:
	gcc -fno-stack-protector \
	-Wno-implicit-function-declaration -no-pie \
	-Wno-format-security -z relro buffer_overflow.c \
	-o buffer_overflow_64bit

dlresolve:
	@echo --- Random buffer length is ${RAND_BUF_LEN} ---
	@echo --- Random read length is ${RAND_READ_LEN} ---
	gcc -fno-stack-protector -no-pie \
	buffer_overflow_dlresolve.c \
	-o buffer_overflow_64bit_dlresolve \
	-Wno-nonnull \
	-DRAND_BUF_LEN=${RAND_BUF_LEN} \
	-DRAND_READ_LEN=${RAND_READ_LEN}

clean:
	rm buffer_overflow_64bit
	rm buffer_overflow_64bit_dlresolve
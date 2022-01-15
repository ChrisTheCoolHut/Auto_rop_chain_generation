
all:
	gcc -fno-stack-protector \
	-Wno-implicit-function-declaration -no-pie \
	-Wno-format-security -z relro buffer_overflow.c \
	-o buffer_overflow_64bit

clean:
	rm buffer_overflow_64bit
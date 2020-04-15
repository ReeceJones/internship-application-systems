CC=gcc
INCLUDE_DIR=.
OUT_NAME=pingeroo
CFLAGS=-I${INCLUDE_DIR} -Wall -Werror -std=c99 -o ${OUT_NAME}

pingeroo: pingeroo.o
	$(CC) pingeroo.o


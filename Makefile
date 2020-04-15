CC=gcc
INCLUDE_DIR=.
OUT_NAME=pingeroo
CFLAGS=-I${INCLUDE_DIR} -g -Wall -Werror -std=gnu99 -o ${OUT_NAME}

pingeroo: pingeroo.o
	$(CC) pingeroo.o


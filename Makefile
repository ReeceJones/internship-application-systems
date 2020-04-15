CC=gcc
INCLUDE_DIR=.
OUT_NAME=pingeroo
CFLAGS=-I${INCLUDE_DIR} -g -Wall -Werror -std=gnu99 -o ${OUT_NAME}

pingeroo: main.o pingeroo.o
	$(CC) pingeroo.o main.o


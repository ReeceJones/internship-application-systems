CC=gcc
INCLUDE_DIR=.
OUT_NAME=pingeroo
CFLAGS=-I${INCLUDE_DIR} -Wall -Werror -std=gnu99
pingeroo: main.o pingeroo.o
	$(CC) -o ${OUT_NAME} pingeroo.o main.o


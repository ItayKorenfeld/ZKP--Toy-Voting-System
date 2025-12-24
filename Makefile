# Makefile for compiling secure voting system with Paillier encryption and ZK proofs

CC = gcc
CFLAGS = -Wall -O2 -I/opt/homebrew/opt/openssl/include
LDFLAGS = -L/opt/homebrew/opt/openssl/lib -lcrypto

OBJS = main.o paillier.o zkproof.o voter.o authority.o
HDRS = paillier.h zkproof.h voter.h authority.h

all: voting_demo

voting_demo: $(OBJS)
	$(CC) $(CFLAGS) -o voting_demo $(OBJS) $(LDFLAGS)

main.o: main.c $(HDRS)
	$(CC) $(CFLAGS) -c main.c

paillier.o: paillier.c paillier.h
	$(CC) $(CFLAGS) -c paillier.c

zkproof.o: zkproof.c zkproof.h paillier.h
	$(CC) $(CFLAGS) -c zkproof.c

voter.o: voter.c voter.h paillier.h zkproof.h
	$(CC) $(CFLAGS) -c voter.c

authority.o: authority.c paillier.h zkproof.h
	$(CC) $(CFLAGS) -c authority.c

clean:
	rm -f *.o voting_demo
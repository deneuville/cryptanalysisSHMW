
CC=g++
NO_RNG_WARNING:=-Wno-unused-but-set-variable -Wno-unused-parameter -Wno-sign-compare 
CFLAGS:=-O2 -pedantic -Wall -Wextra -Wno-vla 

HASH_SRC:=lib/hash/hash.c
HASH_INCLUDE:=-I lib/hash -lcrypto

RNG_SRC:=lib/rng/rng.c
RNG_INCLUDE:=-I lib/rng

FFI_SRC:=src/ffi
FFI_INCLUDE:=-I src/ffi -lntl -lgmp

SRC:=src
INCLUDE:=-I src $(FFI_INCLUDE)
MAIN_SIG:=src/test_signature.cpp
MAIN_ATTACK:=src/attack.cpp
LIB:=$(HASH_INCLUDE) $(RNG_INCLUDE)

SIG_OBJS:=ffi_field.o ffi_elt.o ffi_vec.o parsing.o signature.o 

LIB_OBJS:=hash.o rng.o

BUILD:=bin/build
BIN:=bin



folders:
	@echo -e "\n### Creating build folders\n"
	mkdir -p $(BUILD)

hash.o: folders
	@echo -e "\n### Compiling $@ (wrapper around openssl SHA512 implementation)\n"
	$(CC) $(CFLAGS) -c $(HASH_SRC) $(HASH_INCLUDE) -o $(BUILD)/$@

rng.o: folders
	@echo -e "\n### Compiling NIST rng.o\n"
	$(CC) $(CFLAGS) $(NO_RNG_WARNING) -c $(RNG_SRC) $(RNG_INCLUDE) -o $(BUILD)/$@



ffi_%.o: $(FFI_SRC)/ffi_%.cpp | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(CFLAGS) -c $< $(FFI_INCLUDE) $(LIB) -o $(BUILD)/$@

%.o: $(SRC)/%.cpp | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(CFLAGS) -c $< $(INCLUDE) $(LIB) -o $(BUILD)/$@

signature: $(SIG_OBJS) $(LIB_OBJS) | folders
	@echo -e "\n### Compiling signature\n"
	mkdir -p files
	$(CC) $(CFLAGS) $(MAIN_SIG) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

attack: $(SIG_OBJS) $(LIB_OBJS) | folders
	@echo -e "\n### Compiling attack\n"
	mkdir -p files
	$(CC) $(CFLAGS) $(MAIN_ATTACK) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

clean:
	rm -f PQCkemKAT_*
	rm -f vgcore.*
	rm -rf ./bin


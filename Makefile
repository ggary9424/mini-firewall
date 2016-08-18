CC ?= gcc
CFLAGS = -std=gnu99 -Wall
DEBUG ?= 0

ifeq ($(strip $(DEBUG)), 1)
CFLAGS += -g -DDEBUG
endif

EXEC = mf
all: $(EXEC)

$(EXEC): mf.c
	$(CC) $(CFLAGS) -o mf $^

.PHONY:clean
clean:
	-rm -f mf 

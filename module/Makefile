obj-m += mf_km.o

ifeq ($(strip $(DEBUG)), 1)
CFLAGS_mf_km.o := -DDEBUG
CMD = make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
else
CMD = make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
endif

all:
	$(CMD)
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

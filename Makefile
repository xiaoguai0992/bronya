obj-m += bronya.o 

bronya-y := bronya_kprobes.o bronya_main.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean

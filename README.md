Overview
--------
The package is a mini firewall which is rebuilt according [this artical](http://www.roman10.net/2011/07/23/a-linux-firewall-using-netfilter-part-1overview/) 

It is a practice for me to
* learn how to write a linux kernel module
* learn how to bridge user space and kernel space
* enhance my network perspectives

The mini firewall can BLOCK or LOG packets according to a set of rules.The rules
are set by a user space configuraiton utility program.
User can specify three conditions of ip to BLOCK and LOG:
* ip with specific port
* specific ip
* all of ip in same net id


Environment
--------
Linux kernel for version 4.4.0 .


Build and run
--------
```bash
cd miniFirewall
make
cd module
make
sudo insmod mf_km.ko
cd ..
sudo ./mf --out -t 31.13.87.36 -a BLOCK
```

close the mini firewall
```bash
sudo rmmod mf_km
```

# Audit-framework syscall log hider
 

A loadable kernel module that hides Audit-framework syscall logs if our command has our magic environment variable while still logging others.
	
This implementation assumes auditing EXECVE syscalls.


can be configured by these commands:

```bash
		auditctl -a exit,always -F arch=b32 -S execve
		auditctl -a exit,always -F arch=b64 -S execve
```


### *Check out `flow.md` which describes the flow of my research and the thought dump*


## Installation

### Build

```shell
$ git clone https://github.com/sschwartzer/Auditd
$ cd /Auditd
$ make 
```

### Loading LKM:

```shell
$ dmesg -C # clears all messages from the kernel ring buffer
$ insmod khook-demo.ko
$ dmesg # verify that rootkit has been loaded
```

### Unloading LKM:

```shell
$ rmmod khook-demo
$ dmesg # verify that rootkit has been unloaded
```

### Usage 

```bash
    HIDE=1 ls  # log will not be written
    ls 		   # log will be written
```
tested on Ubuntu Linux server 5.4.0-159-generic vm.

## Intoduction


The target is to hide audit-framework syscall logging on our activity while still logging others.
The audit's configurations are auditing on EXECVE syscalls.

can be configured by the following commands:

```bash

    auditctl -a exit,always -F arch=b32 -S execve
    auditctl -a exit,always -F arch=b64 -S execve
```

In my research, I decided to mainly focus on kernel space.
The reason for this is that without first knowing the full structure of the audit framework,
it can be hard to understand the side effects of only interfering with the usermode without first modifying the kernel. 
Furthermore living within the kernel is harder to detect.


### My solution 

My solution is based on a magic environment variable.
when a command with our environment variable is executing, auditd's log won't be written.
e.g.:

```bash
    HIDE=1 ls  # log will not be written
```


### Flow

The most relevant file is `auditsc.c` (which stands for audit syscall)

In `auditsc.c`:

`__audit_syscall_exit`
Specifically this function is supposed to be called after a system call. 
We are told that if our current state is set to `AUDIT_STATE_RECORD`, write the syscall information.

This function calls `audit_filter_syscall`, this filter is called if audit_state is not low enough that auditing cannot take place,
 but is also not high enough (e.g. writes log on every syscall).
  This filter is relevant when we don't audit every syscall but only specific ones.
This could be used to hide a specific syscall, with a configuration that logs every syscall, this won't hide what we want.

The function `audit_filter_syscall` calls `__audit_filter_op` which seems to call `audit_filter_rules` for each entry of the audit filter list.
Finally, we reached the inner function `audit_filter_rules`. 
A little overwhelming, we meet with a huge switch case, and at its end, something looks a little familiar: 

```c

switch (rule->action) {
    case AUDIT_NEVER:
        *state = AUDIT_STATE_DISABLED;
        break;
    case AUDIT_ALWAYS:
        *state = AUDIT_STATE_RECORD;
        break;
    }
```

This function sets the `audit_state` parameter, notice `AUDIT_STATE_RECORD` this is the same `AUDIT_STATE_RECORD` we talked about in `__audit_syscall_exit`.
Supposedly, if this context is set, then `audit_log_exit` in `__audit_syscall_exit` is called (line 2075 https://github.com/linux-audit/audit-kernel/blob/main/kernel/auditsc.c#L2075).

Notice that `audit_log_exit` does do some 
logging that looks relevant and thus supports this thesis. (https://github.com/linux-audit/audit-kernel/blob/main/kernel/auditsc.c#L1674)

Something doesn't seem quite logical yet.
I didn't understand why this huge switch case was needed so I decided to read a little more about auditd's optional configuration and set up a model.
Now what I gathered from playing a little with the configuration in user mode is that you can configure to ignore specific cases that would have been logged otherwise by your other rules. for example, you configure to log specific syscall but you wish to ignore cases that may not be interesting and not audit them.
e.g. You can configure to audit `EXECVE` but ignore all `ls` commands. Reminds me a little of firewall configuration.

Now when going back to our code it makes sense.

So we gather the following flow:
For every syscall, the kernel calls `__audit_syscall_exit` (problem with this theory: I'm not sure how this 'hook' is done.
 Maybe will come back later)

Inside `__audit_syscall_exit` the function `audit_filter_syscall` is called. Inside `audit_filter_syscall` calls `__audit_filter_op` which finally reaches `audit_filter_rules` which sets the `audit_state` parameter `AUDIT_STATE_RECORD` if log should be written.
 When returning to `__audit_syscall_exit`, if the log should be written, it calls `audit_log_exit` and starts to write the log.


For our future hook:

We need to make `audit_filter_rules` either think that it doesn't need to log us, or we can alternatively make it change and irrelevant.

The problem left is how to identify our syscall and how to access its environment.

To find how to identify our syscalls we can go to several directions.
It is probably accessed via one of the many structs defined in audit.h but it looks a little compilated and probably not an indicative name.
Seems reasonable that the function that starts to log on our syscall needs to identify it too.

So I looked in `audit_log_exit` and found the following line of code:
```c
        audit_log_format(ab, "arch=%x syscall=%d",
                 context->arch, context->major);
```
Now we know that the syscall is `context->major`.

More information about `struct audit_context`:
So as we said previously, `struct audit_context` is the one holding the information about our syscall.
Looking at the actual struct (https://github.com/linux-audit/audit-kernel/blob/main/kernel/audit.h#L102)
We see that the syscall number is in `int major` and the arguments in `unsigned long argv[4]`.


All that's left is to find out how to access the process' environ.

I think the information about the environ is held in `current` parameter which is a global of type `struct task_struct *` (this can be verified by looking at the definition of the audit_filter_syscall function). 
Again if I think about it and stop for a second there must be a place which also reads from the process' environ.

And after a few `CTRL+F` 
```c
    const char __user *p = (const char __user *)current->mm->arg_start;
```
Now I have an idea of how to access the environ.
There are a few more challenges left like `copy_from_user()` but we got the idea.

So apparently we have everything we need to hook `audit_filter_rules`, based on the `*state`.
If we found our magic parameter in the environ, 
we could just decide to change  `*state = AUDIT_DISABLED;`.


*IMPORTANT IN GENERAL*

- The code I used is from https://github.com/linux-audit/audit-kernel/tree/main, it is slightly different from my kernel version.
I looked through bootlin for kernel 5.4. When I wrote the POC it was according to my kernel version.


- for the actual hook, ftrace based https://github.com/milabs/khook, not the most elegant, but worked for my POC.
 If had more time i would have implemented it otherwise (like trampoline). 


This project also can be implemented via user space, 
when running 

```bash
lsof /var/log/audit/audit.log
COMMAND PID USER   FD   TYPE DEVICE SIZE/OFF    NODE NAME
auditd  771 root    5w   REG  253,0  5452513 2494079 /var/log/audit/audit.log


strace -p ($pidof  auditd)
.
.
.

write(5, "type=PATH msg=audit(1694273265.8"..., 197) = 197
```


tested on Ubuntu Linux server 5.4.0-159-generic vm.
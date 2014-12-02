/*
 *  This file contains a PIN tool for tracing system calls on 64-bit Linux systems (POSIX)
 */

#include <stdio.h>
#include <iostream>
#include <cstring>
#include <stdlib.h>
#include <inttypes.h>
#include <sstream>


#define __STDC_FORMAT_MACROS

using namespace std;

#include "pin.H"
#include "map.h"
#include "errors.h"

map<ADDRINT, ADDRINT> eip_syscall_map;

string sanitize(char a) {
	if (a == '\t') {
		return "\\t";
	} else if (a == '\n') {
		return "\\n";
	} else if (a == '\r') {
		return "\\r";
	} else if (a == ' ') {
		return " ";
	} else {
		stringstream ss;
		ss << a;
		string ret;
		ss >> ret;
		return ret;
	}
}

string printCharArray(char **arr, int size) {
	string result = "";
	result += "[";
	for(int i = 0; i < size; i++) {
		if (arr[i] != NULL) {
			int x = 0;
			result += "'";
			while(arr[i][x] != '\0') {
				result += sanitize(arr[i][x]);
			}
			result += "'";
		}
	

	}
	result += "]";
	return result;
}


FILE * trace;

// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	string val = "";

	if (num == SYS__sysctl) { // read/write system params
		// int _sysctl(struct __sysctl_args *args);
    	fprintf(trace,"0x%lx: %s(0x%p)\n",
       		(unsigned long)ip,
       		"sysctl",
			(void *)arg0);
		
	} else if (num == SYS_access) { // int access(const char *pathname, int mode)
    	fprintf(trace,"0x%lx: %s(%s, %d)\n",
       		(unsigned long)ip,
       		"access",
       		(char *)arg0,
       		(int)arg1);

	} else if (num == SYS_acct) { // const char *acct(const char *filename)
		fprintf(trace,"0x%lx: %s(%s)\n",
			(unsigned long) ip,
			"acct",
			(char *)arg0);

	} else if (num == SYS_add_key) { // key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t keyring)
		fprintf(trace,"0x%lx: %s(%s, %s, 0x%p, %d, %d)\n",
			(unsigned long)ip,
			"add_key",
			(char *)arg0,
			(char *)arg1,
			(void *)arg2,
			(int)arg3,
			(int)arg4);

	} else if (num == SYS_adjtimex) { // int adjtimex(struct timex *buf)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"adjtimex",
			(void *) arg0);

	} else if (num == SYS_afs_syscall) {
		fprintf(trace,"0x%lx: %s [UNIMPLEMENTED in the Linux kernel]",
			(unsigned long) ip,
			"afs_syscall");
	} else if (num == SYS_alarm) { // alarm(unsigned int seconds)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"alarm",
			(unsigned int) arg0);

	} else if (num == SYS_brk) { // int brk(void *addr)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"brk",
			(void *)arg0);

	} else if (num == SYS_capget) { // int capget(cap_user_header_t hdrp, cap_user_data_t datap)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p)\n",
			(unsigned long) ip,
			"capget",
			(void *) arg0,
			(void *) arg1);

	} else if (num == SYS_capset) { // int capset(cap_user_header_t hdrp, cap_user_data_t datap)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p)\n",
			(unsigned long) ip,
			"capset",
			(void *) arg0,
			(void *) arg1);

	} else if (num == SYS_chdir) { // int chdir(const char * path)
		fprintf(trace,"0x%lx: %s(%s)\n",
			(unsigned long) ip,
			"chdir",
			(char *)arg0);

	} else if (num == SYS_chmod) { // int chmod(const char *path, mode_t mode)
		fprintf(trace,"0x%lx: %s(%s, %u)\n",
			(unsigned long) ip,
			"chmod",
			(const char *)arg0,
			(mode_t)arg1);

	} else if (num == SYS_chown) { // int chown(const char *pathname, uid_t owner, gid_t group)
		fprintf(trace,"0x%lx: %s(%s, %i, %i)\n",
			(unsigned long) ip,
			"chown",
			(const char *)arg0,
			(int)arg1,
			(int)arg2);

	} else if (num == SYS_chroot) { // int chroot(const char *path)
		fprintf(trace,"0x%lx: %s(%s)\n",
			(unsigned long) ip,
			"chroot",
			(char *)arg0);

	} else if (num == SYS_clock_adjtime) { // clock_adjtime(const struct timeval *delta, struct timeval *olddelta)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p)\n",
			(unsigned long) ip,
			"clock_adjtime",
			(void *)arg0,
			(void *)arg1);

	} else if (num == SYS_clock_getres) { // clock_getres(clockid_t clk_id, struct timespec *res)
		fprintf(trace,"0x%lx: %s(%i, %p)\n",
			(unsigned long) ip,
			"clock_getres",
			(int)arg0,
			(void *)arg1);

	} else if (num == SYS_clock_gettime) { // clock_gettime(clockid_t clk_id, struct timespec *tp)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"clock_gettime",
			(int)arg0,
			(void *)arg1);

	} else if (num == SYS_clock_nanosleep) { // clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *request, struct timespec *remain)
		fprintf(trace,"0x%lx: %s(%i, %i, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"clock_nanosleep",
			(int)arg0,
			(int)arg1,
			(void *)arg2,
			(void *)arg3);

	} else if (num == SYS_clock_settime) { // clock_settime(clockid_t clk_id, const struct timespec *tp)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"clock_settime",
			(int)arg0,
			(void *)arg1);

	} else if (num == SYS_clone) { // long clone(unsigned long flags, void *child_stack, void *ptid, void *ctid, struct pt_regs *regs)
		fprintf(trace,"0x%lx: %s(0x%lx, 0x%p, 0x%p, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"clone",
			(unsigned long)arg0,
			(void *)arg1,
			(void *)arg2,
			(void *)arg3,
			(void *)arg4);

	} else if (num == SYS_close) { // close(int fd)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"close",
			(int)arg0);

	} else if (num == SYS_creat) { // creat(const char *pathname, mode_t mode)
		fprintf(trace,"0x%lx: %s(%s, %u)\n",
			(unsigned long) ip,
			"creat",
			(const char *)arg0,
			(mode_t)arg1);

	} else if (num == SYS_create_module) { // create_module(const char *name, size_t size)
		fprintf(trace,"0x%lx: %s(%s, %i)\n",
			(unsigned long) ip,
			"create_module",
			(const char *)arg0,
			(int)arg1);

	} else if (num == SYS_delete_module) { // delete_module(const char *name, int flags)
		fprintf(trace,"0x%lx: %s(%s, %i)\n",
			(unsigned long) ip,
			"delete_module",
			(const char *)arg0,
			(int)arg1);

	} else if (num == SYS_dup) { // dup(int oldfd)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"dup",
			(int)arg0);

	} else if (num == SYS_dup2) { // dup2(int oldfd, int newfd)
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"dup2",
			(int)arg0,
			(int)arg1);

	} else if (num == SYS_dup3) { // dup3(int oldfd, int newfd, int flags)
		fprintf(trace,"0x%lx: %s(%i, %i, %i)\n",
			(unsigned long) ip,
			"dup3",
			(int)arg0,
			(int)arg1,
			(int)arg2);

	} else if (num == SYS_epoll_create) { // epoll_create(int size)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"epoll_create",
			(int)arg0);

	} else if (num == SYS_epoll_create1) { // epoll_create1(int flags)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"epoll_create1",
			(int)arg0);

	} else if (num == SYS_epoll_ctl) { // epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
		fprintf(trace,"0x%lx: %s(%i, %i, %i, 0x%p)\n",
			(unsigned long) ip,
			"epoll_ctl",
			(int)arg0,
			(int)arg1,
			(int)arg2,
			(void *)arg3);

	} else if (num == SYS_epoll_pwait) { // epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %i, %i, 0x%p)\n",
			(unsigned long) ip,
			"epoll_pwait",
			(int)arg0,
			(void *)arg1,
			(int)arg2,
			(int)arg3,
			(void *)arg4);

	} else if (num == SYS_epoll_wait) { // epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %i, %i)\n",
			(unsigned long) ip,
			"epoll_wait",
			(int)arg0,
			(void *)arg1,
			(int)arg2,
			(int)arg3);

	} else if (num == SYS_eventfd) { // eventfd(unsigned int initval)
		fprintf(trace,"0x%lx: %s(%u)\n",
			(unsigned long) ip,
			"eventfd",
			(unsigned int)arg0);

	} else if (num == SYS_eventfd2) { // eventfd2(unsigned int initval, int flags)
		fprintf(trace,"0x%lx: %s(%u, %i)\n",
			(unsigned long) ip,
			"eventfd",
			(unsigned int)arg0,
			(int)arg1);

	} else if (num == SYS_execve) { // execve(const char *filename, char *const argv[], char *const envp[])
		fprintf(trace,"0x%lx: %s(%s, 0x%p)\n",
			(unsigned long) ip,
			"execve",
			(const char *)arg0,
			(void *)arg1);

		// TODO: pretty-print

	} else if (num == SYS_exit) { // exit(int status)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"exit",
			(int)arg0);

	} else if (num == SYS_exit_group) { // exit_group(int status)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"exit_group",
			(int)arg0);

	} else if (num == SYS_faccessat) { // facessat(int dirfd, const char *pathname, int mode, int flags)
		fprintf(trace,"0x%lx: %s(%i, %s, %i, %i)\n",
			(unsigned long) ip,
			"faccessat",
			(int)arg0,
			(const char *)arg1,
			(int)arg2,
			(int)arg3);

	} else if (num == SYS_fadvise64) { // fadvise64(int fd, off_t offset, off_t len, int advice)
		fprintf(trace,"0x%lx: %s(%i, %i, %i, %i)\n",
			(unsigned long) ip,
			"fadvise64",
			(int)arg0,
			(int)arg1,
			(int)arg2,
			(int)arg3);

	} else if (num == SYS_fallocate) { // fallocate(int fd, int mode, off_t offset, off_t len)
		fprintf(trace,"0x%lx: %s(%i, %i, %i, %i)\n",
			(unsigned long) ip,
			"fallocate",
			(int)arg0,
			(int)arg1,
			(int)arg2,
			(int)arg3);

	} else if (num == SYS_fanotify_init) { // fanotify_init(unsigned int flags, unsigned int event_f_flags)
		fprintf(trace,"0x%lx: %s(%u, %u)\n",
			(unsigned long) ip,
			"fnotify_init",
			(unsigned int)arg0,
			(unsigned int)arg1);

	} else if (num == SYS_fanotify_mark) { // fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *pathname)
		fprintf(trace,"0x%lx: %s(%u, %u, %llu, %i, %s)\n",
			(unsigned long) ip,
			"fnotify_mark",
			(unsigned int)arg0,
			(unsigned int)arg1,
			(unsigned long long int)arg2,
			(int)arg3,
			(const char *)arg4);

	} else if (num == SYS_fchdir) { // fchdir(int fd)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"fchdir",
			(int)arg0);

	} else if (num == SYS_fchmod) { // fchmod(int fd, mode_t mode)
		fprintf(trace,"0x%lx: %s(%i, %u)\n",
			(unsigned long) ip,
			"fchmod",
			(int)arg0,
			(mode_t)arg1);

	} else if (num == SYS_fchmodat) { // fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)
		fprintf(trace,"0x%lx: %s(%i, %s, %u, %i)\n",
			(unsigned long) ip,
			"fchmodat",
			(int)arg0,
			(const char *)arg1,
			(mode_t)arg2,
			(int)arg3);

	} else if (num == SYS_fchown) { // fchown(int fd, uid_t owner, gid_t group)
		fprintf(trace,"0x%lx: %s(%i, %u, %u)\n",
			(unsigned long) ip,
			"fchown",
			(int)arg0,
			(unsigned int)arg1,
			(unsigned int)arg2);

	} else if (num == SYS_fchownat) { // fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags)
		fprintf(trace,"0x%lx: %s(%i, %s, %u, %u, %i)\n",
			(unsigned long) ip,
			"fchownat",
			(int)arg0,
			(const char *)arg1,
			(unsigned int)arg2,
			(unsigned int)arg3,
			(int)arg4);

	} else if (num == SYS_fcntl) { // int fcntl(int fd, int cmd, .../* arg */ )
		fprintf(trace,"0x%lx: %s(%i, %i, ...) [Type of optional 3rd arg is determined by 2nd arg value]\n",
			(unsigned long) ip,
			"fcntl",
			(int)arg0,
			(int)arg1);

	} else if (num == SYS_fdatasync) { // int fdatasync(int fd)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"fdatasync",
			(int)arg0);

	} else if (num == SYS_fgetxattr) { // fgetxattr(int fd, const char *name, void *value, size_t size)
		fprintf(trace,"0x%lx: %s(%i, %s, 0x%p, %lu)\n",
			(unsigned long) ip,
			"fgetxattr",
			(int)arg0,
			(const char *)arg1,
			(void *)arg2,
			(size_t)arg3);

	} else if (num == SYS_flistxattr) { // ssize_t flistxattr(int fd, char *list, size_t size)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %lu)\n",
			(unsigned long) ip,
			"flistxattr",
			(int)arg0,
			(void *)arg1,
			(size_t)arg2);

	} else if (num == SYS_flock) { // int flock(int fd, int operation)
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"flock",
			(int)arg0,
			(int)arg1);

	} else if (num == SYS_fork) { // pid_t fork()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"fork");

	} else if (num == SYS_fremovexattr) { // fremovexattr(int filedes, const char *name)
		fprintf(trace,"0x%lx: %s(%i, %s)\n",
			(unsigned long) ip,
			"fremovexattr",
			(int)arg0,
			(const char *)arg1);

	} else if (num == SYS_fsetxattr) { // setxattr(const char *path, const char *name, const void *value, size_t size, int flags)
		fprintf(trace,"0x%lx: %s(%s, %s, 0x%p, %lu, %i)\n",
			(unsigned long) ip,
			"fsetxattr",
			(const char *)arg0,
			(const char *)arg1,
			(const void *)arg2,
			(size_t)arg3,
			(int)arg4);

	} else if (num == SYS_fstat) { // fstat(int fd, struct stat *buf)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"fstat",
			(int)arg0,
			(void *)arg1);

	} else if (num == SYS_fstatfs) { // fstatfs(int fd, struct stafs *buf)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)",
			(unsigned long) ip,
			"fstatfs",
			(int)arg0,
			(void *)arg1);

	} else if (num == SYS_fsync) { // fsync(int id)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"fsync",
			(int)arg0);

	} else if (num == SYS_ftruncate) { // ftruncate(int fd, off_t length)
		fprintf(trace,"0x%lx: %s(%i, %llu)\n",
			(unsigned long) ip,
			"ftruncate",
			(int)arg0,
			(unsigned long long int)arg1);

	} else if (num == SYS_futex) { // futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3)

		fprintf(trace,"0x%lx: %s(0x%p, %i, %i, 0x%p, 0x%p, %i)\n",
			(unsigned long) ip,
			"futex",
			(void *)arg0,
			(int)arg1,
			(int)arg2,
			(const struct timespec *)arg3,
			(int *)arg4,
			(int)arg5);

	} else if (num == SYS_futimesat) { // futimesat(int dirfd, const char *pathname, const struct timeval times[2])
		fprintf(trace,"0x%lx: %s(%i, %s, 0x%p)\n",
			(unsigned long) ip,
			"futimesat",
			(int)arg0,
			(const char *)arg1,
			(void *)arg2);

	} else if (num == SYS_get_kernel_syms) {
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"get_kernel_syms",
			(void *)arg0);

	} else if (num == SYS_get_mempolicy) { // get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, unsigned long addr, unsigned long flags)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p, %lu, %lu, %lu)\n",
			(unsigned long) ip,
			"get_mempolicy",
			(void *)arg0,
			(void *)arg1,
			(unsigned long)arg2,
			(unsigned long)arg3,
			(unsigned long)arg4);

	} else if (num == SYS_get_robust_list) { // get_robust_list(int pid, struct robust_list_head **head_ptr, size_t *len_ptr)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %u)\n",
			(unsigned long) ip,
			"get_robust_list",
			(int)arg0,
			(void *)arg1,
			(unsigned int)arg2);

	} else if (num == SYS_get_thread_area) { // get_thread_area(struct user_desc *u_info)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"get_thread_area",
			(void *)arg0);

	} else if (num == SYS_getcpu) { // getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p, 0x%p) [3rd argument not used past Linux kernel version 2.6.24]\n",
			(unsigned long) ip,
			"getcpu",
			(unsigned *)arg0,
			(unsigned *)arg1,
			(unsigned *)arg2);

	} else if (num == SYS_getcwd) { // getcwd(char *buf, size_t size)
		fprintf(trace,"0x%lx: %s(0x%p, %u)\n",
			(unsigned long) ip,
			"getcwd",
			(unsigned *)arg0,
			(unsigned int)arg1);

	} else if (num == SYS_getdents) { // getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
		fprintf(trace,"0x%lx: %s(%u, 0x%p, %u)\n",
			(unsigned long) ip,
			"getdents",
			(unsigned int)arg0,
			(void *)arg1,
			(unsigned int)arg2);

	} else if (num == SYS_getdents64) { // getdents64(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
		fprintf(trace,"0x%lx: %s(%u, 0x%p, %u)\n",
			(unsigned long) ip,
			"getdents64",
			(unsigned int)arg0,
			(void *)arg1,
			(unsigned int)arg2);

	} else if (num == SYS_getegid) { // getegid()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"getegid");

	} else if (num == SYS_geteuid) { // geteuid()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"geteuid");

	} else if (num == SYS_getgid) { // getgid()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"getgid");

	} else if (num == SYS_getgroups) { // getgroups(int size, gid_t list[])
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"getgroups",
			(int)arg0,
			(void *)arg1);

	} else if (num == SYS_getitimer) { // getitimer(int which, struct itimerval *curr_value)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"getitimer",
			(int)arg0,
			(void *)arg1);

	} else if (num == SYS_getpgid) { // getpgid(pid_t pid)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"getpgid",
			(int)arg0);

	} else if (num == SYS_getpgrp) { // getpgrp()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"getpgrp");

	} else if (num == SYS_getpid) { // getpid()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"getpid");

	} else if (num == SYS_getpmsg) {
		fprintf(trace,"0x%lx: %s [UNIMPLEMENTED in the Linux kernel]\n",
			(unsigned long) ip,
			"getpmsg");

	} else if (num == SYS_getppid) { // getppid()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"getppid");

	} else if (num == SYS_getpriority) { // getpriority(int which, int who)
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"getpriority",
			(int)arg0,
			(int)arg1);

	} else if (num == SYS_getresgid) { // getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"getresgid",
			(void *)arg0,
			(void *)arg1,
			(void *)arg2);

	} else if (num == SYS_getresuid) { // getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"getresuid",
			(void *)arg0,
			(void *)arg1,
			(void *)arg2);

	} else if (num == SYS_getrlimit) { // getrlimit(int resource, struct rlimit *rlim)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"getrlimit",
			(int)arg0,
			(void *)arg1);

	} else if (num == SYS_getrusage) { // getrusage(int resource, const struct rlimit *rlim)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"getrusage",
			(int)arg0,
			(void *)arg1);

	} else if (num == SYS_getsid) { // getsid(pid_t pid)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"getsid",
			(int)arg0);

	} else if (num == SYS_gettid) { // gettid()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"gettid");

	} else if (num == SYS_gettimeofday) { // gettimeofday(struct timeval *tv, struct timezone *tz)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p)\n",
			(unsigned long) ip,
			"gettimeofday",
			(void *)arg0,
			(void *)arg1);

	} else if (num == SYS_getuid) { // getuid()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"getuid");

	} else if (num == SYS_getxattr) { // getxattr(const char *path, const char *name, void *value, size_t size);
		fprintf(trace,"0x%lx: %s(%s, %s, 0x%p, %lu)\n",
			(unsigned long) ip,
			"getxattr",
			(const char *)arg0,
			(const char *)arg1,
			(void *)arg2,
			(size_t)arg3);

	} else if (num == SYS_init_module) { // init_module(void *module_image, unsigned long len, const char *param_valus)
		fprintf(trace,"0x%lx: %s(0x%p, %lu, %s)\n",
			(unsigned long) ip,
			"init_module",
			(void *)arg0,
			(unsigned long)arg1,
			(const char *)arg2);

	} else if (num == SYS_inotify_add_watch) { // inotify_add_watch(int fd, const char *pathname, uint32_t mask)
		fprintf(trace,"0x%lx: %s(%i, %s, %i)\n",
			(unsigned long) ip,
			"inotify_add_watch",
			(int)arg0,
			(const char *)arg1,
			(int)arg2);

	} else if (num == SYS_inotify_init) { // inotify_init()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"inotify_init");

	} else if (num == SYS_inotify_init1) { // inotify_init1(int flags)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"inotify_init1",
			(int)arg0);

	} else if (num == SYS_inotify_rm_watch) { // inotify_rm_watch(int fd, int wd)
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"inotify_rm_watch",
			(int)arg0,
			(int)arg1);

	} else if (num == SYS_io_cancel) { // io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"io_cancel",
			(void *)arg0,
			(struct iocb *)arg1,
			(struct io_event *)arg2);

	} else if (num == SYS_io_destroy) { // io_destroy(aio_context_t ctx_id)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"io_destroy",
			(void *)arg0);

	} else if (num == SYS_io_getevents) { // io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout)
		fprintf(trace,"0x%lx: %s(0x%p, %ld, %ld, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"io_getevents",
			(void *)arg0,
			(long)arg1,
			(long)arg2,
			(void *)arg3,
			(void *)arg4);

	} else if (num == SYS_io_setup) { // io_setup(unsigned nr_events, aio_context_t *ctx_idp)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"io_getevents",
			(unsigned)arg0,
			(void *)arg1);

	} else if (num == SYS_io_submit) { // io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp)
		fprintf(trace,"0x%lx: %s(0x%p, %ld, 0x%p)\n",
			(unsigned long) ip,
			"io_submit",
			(void *)arg0,
			(long)arg1,
			(void *)arg2);

	} else if (num == SYS_ioctl) { // ioctl(int d, int request, void *memory)
		fprintf(trace,"0x%lx: %s(%i, %i, 0x%p)\n",
			(unsigned long) ip,
			"ioctl",
			(int)arg0,
			(int)arg1,
			(void *)arg2);

	} else if (num == SYS_ioperm) { // ioperm(unsigned long from, unsigned long num, int turn_on)
		fprintf(trace,"0x%lx: %s(%lu, %lu, %i)\n",
			(unsigned long) ip,
			"ioperm",
			(unsigned long)arg0,
			(unsigned long)arg1,
			(int)arg2);

	} else if (num == SYS_iopl) { // iopl(int level)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"iopl",
			(int)arg0);

	} else if (num == SYS_ioprio_get) { // ioprio_get(int which, int who)
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"ioprio_get",
			(int)arg0,
			(int)arg1);

	} else if (num == SYS_ioprio_set) { // ioprio_set(int which, int who, int ioprio)
		fprintf(trace,"0x%lx: %s(%i, %i, %i)\n",
			(unsigned long) ip,
			"ioprio_set",
			(int)arg0,
			(int)arg1,
			(int)arg2);

	} else if (num == SYS_kexec_load) { // kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags)
		fprintf(trace,"0x%lx: %s(%lu, %lu, 0x%p, %lu)\n",
			(unsigned long) ip,
			"kexec_load",
			(unsigned long)arg0,
			(unsigned long)arg1,
			(struct kexec_segment *)arg2,
			(unsigned long)arg3);

	} else if (num == SYS_keyctl) { // long keyctl(int cmd, ...)
    	fprintf(trace,"0x%lx: %s(%i, ...) [other args interpretation depend on command]\n",
       		(unsigned long)ip,
       		"keyctl",
			(int)arg0);

	} else if (num == SYS_kill) { // int kill(pid_t pid, int sig)
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"kill",
			(pid_t)arg0,
			(int)arg1);

	} else if (num == SYS_lchown) { // int lchown(const char *path, uid_t owner, gid_t group)
		fprintf(trace,"0x%lx: %s(%s, %i, %i)\n",
			(unsigned long) ip,
			"lchown",
			(const char *)arg0,
			(uid_t)arg1,
			(gid_t)arg2);

	} else if (num == SYS_lgetxattr) { // ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size);
		fprintf(trace,"0x%lx: %s(%s, %s, 0x%p, %lu)\n",
			(unsigned long) ip,
			"lgetxattr",
			(const char *)arg0,
			(const char *)arg1,
			(void *)arg2,
			(size_t)arg3);

	} else if (num == SYS_link) { // int link(const char *oldpath, const char *newpath)
		fprintf(trace,"0x%lx: %s(%s, %s)\n",
			(unsigned long) ip,
			"link",
			(const char *)arg0,
			(const char *)arg1);

	} else if (num == SYS_linkat) { // int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
		fprintf(trace,"0x%lx: %s(%i, %s, %i, %s, %i)\n",
			(unsigned long) ip,
			"linkat",
			(int)arg0,
			(const char *)arg1,
			(int)arg2,
			(const char *)arg3,
			(int)arg4);

	} else if (num == SYS_listxattr) { // ssize_t listxattr(const char *path, char *list, size_t size)
		fprintf(trace,"0x%lx: %s(%s, 0x%p, %lu)\n",
			(unsigned long) ip,
			"listxattr",
			(const char *)arg0,
			(void *)arg1,
			(size_t)arg2);

	} else if (num == SYS_llistxattr) { // ssize_t llistxattr(const char *path, char *list, size_t size)
		fprintf(trace,"0x%lx: %s(%s, 0x%p, %lu)\n",
			(unsigned long) ip,
			"llistxattr",
			(const char *)arg0,
			(void *)arg1,
			(size_t)arg2);

	} else if (num == SYS_lookup_dcookie) { // int lookup_dcookie(u64 cookie, char *buffer, size_t len)
		fprintf(trace,"0x%lx: %s(%llu, 0x%p, %lu)\n",
			(unsigned long) ip,
			"lookup_dcookie",
			(unsigned long long)arg0,
			(void *)arg1,
			(size_t)arg2);

	} else if (num == SYS_lremovexattr) { // int lremovexattr(const char *path, const char *name)
		fprintf(trace,"0x%lx: %s(%s, %s)\n",
			(unsigned long) ip,
			"lremovexattr",
			(const char *)arg0,
			(const char *)arg1);

	} else if (num == SYS_lseek) { // off_t lseek(int fd, off_t offset, int whence)
		fprintf(trace,"0x%lx: %s(%i, %lu, %i)\n",
			(unsigned long) ip,
			"lseek",
			(int)arg0,
			(off_t)arg1,
			(int)arg2);

	} else if (num == SYS_lsetxattr) { // int lsetxattr(const char *path, const char *name, const void      *value, size_t size, int flags)
		fprintf(trace,"0x%lx: %s(%s, %s, 0x%p, %lu, %i)\n",
			(unsigned long) ip,
			"lsetxattr",
			(const char *)arg0,
			(const char *)arg1,
			(const void *)arg2,
			(size_t)arg3,
			(int)arg4);

	} else if (num == SYS_lstat) { // int lstat(const char *path, struct stat *buf)
		fprintf(trace,"0x%lx: %s(%s, 0x%p)\n",
			(unsigned long) ip,
			"lstat",
			(const char *)arg0,
			(void *)arg1);

	} else if (num == SYS_madvise) { // int madvise(void *addr, size_t length, int advice)
		fprintf(trace,"0x%lx: %s(0x%p, %lu, %i)\n",
			(unsigned long) ip,
			"madvise",
			(void *)arg0,
			(size_t)arg1,
			(int)arg2);

	} else if (num == SYS_mbind) { // int mbind(void * addr, unsigned long len, int mode, unsigned long *nodemask, unsigned long maxnode, unsigned flags)
		fprintf(trace,"0x%lx: %s(0x%p, %lu, %i, 0x%p, %lu, %u)\n",
			(unsigned long) ip,
			"mbind",
			(void *)arg0,
			(unsigned long)arg1,
			(int)arg2,
			(void *)arg3,
			(unsigned long)arg4,
			(unsigned)arg5);

	} else if (num == SYS_migrate_pages) { // long migrate_pages(int pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes)
		fprintf(trace,"0x%lx: %s(%i, %lu, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"migrate_pages",
			(int)arg0,
			(unsigned long)arg1,
			(void *)arg2,
			(void *)arg3);

	} else if (num == SYS_mincore) { // int mincore(void *addr, size_t length, unsigned char *vec)

		fprintf(trace,"0x%lx: %s(0x%p, %lu, 0x%p)\n",
			(unsigned long) ip,
			"mincore",
			(void *)arg0,
			(size_t)arg1,
			(void *)arg2);

	} else if (num == SYS_mkdir) { // int mkdir(const char *pathname, mode_t mode)
		fprintf(trace,"0x%lx: %s(%s, %u)\n",
			(unsigned long) ip,
			"mkdir",
			(const char *)arg0,
			(mode_t)arg1);

	} else if (num == SYS_mkdirat) { // int mkdirat(int dirfd, const char *pathname, mode_t mode)
		fprintf(trace,"0x%lx: %s(%i, %s, %u)\n",
			(unsigned long) ip,
			"mkdir",
			(int)arg0,
			(const char *)arg1,
			(mode_t)arg2);

	} else if (num == SYS_mknod) { // int mknod(const char *pathname, mode_t mode, dev_t dev
		fprintf(trace,"0x%lx: %s(%s, %u, %lu)\n",
			(unsigned long) ip,
			"mknod",
			(const char *)arg0,
			(mode_t)arg1,
			(dev_t)arg2);

	} else if (num == SYS_mknodat) { // int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev)
		fprintf(trace,"0x%lx: %s(%i, %s, %u, %lu)\n",
			(unsigned long) ip,
			"mknodat",
			(int)arg0,
			(const char *)arg1,
			(mode_t)arg2,
			(dev_t)arg3);

	} else if (num == SYS_mlock) { // int mlock(const void *addr, size_t len)
		fprintf(trace,"0x%lx: %s(0x%p, %lu)\n",
			(unsigned long) ip,
			"mlock",
			(const void *)arg0,
			(size_t)arg1);

	} else if (num == SYS_mlockall) { // int mlockall(int flags)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"mlockall",
			(int)arg0);

	} else if (num == SYS_mmap) { // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
		
		fprintf(trace,"0x%lx: %s(0x%p, %lu, %i, %i, %i, %lu)\n",
			(unsigned long) ip,
			"mmap",
			(void *)arg0,
			(size_t)arg1,
			(int)arg2,
			(int)arg3,
			(int)arg4,
			(off_t)arg5);

	} else if (num == SYS_modify_ldt) { // int modify_ldt(int func, void *ptr, unsigned long bytecount)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %lu)\n",
			(unsigned long) ip,
			"modify_ldt",
			(int)arg0,
			(void *)arg1,
			(unsigned long)arg2);

	} else if (num == SYS_mount) { // int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data)
		fprintf(trace,"0x%lx: %s(%s, %s, %s, %lu, 0x%p)\n",
			(unsigned long) ip,
			"mount",
			(const char *)arg0,
			(const char *)arg1,
			(const char *)arg2,
			(unsigned long)arg3,
			(const void *)arg4);

	} else if (num == SYS_move_pages) { // long move_pages(int pid, unsigned long count, void **pages, const int *nodes, int *status, int flags)
		fprintf(trace,"0x%lx: %s(%i, %lu, 0x%p, 0x%p, 0x%p, %i)\n",
			(unsigned long) ip,
			"move_pages",
			(int)arg0,
			(unsigned long)arg1,
			(void **)arg2,
			(const int *)arg3,
			(int *)arg4,
			(int)arg5);

	} else if (num == SYS_mprotect) { // int mprotect(void *addr, size_t len, int prot)
		fprintf(trace,"0x%lx: %s(0x%p, %lu, %i)\n",
			(unsigned long) ip,
			"mprotect",
			(void *)arg0,
			(size_t)arg1,
			(int)arg2);

	} else if (num == SYS_mq_getsetattr) { // int mq_getsetattr(mqd_t mqdes, struct mq_attr *newattr, struct mq_attr *oldattr)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"mq_getsetattr",
			(void *)arg0,
			(void *)arg1,
			(void *)arg2);

	} else if (num == SYS_mq_notify) { // int mq_notify(mqd_t mqdes, const struct sigevent *sevp)
		// mq_open takes two args if O_CREAT is specified in oflag [TODO: properly implement]
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p)\n",
			(unsigned long) ip,
			"mq_notify",
			(void *)arg0,
			(void *)arg1);

	} else if (num == SYS_mq_open) { // mqd_t mq_open(const char *name, int oflag [,mode_t mode, struct mq_attr *attr])
		// mq_open takes two args if O_CREAT is specified in oflag [TODO: properly implement]
		fprintf(trace,"0x%lx: %s(%s, %i)\n",
			(unsigned long) ip,
			"mq_open",
			(const char *)arg0,
			(int)arg1);

	} else if (num == SYS_mq_timedreceive) { // ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned *msg_prio, const struct timespec *abs_timeout)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p, %lu, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"mq_timedreceive",
			(void *)arg0,
			(void *)arg1,
			(size_t)arg2,
			(unsigned *)arg3,
			(const struct timespec *)arg4);

	} else if (num == SYS_mq_timedsend) { // int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned msg_prio, const struct timespec *abs_timeout)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p, %lu, %u, 0x%p)\n",
			(unsigned long) ip,
			"mq_timedsend",
			(void *)arg0,
			(void *)arg1,
			(size_t)arg2,
			(unsigned)arg3,
			(const struct timespec *)arg4);

	} else if (num == SYS_mq_unlink) { // int mq_unlink(const char *name)
		fprintf(trace,"0x%lx: %s(%s)\n",
			(unsigned long) ip,
			"mq_unlink",
			(const char *)arg0);

	} else if (num == SYS_mremap) { // void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, [optional] void *new_address)
		// TODO: support optional argument
		fprintf(trace,"0x%lx: %s(0x%p, %lu, %lu, %i)\n",
			(unsigned long) ip,
			"mremap",
			(void *)arg0,
			(size_t)arg1,
			(size_t)arg2,
			(int)arg3);

	} else if (num == SYS_msync) { // int msync(void *addr, size_t length, int flags)
		fprintf(trace,"0x%lx: %s(0x%p, %lu, %i)\n",
			(unsigned long) ip,
			"msync",
			(void *)arg0,
			(size_t)arg1,
			(int)arg2);

	} else if (num == SYS_munlock) { // int munlock(const void *addr, size_t len)
		fprintf(trace,"0x%lx: %s(0x%p, %lu)\n",
			(unsigned long) ip,
			"munlock",
			(void *)arg0,
			(size_t)arg1);

	} else if (num == SYS_munlockall) { // int munlockall()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"munlockall");

	} else if (num == SYS_munmap) { // int munmap(void *addr, size_t length)
		fprintf(trace,"0x%lx: %s(0x%p, %lu)\n",
			(unsigned long) ip,
			"munmap",
			(void *)arg0,
			(size_t)arg1);

	} else if (num == SYS_name_to_handle_at) { // int name_to_handle_at(int dirfd, const char *pathname, struct filehandle *handle, int *mount_id, int flags)
		fprintf(trace,"0x%lx: %s(%i, %s, 0x%p, 0x%p, %i)\n",
			(unsigned long) ip,
			"name_to_handle_at",
			(int)arg0,
			(const char *)arg1,
			(struct filehandle *)arg2,
			(int *)arg3,
			(int)arg4);

	} else if (num == SYS_nanosleep) { // int nanosleep(const struct timespec *req, struct timespec *rem)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p)\n",
			(unsigned long) ip,
			"nanosleep",
			(const struct timespec *)arg0,
			(struct timespec *)arg1);

	} else if (num == SYS_nfsservctl) { // long nfsservctl(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"nfsservctl",
			(int)arg0,
			(struct nfsctl_arg *)arg1,
			(union nfsctl_res *)arg2);

	} else if (num == SYS_open) { // int open(const char *pathname, int flags, mode_t mode)
		// Note: mode is only used if O_CREAT is specified in flags
		fprintf(trace,"0x%lx: %s(%s, %i, %u)\n",
			(unsigned long) ip,
			"open",
			(const char *)arg0,
			(int)arg1,
			(mode_t)arg2);

	} else if (num == SYS_open_by_handle_at) { // int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %i)\n",
			(unsigned long) ip,
			"open_by_handle_at",
			(int)arg0,
			(struct filehandle *)arg1,
			(int)arg2);

	} else if (num == SYS_openat) { // int openat(int dirfd, const char *pathname, int flags, mode_t mode)
		fprintf(trace,"0x%lx: %s(%i, %s, %i, %u)\n",
			(unsigned long) ip,
			"openat",
			(int)arg0,
			(const char *)arg1,
			(int)arg2,
			(mode_t)arg3);

	} else if (num == SYS_pause) { // int pause()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"pause");

	} else if (num == SYS_perf_event_open) { // int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
		fprintf(trace,"0x%lx: %s(0x%p, %i, %i, %i, %lu)\n",
			(unsigned long) ip,
			"perf_event_open",
			(struct perf_event_attr *)arg0,
			(pid_t)arg1,
			(int)arg2,
			(int)arg3,
			(unsigned long)arg4);

	} else if (num == SYS_personality) { // int personality(unsigned long persona)
		fprintf(trace,"0x%lx: %s(%lu)\n",
			(unsigned long) ip,
			"personality",
			(unsigned long)arg0);

	} else if (num == SYS_pipe) { // int pipe(int pipefd[2])
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"pipe",
			(void *)arg0);


	} else if (num == SYS_pipe2) { // int pipe2(int pipefd[2], int flags)
		fprintf(trace,"0x%lx: %s(0x%p, %i)\n",
			(unsigned long) ip,
			"pipe2",
			(void *)arg0,
			(int)arg1);

	} else if (num == SYS_pivot_root) { // const char *new_root, const char *put_old)
		fprintf(trace,"0x%lx: %s(%s, %s)\n",
			(unsigned long) ip,
			"pivot_root",
			(const char *)arg0,
			(const char *)arg1);

	} else if (num == SYS_poll) { // int poll(struct pollfd *fds, nfds_t nfds, int timeout)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p, %i)\n",
			(unsigned long) ip,
			"poll",
			(struct pollfd *)arg0,
			(void *)arg1,
			(int)arg2);

	} else if (num == SYS_ppoll) { // int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"ppoll",
			(struct pollfd *)arg0,
			(void *)arg1,
			(const struct timespec *)arg2,
			(const sigset_t *)arg3);

	} else if (num == SYS_prctl) { // int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
		fprintf(trace,"0x%lx: %s(%i, %lu, %lu, %lu, %lu)\n",
			(unsigned long) ip,
			"prctl",
			(int)arg0,
			(unsigned long)arg1,
			(unsigned long)arg2,
			(unsigned long)arg3,
			(unsigned long)arg4);

	} else if (num == SYS_pread64) { // ssize_t pread64(int fd, void *buf, size_t count, off_t offset)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %lu, %ld)\n",
			(unsigned long) ip,
			"pread64",
			(int)arg0,
			(void *)arg1,
			(size_t)arg2,
			(off_t)arg3);

	} else if (num == SYS_preadv) { // ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %i, %ld)\n",
			(unsigned long) ip,
			"preadv",
			(int)arg0,
			(const struct iovec *)arg1,
			(int)arg2,
			(off_t)arg3);

	} else if (num == SYS_prlimit64) {
		fprintf(trace,"0x%lx: %s [undocumented]\n",
			(unsigned long) ip,
			"prlimit64");

	} else if (num == SYS_process_vm_readv) { // ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcn, unsigned long flags)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %lu, 0x%p, %lu, %lu)\n",
			(unsigned long) ip,
			"process_vm_readv",
			(pid_t)arg0,
			(const struct iovec *)arg1,
			(unsigned long)arg2,
			(const struct iovec *)arg3,
			(unsigned long)arg4,
			(unsigned long)arg5);

	} else if (num == SYS_process_vm_writev) { // ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcn, unsigned long flags)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %lu, 0x%p, %lu, %lu)\n",
			(unsigned long) ip,
			"process_vm_writev",
			(pid_t)arg0,
			(const struct iovec *)arg1,
			(unsigned long)arg2,
			(const struct iovec *)arg3,
			(unsigned long)arg4,
			(unsigned long)arg5);

	} else if (num == SYS_pselect6) { // int pselect6(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, 0x%p, 0x%p, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"pselect6",
			(int)arg0,
			(fd_set *)arg1,
			(fd_set *)arg2,
			(fd_set *)arg3,
			(const struct timespec *)arg4,
			(const sigset_t *)arg5);

	} else if (num == SYS_ptrace) { // long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data)
		fprintf(trace,"0x%lx: %s(%i, %i, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"ptrace",
			(int)arg0,
			(pid_t)arg1,
			(void *)arg2,
			(void *)arg3);

	} else if (num == SYS_putpmsg) {
		fprintf(trace,"0x%lx: %s [UNIMPLEMENTED in the Linux kernel]\n",
			(unsigned long) ip,
			"putpmsg");

	} else if (num == SYS_pwrite64) { // ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %lu, %ld)\n",
			(unsigned long) ip,
			"pwrite64",
			(int)arg0,
			(const void *)arg1,
			(size_t)arg2,
			(off_t)arg3);

	} else if (num == SYS_pwritev) { // ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %i, %ld)\n",
			(unsigned long) ip,
			"pwritev",
			(int)arg0,
			(const struct iovec *)arg1,
			(int)arg2,
			(off_t)arg3);

	} else if (num == SYS_query_module) { // int query_module(const char *name, int which, void *buf, size_t bufsize, size_t *ret)
		fprintf(trace,"0x%lx: %s(%s, %i, 0x%p, %lu, %lu)\n",
			(unsigned long) ip,
			"query_module",
			(const char *)arg0,
			(int)arg1,
			(void *)arg2,
			(size_t)arg3,
			(size_t)arg4);

	} else if (num == SYS_quotactl) { // long quotactl(int cmd, char *special, qid_t id, caddr_t addr) 

    	fprintf(trace,"0x%lx: %s(%i, %s, %u, 0x%p)\n",
       		(unsigned long)ip,
       		"quotactl",
       		(int)arg0,
       		(char *)arg1,
       		(unsigned int)arg2,
       		(void *)arg3);

	} else if (num == SYS_read) { // ssize_t read(int fd, void * buf, size_t count)
    	fprintf(trace,"0x%lx: %s(%lu, 0x%lx, %lu (0x%lx) bytes)\n",
       		(unsigned long)ip,
       		"read",
       		(unsigned long)arg0,
       		(unsigned long)arg1,
       		(unsigned long)arg2,
       		(unsigned long)arg2);

	} else if (num == SYS_readahead) { // ssize_t readahead(int fd, off64_t offset, size_t count)
    	fprintf(trace,"0x%lx: %s(%i, %ld, %lu)\n",
       		(unsigned long)ip,
       		"readahead",
			(int)arg0,
			(off64_t)arg1,
			(size_t)arg2);

	} else if (num == SYS_readlink) { // ssize_t readlink(const char *path, char *buf, size_t bufsiz)
    	fprintf(trace,"0x%lx: %s(%s, 0x%p, %lu)\n",
       		(unsigned long)ip,
       		"readlink",
			(const char *)arg0,
			(void *)arg0,
			(size_t)arg1);

	} else if (num == SYS_readlinkat) { // int readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
    	fprintf(trace,"0x%lx: %s(%i, %s, 0x%p, %lu)\n",
       		(unsigned long)ip,
       		"readlinkat",
			(int)arg0,
			(const char *)arg1,
			(void *)arg2,
			(size_t)arg3);

	} else if (num == SYS_readv) { // ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, %i)\n",
       		(unsigned long)ip,
       		"readv",
			(int)arg0,
			(const struct iovec *)arg1,
			(int)arg2);

	} else if (num == SYS_reboot) { // int reboot(int magic, int magic2, int cmd, void *arg)
    	fprintf(trace,"0x%lx: %s(%i, %i, %i, 0x%p)\n",
       		(unsigned long)ip,
       		"reboot",
			(int)arg0,
			(int)arg1,
			(int)arg2,
			(void *)arg3);

	} else if (num == SYS_recvmmsg) { // int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags, struct timespec *timeout)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, %u, %u, 0x%p)\n",
       		(unsigned long)ip,
       		"recvmmsg",
			(int)arg0,
			(struct mmsghdr *)arg1,
			(unsigned int)arg2,
			(unsigned int)arg3,
			(struct timespec *)arg4);
		

	} else if (num == SYS_remap_file_pages) { // int remap_file_pages(void *addr, size_t size, int prot, ssize_t pgoff, int flags)
		fprintf(trace,"0x%lx: %s(0x%p, %lu, %i, %ld, %i)\n",
			(unsigned long) ip,
			"remap_file_pages",
			(void *)arg0,
			(size_t)arg1,
			(int)arg2,
			(ssize_t)arg3,
			(int)arg4);

	} else if (num == SYS_removexattr) { // int removexattr(const char *path, const char *name)
		fprintf(trace,"0x%lx: %s(%s, %s)\n",
			(unsigned long) ip,
			"removexattr",
			(const char *)arg0,
			(const char *)arg1);

	} else if (num == SYS_rename) { // int rename(const char *oldpath, const char *newpath)
		fprintf(trace,"0x%lx: %s(%s, %s)\n",
			(unsigned long) ip,
			"rename",
			(const char *)arg0,
			(const char *)arg1);

	} else if (num == SYS_renameat) { // int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
		fprintf(trace,"0x%lx: %s(%i, %s, %i, %s)\n",
			(unsigned long) ip,
			"renameat",
			(int)arg0,
			(const char *)arg1,
			(int)arg2,
			(const char *)arg3);

	} else if (num == SYS_request_key) { // key_serial_t request_key(const char *type, const char *description, const char *callout_info, key_serial_t keyring)
		fprintf(trace,"0x%lx: %s(%s, %s, %s, %s, %i)\n",
			(unsigned long) ip,
			"request_key",
			(const char *)arg0,
			(const char *)arg1,
			(const char *)arg2,
			(const char *)arg3,
			(int)arg4);

	} else if (num == SYS_restart_syscall) { // int restart_syscall()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"restart_syscall");

	} else if (num == SYS_rmdir) { // int rmdir(const char *pathname)
		fprintf(trace,"0x%lx: %s(%s)\n",
			(unsigned long) ip,
			"rmdir",
			(const char *)arg0);

	} else if (num == SYS_rt_sigaction) { // int rt_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"rt_sigaction",
			(int)arg0,
			(const struct sigaction *)arg1,
			(struct sigaction *)arg2);

	} else if (num == SYS_rt_sigpending) { // int rt_sigpending(sigset_t *set)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"rt_sigpending",
			(sigset_t *)arg0);

	} else if (num == SYS_rt_sigprocmask) { // int rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"rt_sigprocmask",
			(int)arg0,
			(const sigset_t *)arg1,
			(sigset_t *)arg2);

	} else if (num == SYS_rt_sigqueueinfo) { // int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo)
		fprintf(trace,"0x%lx: %s(%i, %i, 0x%p)\n",
			(unsigned long) ip,
			"rt_sigqueueinfo",
			(pid_t)arg0,
			(int)arg1,
			(void *)arg2);

	} else if (num == SYS_rt_sigreturn) { // int rt_sigreturn(unsigned long __unused)
		fprintf(trace,"0x%lx: %s(%lu)\n",
			(unsigned long) ip,
			"rt_sigreturn",
			(unsigned long)arg0);

	} else if (num == SYS_rt_sigsuspend) { // int rt_sigsuspend(const sigset_t *mask)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"rt_sigsuspend",
			(const sigset_t *)arg0);

	} else if (num == SYS_rt_sigtimedwait) { // int rt_sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"rt_sigtimedwait",
			(const sigset_t *)arg0,
			(void *)arg1,
			(const struct timespec *)arg2);

	} else if (num == SYS_rt_tgsigqueueinfo) { // int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *uinfo)
		fprintf(trace,"0x%lx: %s(%i, %i, %i, 0x%p)\n",
			(unsigned long) ip,
			"rt_tgsigqueueinfo",
			(pid_t)arg0,
			(pid_t)arg1,
			(int)arg2,
			(void *)arg3);

	} else if (num == SYS_sched_get_priority_max) { // int sched_get_priority_max(int policy)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"sched_get_priority_max",
			(int)arg0);

	} else if (num == SYS_sched_get_priority_min) { // int sched_get_priority_min(int policy)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"sched_get_priority_min",
			(int)arg0);

	} else if (num == SYS_sched_getaffinity) { // int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask)
		fprintf(trace,"0x%lx: %s(%i, %lu, 0x%p)\n",
			(unsigned long) ip,
			"sched_getaffinity",
			(pid_t)arg0,
			(size_t)arg1,
			(cpu_set_t *)arg2);

	} else if (num == SYS_sched_getparam) { // int sched_getparam(pid_t pid, struct sched_param *param)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"sched_getparam",
			(pid_t)arg0,
			(struct sched_param *)arg1);

	} else if (num == SYS_sched_getscheduler) { // int sched_getscheduler(pid_t pid)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"sched_getscheduler",
			(pid_t)arg0);

	} else if (num == SYS_sched_rr_get_interval) { // int sched_rr_get_interval(pid_t pid, struct timespec *tp)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"sched_rr_get_interval",
			(pid_t)arg0,
			(struct timespec *)arg1);

	} else if (num == SYS_sched_setaffinity) { // int sched_setaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask)
		fprintf(trace,"0x%lx: %s(%i, %lu, 0x%p)\n",
			(unsigned long) ip,
			"sched_setaffinity",
			(pid_t)arg0,
			(size_t)arg1,
			(cpu_set_t *)arg2);

	} else if (num == SYS_sched_setparam) { // int sched_setparam(pid_t pid, const struct sched_param *param)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"sched_setparam",
			(pid_t)arg0,
			(const struct sched_param *)arg1);

	} else if (num == SYS_sched_setscheduler) { // int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)
		fprintf(trace,"0x%lx: %s(%i, %i, 0x%p)\n",
			(unsigned long) ip,
			"sched_setscheduler",
			(pid_t)arg0,
			(int)arg1,
			(const struct sched_param *)arg2);

	} else if (num == SYS_sched_yield) { // int sched_yield()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"sched_yield");

	} else if (num == SYS_select) { // int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, 0x%p, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"select",
			(int)arg0,
			(fd_set *)arg1,
			(fd_set *)arg2,
			(fd_set *)arg3,
			(struct timeval *)arg4);

	} else if (num == SYS_sendfile) { // ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
		fprintf(trace,"0x%lx: %s(%i, %i, %ld, %lu)\n",
			(unsigned long) ip,
			"sendfile",
			(int)arg0,
			(int)arg1,
			(off_t)arg2,
			(size_t)arg3);
			

	} else if (num == SYS_sendmmsg) { // ssize_t sendmmsg(int sockfd, const struct mmsghdr *msg, unsigned int vlen, unsigned int flags)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %u, %u)\n",
			(unsigned long) ip,
			"sendmmsg",
			(int)arg0,
			(const struct mmsghdr *)arg1,
			(unsigned int)arg2,
			(unsigned int)arg3);

	} else if (num == SYS_set_mempolicy) { // int set_mempolicy(int mode, unsigned long *nodesmask, unsigned long maxnode)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %lu)\n",
			(unsigned long) ip,
			"set_mempolicy",
			(int)arg0,
			(unsigned long *)arg1,
			(unsigned long)arg2);

	} else if (num == SYS_set_robust_list) { // long set_robust_list(struct robust_list_head *head, size_t len)
		fprintf(trace,"0x%lx: %s(0x%p, %lu)\n",
			(unsigned long) ip,
			"set_robust_list",
			(struct robust_list_head *)arg0,
			(size_t)arg1);

	} else if (num == SYS_set_thread_area) { // int set_thread_area(struct user_desc *u_info)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"set_thread_area",
			(struct user_desc *)arg0);

	} else if (num == SYS_set_tid_address) { // long set_tid_address(int *tidptr)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"set_tid_address",
			(int *)arg0);

	} else if (num == SYS_setdomainname) { // int setdomainname(const char *name, size_t len)
		fprintf(trace,"0x%lx: %s(%s, %lu)\n",
			(unsigned long) ip,
			"set_tid_address",
			(const char *)arg0,
			(size_t)arg1);

	} else if (num == SYS_setfsgid) { // int setfsgid(uid_t fsgid)
		fprintf(trace,"0x%lx: %s(%u)\n",
			(unsigned long) ip,
			"setfsgid",
			(uid_t)arg0);

	} else if (num == SYS_setfsuid) { // int setfsuid(uid_t fsuid)
		fprintf(trace,"0x%lx: %s(%u)\n",
			(unsigned long) ip,
			"setfsuid",
			(uid_t)arg0);

	} else if (num == SYS_setgid) { // int setgid(gid_t gid)
		fprintf(trace,"0x%lx: %s(%u)\n",
			(unsigned long) ip,
			"setgid",
			(gid_t)arg0);

	} else if (num == SYS_setgroups) { // int setgroups(size_t size, const gid_t *list)
		fprintf(trace,"0x%lx: %s(%lu, 0x%p)\n",
			(unsigned long) ip,
			"setgroups",
			(size_t)arg0,
			(const gid_t *)arg1);

	} else if (num == SYS_sethostname) { // int sethostname(const char *name, size_t len)
		fprintf(trace,"0x%lx: %s(%s, %lu)\n",
			(unsigned long) ip,
			"sethostname",
			(const char *)arg0,
			(size_t)arg1);

	} else if (num == SYS_setitimer) { // int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"setitimer",
			(int)arg0,
			(const struct itimerval *)arg1,
			(struct itimerval *)arg2);

	} else if (num == SYS_setns) { // int setns(int fd, int nstype)
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"setns",
			(int)arg0,
			(int)arg1);

	} else if (num == SYS_setpgid) { // int setpgid(pid_t pid, pid_t pgid)
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"setpgid",
			(pid_t)arg0,
			(pid_t)arg1);

	} else if (num == SYS_setpriority) { // int setpriority(int which, int who, int prio)
		fprintf(trace,"0x%lx: %s(%i, %i, %i)\n",
			(unsigned long) ip,
			"setpriority",
			(int)arg0,
			(int)arg1,
			(int)arg2);

	} else if (num == SYS_setregid) { // int setregid(gid_t rgid, gid_t egid)
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"setregid",
			(gid_t)arg0,
			(gid_t)arg1);

	} else if (num == SYS_setresgid) { // int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
		fprintf(trace,"0x%lx: %s(%i, %i, %i)\n",
			(unsigned long) ip,
			"setresgid",
			(gid_t)arg0,
			(gid_t)arg1,
			(gid_t)arg2);

	} else if (num == SYS_setresuid) { // int setresuid(uid_t ruid, uid_t euid, uid_t suid)
		fprintf(trace,"0x%lx: %s(%i, %i, %i)\n",
			(unsigned long) ip,
			"setresuid",
			(uid_t)arg0,
			(uid_t)arg1,
			(uid_t)arg2);

	} else if (num == SYS_setreuid) { // int setreuid(uid_t ruid, uid_t euid)
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"setreuid",
			(uid_t)arg0,
			(uid_t)arg1);

	} else if (num == SYS_setrlimit) { // int setrlimit(int resource, const struct rlimit *rlim)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"setrlimit",
			(int)arg0,
			(const struct rlimit *)arg1);

	} else if (num == SYS_setsid) { // pid_t setsid()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"setsid");

	} else if (num == SYS_settimeofday) { // int settimeofday(const struct timeval *tv, const struct timezone *tz)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p)\n",
			(unsigned long) ip,
			"settimeofday",
			(const struct timeval *)arg0,
			(const struct timezone *)arg1);

	} else if (num == SYS_setuid) { // int setuid(uid_t uid)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"setuid",
			(uid_t)arg0);

	} else if (num == SYS_setxattr) { // setxattr(int fd, const char *name, const void      *value, size_t size, int flags)
		fprintf(trace,"0x%lx: %s(%i, %s, 0x%p, %lu, %i)\n",
			(unsigned long) ip,
			"setxattr",
			(int)arg0,
			(const char *)arg1,
			(const void *)arg2,
			(size_t)arg3,
			(int)arg4);

	} else if (num == SYS_sigaltstack) { // const stack_t *ss, stack_t *oss)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p)\n",
			(unsigned long) ip,
			"sigaltstack",
			(void *)arg0,
			(void *)arg1);

	} else if (num == SYS_signalfd) { // int signalfd(int fd, const sigset_t *mask, int flags)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %i)\n",
			(unsigned long) ip,
			"signalfd",
			(int)arg0,
			(const sigset_t *)arg1,
			(int)arg2);

	} else if (num == SYS_signalfd4) { // int signalfd4(int fd, const sigset_t *mask, int flags)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %i)\n",
			(unsigned long) ip,
			"signalfd",
			(int)arg0,
			(const sigset_t *)arg1,
			(int)arg2);

	} else if (num == SYS_splice) { // ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %i, 0x%p, %lu, %u)\n",
			(unsigned long) ip,
			"splice",
			(int)arg0,
			(void *)arg1,
			(int)arg2,
			(void *)arg3,
			(size_t)arg4,
			(unsigned int)arg5);

	} else if (num == SYS_stat) { // stat(const char *path, struct stat *buf)
		fprintf(trace,"0x%lx: %s(%s, 0x%p)\n",
			(unsigned long) ip,
			"stat",
			(const char *)arg0,
			(void *)arg1);

	} else if (num == SYS_statfs) { //statfs(const char *path, struct statfs *buf)
		fprintf(trace,"0x%lx: %s(%s, 0x%p)\n",
			(unsigned long) ip,
			"statfs",
			(const char *)arg0,
			(void *)arg1);

	} else if (num == SYS_swapoff) { // int swapoff(const char *path)
		fprintf(trace,"0x%lx: %s(%s)\n",
			(unsigned long) ip,
			"swapoff",
			(const char *)arg0);

	} else if (num == SYS_swapon) { // int swapon(const char *path, int swapflags)
		fprintf(trace,"0x%lx: %s(%s, %i)\n",
			(unsigned long) ip,
			"swapon",
			(const char *)arg0,
			(int)arg1);

	} else if (num == SYS_symlink) { // int symlink(const char *oldpath, const char *newpath)
		fprintf(trace,"0x%lx: %s(%s, %s)\n",
			(unsigned long) ip,
			"symlink",
			(const char *)arg0,
			(const char *)arg1);

	} else if (num == SYS_symlinkat) { // int symlinkat(const char *oldpath, int newdirfd, const char *newpath)
		fprintf(trace,"0x%lx: %s(%s, %i, %s)\n",
			(unsigned long) ip,
			"symlinkat",
			(const char *)arg0,
			(int)arg1,
			(const char *)arg2);

	} else if (num == SYS_sync) { // void sync()
		fprintf(trace,"0x%lx: %s()\n",
			(unsigned long) ip,
			"sync");

	} else if (num == SYS_sync_file_range) { // int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags)
		fprintf(trace,"0x%lx: %s(%i, %ld, %ld, %u)\n",
			(unsigned long) ip,
			"sync_file_range",
			(int)arg0,
			(off64_t)arg1,
			(off64_t)arg2,
			(unsigned int)arg3);

	} else if (num == SYS_syncfs) { // int syncfs(int fd)
		fprintf(trace,"0x%lx: %s(%i)\n",
			(unsigned long) ip,
			"syncfs",
			(int)arg0);

	} else if (num == SYS_sysfs) {
		#define GETFSIND	1
		#define GETFSTYP	2
		#define GETNFSTYP	3
		int opcode = (int) arg0;
		if (opcode == GETFSIND) { // int sysfs(GETFSIND, const char *fsname)
			fprintf(trace,"0x%lx: %s(%i, %s)\n",
				(unsigned long) ip,
				"sysfs",
				(int)arg0,
				(const char *)arg1);
			
		} else if (opcode == GETFSTYP) { // int sysfs(GETFSYP, int fs_index, char *buf)
			fprintf(trace,"0x%lx: %s(%i, %i, 0x%p)\n",
				(unsigned long) ip,
				"sysfs",
				(int)arg0,
				(int)arg1,
				(void *)arg2);

		} else if (opcode == GETNFSTYP) { // int sysfs(GETNFSTYP)
			fprintf(trace,"0x%lx: %s(%i)\n",
				(unsigned long) ip,
				"sysfs",
				(int)arg0);
		}

	} else if (num == SYS_sysinfo) { // int sysinfo(struct sysinfo *info)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"sysinfo",
			(struct sysinfo *)arg0);

	} else if (num == SYS_syslog) { // int syslog(int type, char *bufp, int len)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %i)\n",
			(unsigned long) ip,
			"syslog",
			(int)arg0,
			(void *)arg1,
			(int)arg2);

	} else if (num == SYS_tee) { // ssize_t tee(int fd_in, int fd_out, size_t len)
		fprintf(trace,"0x%lx: %s(%i, %i, %lu)\n",
			(unsigned long) ip,
			"tee",
			(int)arg0,
			(int)arg1,
			(size_t)arg2);

	} else if (num == SYS_tgkill) { // int tgkill(int tgid, int tid, int sig)
		fprintf(trace,"0x%lx: %s(%i, %i, %i)\n",
			(unsigned long) ip,
			"tgkill",
			(int)arg0,
			(int)arg1,
			(int)arg2);

	} else if (num == SYS_time) { // time_t time(time_t *t)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"time",
			(time_t *)arg0);

	} else if (num == SYS_timer_create) { // int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"timer_create",
			(clockid_t)arg0,
			(struct sigevent *)arg1,
			(timer_t *)arg2);

	} else if (num == SYS_timer_delete) { // int timer_delete(timer_t timerid)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"timer_delete",
			(timer_t)arg0);

	} else if (num == SYS_timer_getoverrun) { // int timer_getoverrun(timer_t timerid)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"timer_getoverrun",
			(timer_t)arg0);

	} else if (num == SYS_timer_gettime) { // int timer_gettime(timer_t timerid, struct itimerspec *value)
		fprintf(trace,"0x%lx: %s(0x%p, 0x%p)\n",
			(unsigned long) ip,
			"timer_gettime",
			(timer_t)arg0,
			(struct itimerspec *)arg1);

	} else if (num == SYS_timer_settime) { // int settime(timer_t timerid, int flags, const struct itimerspec *restrict value, struct itimerspec *restrict ovalue)
		fprintf(trace,"0x%lx: %s(0x%p, %i, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"timer_settime",
			(timer_t)arg0,
			(int)arg1,
			(const struct itimerspec *)arg2,
			(struct itimerspec *)arg3);

	} else if (num == SYS_timerfd_create) { // int timerfd_create(int clockid, int flags)
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"timerfd_create",
			(int)arg0,
			(int)arg1);

	} else if (num == SYS_timerfd_gettime) { // int timerfd_gettime(int fd, struct itimerspec *curr_value)
		fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
			(unsigned long) ip,
			"timerfd_gettime",
			(int)arg0,
			(struct itimerspec *)arg1);

	} else if (num == SYS_timerfd_settime) { // int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value)
		fprintf(trace,"0x%lx: %s(%i, %i, 0x%p, 0x%p)\n",
			(unsigned long) ip,
			"timerfd_settime",
			(int)arg0,
			(int)arg1,
			(const struct itimerspec *)arg2,
			(struct itimerspec *)arg3);

	} else if (num == SYS_times) { // clock_t times(struct tms *buf)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"times",
			(struct tms *)arg0);

	} else if (num == SYS_tkill) { // int tkill(int tid, int sig) [obsolete predecessor to tgkill()]
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"tkill",
			(int)arg0,
			(int)arg1);

	} else if (num == SYS_truncate) { // truncate(cons char *path, off_t length)
    	fprintf(trace,"0x%lx: %s(%s, %u)\n",
       		(unsigned long)ip,
       		"truncate",
			(const char *)arg0,
			(unsigned int)arg1);

	} else if (num == SYS_umask) { // mode_t umask(mode_t mask)
    	fprintf(trace,"0x%lx: %s(%u)\n",
       		(unsigned long)ip,
       		"umask",
			(mode_t)arg0);

	} else if (num == SYS_umount2) { // int umount2(const char *target, int flags)
    	fprintf(trace,"0x%lx: %s(%s, %i)\n",
       		(unsigned long)ip,
       		"umount2",
			(const char *)arg0,
			(int)arg1);

	} else if (num == SYS_uname) { // int uname(struct utsname *buf)
    	fprintf(trace,"0x%lx: %s(0x%p)\n",
       		(unsigned long)ip,
       		"uname",
			(struct utsname *)arg0);

	} else if (num == SYS_unlink) { // int unlink(const char *pathname)
    	fprintf(trace,"0x%lx: %s(%s)\n",
       		(unsigned long)ip,
       		"unlink",
			(const char *)arg0);

	} else if (num == SYS_unlinkat) { // int unlinkat(int dirfd, const char *pathname, int flags)
    	fprintf(trace,"0x%lx: %s(%i, %s, %i)\n",
       		(unsigned long)ip,
       		"unlinkat",
			(int)arg0,
			(const char *)arg1,
			(int)arg2);

	} else if (num == SYS_unshare) { // int unshare(int flags)
    	fprintf(trace,"0x%lx: %s(%i)\n",
       		(unsigned long)ip,
       		"unshare",
			(int)arg0);

	} else if (num == SYS_uselib) { // int uselib(constr char *library)
    	fprintf(trace,"0x%lx: %s(%s)\n",
       		(unsigned long)ip,
       		"uselib",
			(const char *)arg0);

	} else if (num == SYS_ustat) { // int ustat(dev_t dev, struct ustat *ubuf)
    	fprintf(trace,"0x%lx: %s(%lu, 0x%p)\n",
       		(unsigned long)ip,
       		"ustat",
			(dev_t)arg0,
			(struct ustat *)arg1);

	} else if (num == SYS_utime) { // int utime(const char *filename, const struct utimbuf *times)
    	fprintf(trace,"0x%lx: %s(%s, 0x%p)\n",
       		(unsigned long)ip,
       		"utime",
			(const char *)arg0,
			(const struct utimbuf *)arg1);

	} else if (num == SYS_utimensat) { // int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags)
    	fprintf(trace,"0x%lx: %s(%i, %s, 0x%p, %i)\n",
       		(unsigned long)ip,
       		"utimensat",
			(int)arg0,
			(const char *)arg1,
			(void *)arg2,
			(int)arg3);

	} else if (num == SYS_utimes) { // int utimes(const char *filename, const struct timeval times[2])
    	fprintf(trace,"0x%lx: %s(%s, 0x%p)\n",
       		(unsigned long)ip,
       		"utimes",
			(const char *)arg0,
			(void *)arg1);

	} else if (num == SYS_vfork) { // pid_t vfork()
    	fprintf(trace,"0x%lx: %s()\n",
       		(unsigned long)ip,
       		"vfork");

	} else if (num == SYS_vhangup) { // int vhangup()
    	fprintf(trace,"0x%lx: %s()\n",
       		(unsigned long)ip,
       		"vhangup");

	} else if (num == SYS_vmsplice) { // ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, %lu, %u)\n",
       		(unsigned long)ip,
       		"vmsplice",
			(int)arg0,
			(const struct iovec *)arg1,
			(unsigned long)arg2,
			(unsigned int)arg3);

	} else if (num == SYS_vserver) {
		fprintf(trace,"0x%lx: %s [UNIMPLEMENTED in the Linux kernel]\n",
			(unsigned long) ip,
			"vserver");

	} else if (num == SYS_wait4) { // pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, %i, 0x%p)\n",
       		(unsigned long)ip,
       		"wait4",
			(pid_t)arg0,
			(int *)arg1,
			(int)arg2,
			(struct rusage *)arg3);

	} else if (num == SYS_waitid) { // int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)
    	fprintf(trace,"0x%lx: %s(%i, %i, 0x%p, %i)\n",
       		(unsigned long)ip,
       		"waitid",
			(uint32_t)arg0,
			(uint32_t)arg1,
			(void *)arg2,
			(int)arg3);

	} else if (num == SYS_write) { // ssize_t write(int fd, const void *buf, size_t count)
		string written = "'";
		char *buf = (char *)arg1;
		for (unsigned int i = 0; i < (size_t)arg2; i++) {
			if (buf[i] == '\0') {
				break;
			} else {
				char z = buf[i];
				written += sanitize(z);
			}
		}
		written += "'";
    	fprintf(trace,"0x%lx: %s(%i, %s, %lu)\n",
       		(unsigned long)ip,
       		"write",
			(int)arg0,
			//(const void *)arg1,
			written.c_str(),
			(size_t)arg2);

	} else if (num == SYS_writev) { // ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
		// TODO: special implentation
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, %i)\n",
       		(unsigned long)ip,
       		"writev",
			(int)arg0,
			(const struct iovec *)arg1,
			(int)arg2);

	} else if (num == SYS_accept) { // int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, 0x%p)\n",
       		(unsigned long)ip,
       		"accept",
			(int)arg0,
			(struct sockaddr *)arg1,
			(void *)arg2);

	} else if (num == SYS_accept4) { // int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, 0x%p, %i)\n",
       		(unsigned long)ip,
       		"accept4",
			(int)arg0,
			(struct sockaddr *)arg1,
			(void *)arg2,
			(int)arg3);

	} else if (num == SYS_arch_prctl) { // int arch_prctl(int code, unsigned long [*]addr)
		#define ARCH_SET_GS 0x1001
		#define ARCH_SET_FS 0x1002
		#define ARCH_GET_FS 0x1003
		#define ARCH_GET_GS 0x1004

		int code = (int)arg0;
		if (code == ARCH_SET_FS || code == ARCH_SET_GS) { // treat 2nd arg as unsinged long
			fprintf(trace,"0x%lx: %s(%i, %lu)\n",
				(unsigned long) ip,
				"arch_prctl",
				(int)arg0,
				(unsigned long)arg1);
		} else { // treat 2nd arg as unsinged long *
			fprintf(trace,"0x%lx: %s(%i, 0x%p)\n",
				(unsigned long) ip,
				"arch_prctl",
				(int)arg0,
				(unsigned long *)arg1);
		}

	} else if (num == SYS_bind) { // int bind(int sockfd, const struct sockaddr *my_addr, socklen_t addrlen)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, %i)\n",
       		(unsigned long)ip,
       		"bind",
			(int)arg0,
			(void *)arg1,
			(int)arg2);

	} else if (num == SYS_connect) { // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, %i)\n",
       		(unsigned long)ip,
       		"connect",
			(int)arg0,
			(void *)arg1,
			(int)arg2);
			
	} else if (num == SYS_epoll_ctl_old) { // int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
    	fprintf(trace,"0x%lx: %s(%i, %i, %i, 0x%p)\n",
       		(unsigned long)ip,
       		"epoll_ctl_old",
			(int)arg0,
			(int)arg1,
			(int)arg2,
			(struct epoll_event *)arg3);

	} else if (num == SYS_epoll_wait_old) { // int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, %i, %i)\n",
       		(unsigned long)ip,
       		"epoll_wait_old",
			(int)arg0,
			(struct epoll_event *)arg1,
			(int)arg2,
			(int)arg3);

	} else if (num == SYS_getpeername) { // int getpeername(int s, struct sockaddr *name, socklen_t *namelen)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, 0x%p)\n",
       		(unsigned long)ip,
       		"getpeername",
			(int)arg0,
			(struct sockaddr *)arg1,
			(void *)arg2);

	} else if (num == SYS_getsockname) { // int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, 0x%p)\n",
       		(unsigned long)ip,
       		"getsockname",
			(int)arg0,
			(struct sockaddr *)arg1,
			(void *)arg2);

	} else if (num == SYS_getsockopt) { // int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
    	fprintf(trace,"0x%lx: %s(%i, %i, %i, 0x%p, 0x%p)\n",
       		(unsigned long)ip,
       		"getsockopt",
			(int)arg0,
			(int)arg1,
			(int)arg2,
			(void *)arg3,
			(void *)arg4);

	} else if (num == SYS_listen) { // int listen(int sockfd, int backlog)
    	fprintf(trace,"0x%lx: %s(%i, %i)\n",
       		(unsigned long)ip,
       		"listen",
			(int)arg0,
			(int)arg1);

	} else if (num == SYS_msgctl) { // int msgctl(int msqid, int cmd, struct msqid_ds *buf)
    	fprintf(trace,"0x%lx: %s(%i, %i, 0x%p)\n",
       		(unsigned long)ip,
       		"msgctl",
			(int)arg0,
			(int)arg1,
			(struct msqid_ds *)arg2);

	} else if (num == SYS_msgget) { // int msgget(key_t key, int msgflag)
    	fprintf(trace,"0x%lx: %s(%i, %i)\n",
       		(unsigned long)ip,
       		"msgget",
			(key_t)arg0,
			(int)arg1);

	} else if (num == SYS_msgrcv) { // ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtp, int msgflg)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, %lu, %ld, %i)\n",
       		(unsigned long)ip,
       		"msgrcv",
			(int)arg0,
			(void *)arg1,
			(size_t)arg2,
			(long)arg3,
			(int)arg4);

	} else if (num == SYS_msgsnd) { // int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, %lu, %i)\n",
       		(unsigned long)ip,
       		"msgsend",
			(int)arg0,
			(const void *)arg1,
			(size_t)arg2,
			(int)arg3);

	} else if (num == SYS_newfstatat) { // int newfstatat(int dfd, char *filename, struct stat *buf, int flag)
    	fprintf(trace,"0x%lx: %s(%i, %s, 0x%p, %i)\n",
       		(unsigned long)ip,
       		"newfstatat",
			(int)arg0,
			(char *)arg1,
			(struct stat *)arg2,
			(int)arg3);

	} else if (num == SYS_recvfrom) { // ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
    	fprintf(trace,"0x%lx: %s(%i, 0x%p, %lu, %i, 0x%p, 0x%p)\n",
       		(unsigned long)ip,
       		"recvfrom",
			(int)arg0,
			(void *)arg1,
			(size_t)arg2,
			(int)arg3,
			(struct sockaddr *)arg4,
			(void *)arg5);

	} else if (num == SYS_recvmsg) { // ssize_t recvmsg(int s, struct msghdr *msg, int flags)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %i)\n",
			(unsigned long) ip,
			"recvmsg",
			(int)arg0,
			(struct msghdr *)arg1,
			(int)arg2);

	} else if (num == SYS_security) {
		fprintf(trace,"0x%lx: %s [UNIMPLEMENTED in the Linux kernel]\n",
			(unsigned long) ip,
			"security");

	} else if (num == SYS_semctl) { // int semctl(int semid, int semnum, int cmd, union semun sem)
		fprintf(trace,"0x%lx: %s(%i, %i, %i, 0x%p) [4th argument may or may not be used depending on cmd input]\n",
			(unsigned long) ip,
			"semctl",
			(int)arg0,
			(int)arg1,
			(int)arg2,
			(void *)arg3);

	} else if (num == SYS_semget) { // int semget(key_t key, int nsems, int semflg)
		fprintf(trace,"0x%lx: %s(%i, %i, %i)\n",
			(unsigned long) ip,
			"semget",
			(key_t)arg0,
			(int)arg1,
			(int)arg2);

	} else if (num == SYS_semop) { // int semop(int semid, struct sembuf *sops, unsigned nsops)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %u)\n",
			(unsigned long) ip,
			"semop",
			(int)arg0,
			(struct sembuf *)arg1,
			(unsigned)arg2);

	} else if (num == SYS_semtimedop) { // int semtimedop(int semid, struct sembuf *sops, unsigned nsops, struct timespec *timeout)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %u, 0x%p)\n",
			(unsigned long) ip,
			"semtimedop",
			(int)arg0,
			(struct sembuf *)arg1,
			(unsigned)arg2,
			(struct timespec *)arg3);

	} else if (num == SYS_sendmsg) { // ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %i)\n",
			(unsigned long) ip,
			"sendmsg",
			(int)arg0,
			(void *)arg1,
			(int)arg1);

	} else if (num == SYS_sendto) { // ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %lu, %i, 0x%p, %i)\n",
			(unsigned long) ip,
			"sendto",
			(int)arg0,
			(const void *)arg1,
			(size_t)arg2,
			(int)arg3,
			(const struct sockaddr *)arg4,
			(int)arg5);

	} else if (num == SYS_setsockopt) { // int sockfd, int level, int optname, const void *optval, socklen_t optlen)
		fprintf(trace,"0x%lx: %s(%i, %i, %i, 0x%p, %i)\n",
			(unsigned long) ip,
			"setsockopt",
			(int)arg0,
			(int)arg1,
			(int)arg2,
			(const void *)arg3,
			(int)arg4);

	} else if (num == SYS_shmat) { // void *shmat(int shmid, const void *shmaddr, int shmflg)
		fprintf(trace,"0x%lx: %s(%i, 0x%p, %i)\n",
			(unsigned long) ip,
			"shmat",
			(int)arg0,
			(const void *)arg1,
			(int)arg2);

	} else if (num == SYS_shmctl) {  // int shmctl(int shmid, int cmd, struct shmid_ds *buf)
		fprintf(trace,"0x%lx: %s(%i, %i, 0x%p)\n",
			(unsigned long) ip,
			"shmctl",
			(int)arg0,
			(int)arg1,
			(struct shmid_ds *)arg2);

	} else if (num == SYS_shmdt) { // int shmdt(const void *shmaddr)
		fprintf(trace,"0x%lx: %s(0x%p)\n",
			(unsigned long) ip,
			"shmdt",
			(const void *)arg0);

	} else if (num == SYS_shmget) { // int shmget(key_t key, size_t size, int shmflg)
		fprintf(trace,"0x%lx: %s(%i, %lu, %i)\n",
			(unsigned long) ip,
			"shmget",
			(key_t)arg0,
			(size_t)arg1,
			(int)arg2);

	} else if (num == SYS_shutdown) { // int shutdown(int s, int how)
		fprintf(trace,"0x%lx: %s(%i, %i)\n",
			(unsigned long) ip,
			"shutdown",
			(int)arg0,
			(int)arg1);
	} else if (num == SYS_socket) { // int socket(int domain, int type, int protocol)
		fprintf(trace,"0x%lx: %s(%i, %i, %i)\n",
			(unsigned long) ip,
			"socket",
			(int)arg0,
			(int)arg1,
			(int)arg2);
	} else if (num == SYS_socketpair) { // int socketpair(int d, int type, int protocol, int sv[2])
		fprintf(trace,"0x%lx: %s(%i, %i, %i, 0x%p)\n",
			(unsigned long) ip,
			"socketpair",
			(int)arg0,
			(int)arg1,
			(int)arg2,
			(void *)arg3);

	} else if (num == SYS_tuxcall) {
		fprintf(trace,"0x%lx: %s [UNIMPLEMENTED in the Linux kernel]\n",
			(unsigned long) ip,
			"tuxcall");
	} else {
    	fprintf(trace,"0x%lx: %ld(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)",
       		(unsigned long)ip,
       		(long)num,
       		(unsigned long)arg0,
       		(unsigned long)arg1,
       		(unsigned long)arg2,
       		(unsigned long)arg3,
       		(unsigned long)arg4,
       		(unsigned long)arg5);
		
	}

}

// Print the return value of the system call
VOID SysAfter(ADDRINT ret, ADDRINT num, ADDRINT errno) {

	if (errno != 0) {
		fprintf(trace,"\treturns: %i %s\n", (int)ret, error_map[errno].c_str());
	} else if (ret_map[num] == UNKNOWN) {
   		fprintf(trace,"\treturns: 0x%lx\n", (signed long)ret);
	} else if (ret_map[num] == INT) {
		fprintf(trace,"\treturns: %i\n", (int)ret);
	} else if (ret_map[num] == STR) {
		fprintf(trace,"\treturns: %s\n", (char *)ret);
	} else if (ret_map[num] == PTR) {
   		fprintf(trace,"\treturns: 0x%p\n", (void *)ret);
	} else if (ret_map[num] == UNSIGNED) {
   		fprintf(trace,"\treturns: %u\n", (unsigned)ret);
	} else if (ret_map[num] == NONE) {
   		fprintf(trace,"\treturns (no return value)\n");
	} else if (ret_map[num] == SSIZE_T) {
		fprintf(trace,"\treturns: %ld\n", (ssize_t)ret);
	} else if (ret_map[num] == CLOCK_T) {
		fprintf(trace,"\treturns: %ld\n", (clock_t)ret);
	} else if (ret_map[num] == MODE_T) {
		fprintf(trace,"\treturns: %u\n", (mode_t)ret);
	} else if (ret_map[num] == PID_T) {
		fprintf(trace,"\treturns: %i\n", (pid_t)ret);
	} else if (ret_map[num] == PID_T) {
		fprintf(trace,"\treturns: %ld\n", (time_t)ret);
	} else if (ret_map[num] == LONG) {
		fprintf(trace,"\treturns: %ld\n", (long)ret);
	} else if (ret_map[num] == KEY_SERIAL_T) {
		fprintf(trace,"\treturns: %i\n", (int)ret);
	} else if (ret_map[num] == GID_T) {
		fprintf(trace,"\treturns: %i\n", (gid_t)ret);
	} else if (ret_map[num] == UID_T) {
		fprintf(trace,"\treturns: %i\n", (uid_t)ret);
	} else if (ret_map[num] == OFF_T) {
		fprintf(trace,"\treturns: %ld\n", (off_t)ret);
	}
    fflush(trace);
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
    SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
        PIN_GetSyscallNumber(ctxt, std),
        PIN_GetSyscallArgument(ctxt, std, 0),
        PIN_GetSyscallArgument(ctxt, std, 1),
        PIN_GetSyscallArgument(ctxt, std, 2),
        PIN_GetSyscallArgument(ctxt, std, 3),
        PIN_GetSyscallArgument(ctxt, std, 4),
        PIN_GetSyscallArgument(ctxt, std, 5));
	eip_syscall_map[PIN_GetContextReg(ctxt, REG_INST_PTR)] = PIN_GetSyscallNumber(ctxt, std);
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
    // SysAfter(PIN_GetSyscallReturn(ctxt, std), PIN_GetSyscallNumber(ctxt, std));
	// The above line shows how the sample strace got the syscall number for syscall exit
	// However, this did not work very well, as the syscall was not properly retrieved
	// Instead, I am using a map of eip-2 (syscall entry) to syscall number

    SysAfter(PIN_GetSyscallReturn(ctxt, std), eip_syscall_map[(PIN_GetContextReg(ctxt, REG_INST_PTR)-2)], PIN_GetSyscallErrno(ctxt, std));
        
}

// Is called for every instruction and instruments syscalls
VOID Instruction(INS ins, VOID *v)
{
    // For O/S's (Mac) that don't support PIN_AddSyscallEntryFunction(),
    // instrument the system call instruction.

    if (INS_IsSyscall(ins) && INS_HasFallThrough(ins))
    {
        // Arguments and syscall number is only available before
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
                       IARG_INST_PTR, IARG_SYSCALL_NUMBER,
                       IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
                       IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3,
                       IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
                       IARG_END);

        // return value only available after
        INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SysAfter),
                       IARG_SYSRET_VALUE,
                       IARG_END);
    }
}

VOID Fini(INT32 code, VOID *v)
{
    fprintf(trace,"#eof\n");
    fclose(trace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR("This tool prints a log of system calls" 
                + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{

	if(__WORDSIZE != 64) {
		cout << "This pintool is designed for 64-bit Linux systems" << endl;
	}
	ret_map = getMap();
	error_map = getErrorMap();

    if (PIN_Init(argc, argv)) return Usage();

    trace = fopen("strace.out", "w");

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}

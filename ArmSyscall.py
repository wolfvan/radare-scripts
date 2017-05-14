import r2pipe
import sys
import os


def extractSyscall(line):
	if "0x90" in line:
		syscall = line.split(" ")[6]
		return syscall[:-1]
	else: return 0

def extractAddr(line):
	if "0x90" in line:
		addr = line.split(" ")[0]
		return addr
	else: return 0


class ARM(object):
	def __init__(self, bin):
		self.r2 = r2pipe.open(bin)

	def execute(self):
		self.r2.cmd("aaa")
		syscll = self.getSyscall()
		self.writeSyscall(syscll)
		self.addComment()

	def getSyscall(self):
		tot_syscall = self.r2.cmd("/c svc")
		return tot_syscall

	def writeSyscall(self, syscll):
		os.system("touch /tmp/syscallARM")
		f = open("/tmp/syscallARM", "w")
		f.write(syscll)

	def addComment(self):
		dic = {"0x900000":"reset_syscall", "0x900001":"exit","0x900002":"fork","0x900003":"read","0x900004":"write","0x900005":"open","0x900006":"close","0x900008":"creat","0x900009":"link","0x90000a":"unlink","0x90000b":"execve","0x90000c":"chdir","0x90000d":"time","0x90000e":"mknod","0x90000f":"chmod","0x900010":"lchown","0x900013":"lseek","0x900014":"getpid","0x900015":"mount","0x900016":"umount","0x900017":"setuid","0x900018":"getuid","0x900019":"stime","0x90001a":"ptrace","0x90001b":"alarm","0x90001d":"pause","0x90001e":"utime","0x900021":"access","0x900022":"nice","0x900024":"sync","0x900025":"kill","0x900026":"rename","0x900027":"mkdir","0x900028":"rmdir","0x900029":"dup","0x90002a":"pipe","0x90002b":"times","0x90002d":"brk","0x90002e":"setgid","0x90002f":"getgid","0x900031":"geteuid","0x900032":"getegid","0x900033":"acct","0x900034":"umount2","0x900036":"ioctl","0x900037":"fcntl","0x900039":"setpgid","0x90003c":"umask","0x90003d":"chroot","0x90003e":"ustat","0x90003f":"dup2","0x900040":"getppid","0x900041":"getpgrp","0x900042":"setsid","0x900043":"sigaction","0x900046":"setreuid","0x900047":"setregid","0x900048":"sigsuspend","0x900049":"sigpending","0x90004a":"sethostname","0x90004b":"setrlimit","0x90004c":"getrlimit","0x90004d":"getrusage","0x90004e":"gettimeofday","0x90004f":"settimeofday","0x900050":"getgroups","0x900051":"setgroups","0x900052":"select","0x900053":"symlink","0x900055":"readlink","0x900056":"uselib","0x900057":"swapon","0x900058":"reboot","0x900059":"readdir","0x90005a":"mmap","0x90005b":"munmap","0x90005c":"truncate","0x90005d":"ftruncate","0x90005e":"fchmod","0x90005f":"fchown","0x900060":"getpriority","0x900061":"setpriority","0x900063":"statfs","0x900064":"fstatfs","0x900066":"socketcall","0x900067":"syslog","0x900068":"setitimer","0x900069":"getitimer","0x90006a":"stat","0x90006b":"lstat","0x90006c":"fstat","0x90006f":"vhangup","0x900071":"syscall","0x900072":"wait4","0x900073":"swapoff","0x900074":"sysinfo","0x900075":"ipc","0x900076":"fsync","0x900077":"sigreturn","0x900078":"clone","0x900079":"setdomainname","0x90007a":"uname","0x90007c":"adjtimex","0x90007d":"mprotect","0x90007e":"sigprocmask","0x900080":"init_module","0x900081":"delete_module","0x900083":"quotactl","0x900084":"getpgid","0x900085":"fchdir","0x900086":"bdflush","0x900087":"sysfs","0x900088":"personality","0x90008a":"setfsuid","0x90008b":"setfsgid","0x90008c":"_llseek","0x90008d":"getdents","0x90008e":"_newselect","0x90008f":"flock","0x900090":"msync","0x900091":"readv","0x900092":"writev","0x900093":"getsid","0x9000ned":"fdatasync","0x900095":"_sysctl","0x900096":"mlock","0x900097":"munlock","0x900098":"mlockall","0x900099":"munlockall","0x90009a":"sched_setparam","0x90009b":"sched_getparam","0x90009c":"sched_setscheduler","0x90009d":"sched_getscheduler","0x90009e":"sched_yield","0x90009f":"sched_get_priority_max","0x9000a0":"sched_get_priority_min","0x9000a1":"sched_rr_get_interval","0x9000a2":"nanosleep","0x9000a3":"mremap","0x9000a4":"setresuid","0x9000a5":"getresuid","0x9000a8":"poll","-":"nfsservctl","0x9000aa":"setresgid","0x9000ab":"getresgid","0x9000ad":"rt_sigreturn","0x9000af":"rt_sigprocmask","0x9000b0":"rt_sigpending","0x9000b1":"rt_sigtimedwait","0x9000b2":"rt_sigqueueinfo","0x9000b3":"rt_sigsuspend","0x9000b4":"pread64","0x9000b5":"pwrite64","0x9000b6":"chown","0x9000b7":"getcwd","0x9000b8":"capget","0x9000b9":"capset","-":"sigaltstack","0x9000bb":"sendfile","0x9000be":"vfork","0x9000bf":"ugetrlimit","0x9000c0":"mmap2","0x9000c1":"truncate64","0x9000c2":"ftruncate64","0x9000c3":"stat64","0x9000c4":"lstat64","0x9000c5":"fstat64","0x9000c6":"lchown32","0x9000c7":"getuid32","0x9000c8":"getgid32","0x9000c9":"geteuid32","0x9000ca":"getegid32","0x9000cb":"setreuid32","0x9000cc":"setregid32","0x9000cd":"getgroups32","0x9000ce":"setgroups32","0x9000cf":"fchown32","0x9000d0":"setresuid32","0x9000d1":"getresuid32","0x9000d2":"setresgid32","0x9000d3":"getresgid32","0x9000d5":"setuid32","0x9000d6":"setgid32","0x9000d7":"setfsuid32","0x9000d8":"setfsgid32","0x9000d9":"getdents64","0x9000da":"pivot_root","0x9000db":"mincore","0x9000dc":"madvise","0x9000dd":"fcntl64","0x9000e0":"gettid","0x9000e1":"readahead","0x9000e2":"setxattr","0x9000e3":"lsetxattr","0x9000e4":"fsetxattr","0x9000e5":"getxattr","0x9000e6":"lgetxattr","0x9000e7":"fgetxattr","0x9000e8":"listxattr","0x9000e9":"llistxattr","0x9000ea":"flistxattr","0x9000eb":"removexattr","0x9000ec":"lremovexattr","0x9000ed":"fremovexattr","0x9000ee":"tkill","0x9000ef":"sendfile64","0x9000f0":"futex","0x9000f1":"sched_setaffinity","0x9000f2":"sched_getaffinity","0x9000f3":"io_setup","0x9000f4":"io_destroy","0x9000f5":"io_getevents","0x9000f6":"io_submit","0x9000f7":"io_cancel","0x9000f8":"exit_group","0x9000f9":"lookup_dcookie","0x9000fa":"epoll_create","0x9000fb":"epoll_ctl","0x9000fc":"epoll_wait","0x9000fd":"remap_file_pages","0x900100":"set_tid_address","0x900101":"timer_create","0x900102":"timer_settime","0x900103":"timer_gettime","0x900104":"timer_getoverrun","0x900105":"timer_delete","0x900106":"clock_settime","0x900107":"clock_gettime","0x900108":"clock_getres","0x900109":"clock_nanosleep","0x90010a":"statfs64","0x90010b":"fstatfs64","0x90010c":"tgkill","0x90010d":"utimes","0x90010e":"arm_fadvise64_64","-":"pciconfig_iobase","0x900110":"pciconfig_read","0x900111":"pciconfig_write","0x900112":"mq_open","0x900113":"mq_unlink","0x900114":"mq_timedsend","0x900115":"mq_timedreceive","0x900116":"mq_notify","0x900117":"mq_getsetattr","0x900118":"waitid","0x900119":"socket","0x90011a":"bind","0x90011b":"connect","0x90011c":"listen","0x90011d":"accept","0x90011e":"getsockname","0x90011f":"getpeername","0x900120":"socketpair","0x900121":"send","0x900122":"sendto","0x900123":"recv","0x900124":"recvfrom","0x900125":"shutdown","0x900126":"setsockopt","0x900127":"getsockopt","0x900128":"sendmsg","0x900129":"recvmsg","0x90012a":"semop","0x90012b":"semget","0x90012c":"semctl","0x90012d":"msgsnd","0x90012e":"msgrcv","0x90012f":"msgget","0x900130":"msgctl","0x900131":"shmat","0x900132":"shmdt","0x900133":"shmget","0x900134":"shmctl","0x900135":"add_key","0x900136":"request_key","0x900137":"keyctl","0x900138":"semtimedop","0x90013a":"ioprio_set","0x90013b":"ioprio_get","0x90013c":"inotify_init","0x90013d":"inotify_add_watch","0x90013e":"inotify_rm_watch","0x90013f":"mbind","0x900140":"get_mempolicy","0x900141":"set_mempolicy","0x900142":"openat","0x900143":"mkdirat","0x900144":"mknodat","0x900145":"fchownat","0x900146":"futimesat","0x900147":"fstatat64","0x900148":"unlinkat","0x900149":"renameat","0x90014a":"linkat","0x90014b":"symlinkat","0x90014c":"readlinkat","0x90014d":"fchmodat","0x90014e":"faccessat","0x90014f":"pselect6","0x900150":"ppoll","0x900151":"unshare","0x900152":"set_robust_list","0x900153":"get_robust_list","0x900154":"splice","0x900155":"sync_file_range2","0x900156":"tee","0x900157":"vmsplice","0x900158":"move_pages","0x900159":"getcpu","0x90015a":"epoll_pwait","0x90015b":"kexec_load","0x90015c":"utimensat","0x90015d":"signalfd","0x90015e":"timerfd_create","0x90015f":"eventfd","0x900160":"fallocate","0x900161":"timerfd_settime","0x900162":"timerfd_gettime","0x900163":"signalfd4","0x900164":"eventfd2","0x900165":"epoll_create1","0x900166":"dup3","0x900167":"pipe2","0x900168":"inotify_init1","0x900169":"preadv","0x90016a":"pwritev","0x90016b":"rt_tgsigqueueinfo","0x90016c":"perf_event_open","0x90016d":"recvmmsg","0x90016e":"accept4","0x90016f":"fanotify_init","0x900170":"fanotify_mark","0x900171":"prlimit64","0x900172":"name_to_handle_at","0x900173":"open_by_handle_at","0x900174":"clock_adjtime","0x900175":"syncfs","0x900176":"sendmmsg","0x900177":"setns"}
		f1 = open("/tmp/syscallARM")
		for line in f1:
			for line in f1:
				if "0x90" in line:
					syscall = extractSyscall(line)
					addr = extractAddr(line)

					print addr
					try:
						sysName = dic[syscall]
						self.r2.cmd("s "+addr)
						a = self.r2.cmd("CC "+sysName)
						print a
					except:
						pass

if __name__ == "__main__":
	binary = sys.argv[1]
	armr2 = ARM(binary)
	armr2.execute()

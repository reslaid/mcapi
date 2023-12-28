from .dllapi import DLLAPI

import os
import time
import ctypes
import ctypes.util
import codecs


class CLibCore(DLLAPI):
    def __init__(self) -> None:
        super().__init__('msvcrt' if os.name == 'nt' else 'c', local=False)


class CLibWinApi(CLibCore):
    def __init__(self, base_logger = None) -> None:
        super().__init__()
        self._logger = base_logger
        self._windll = ctypes.windll
        self._kernel32 = self._windll.kernel32

        self.m_CreateThread = self._kernel32.CreateThread
        self.m_GetLastError = self._kernel32.GetLastError
        self.m_WaitForSingleObject = self._kernel32.WaitForSingleObject

        self.INFINITE = 0xFFFFFFFF
        self.CREATE_SUSPENDED = 0x00000004

    def printf(self, text):
        _text_is_str: bool = isinstance(text, str)

        result = self.call(
            'printf', 
            text.encode(
                self._encoding
            ) if _text_is_str else text
        )

        return result

    def sprintf(self, char_buffer, format_str, *args):
        formatted_str = format_str % args
        encoded_str = formatted_str.encode()
        
        if len(encoded_str) + 1 > len(char_buffer):
            raise ValueError("Insufficient space in the character buffer")

        ctypes.memmove(char_buffer, encoded_str, len(encoded_str))
        char_buffer[len(encoded_str)] = 0

    def clearf(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def copy_to_buffer(self, dest, data):
        if not isinstance(data, bytes):
            raise TypeError("Data must be of type bytes.")

        data_length = len(data)
        dest_size = ctypes.sizeof(dest) + 0x2

        if dest is None:
            raise ValueError("Invalid destination buffer.")

        if data_length > dest_size:
            raise ValueError("Insufficient space in the destination buffer.")

        ctypes.memmove(dest, data, data_length)

    def inputf(self, format_str: str | None = None, prompt: str | None = None, split: str | None = ''):
        if format_str:
            if '%' in format_str and format_str.index('%') < len(format_str) - 0x1:
                type_specifier = format_str[format_str.index('%') + 0x1]
                if type_specifier == 's':
                    input_value = ctypes.create_string_buffer(0x100)
                else:
                    input_value = ctypes.c_int()
            else:
                input_value = ctypes.c_int()

            prompt_bytes = prompt.encode(self._encoding) if prompt else None

            if prompt_bytes:
                self.printf(prompt_bytes)

            self._lib.scanf(format_str, ctypes.byref(input_value))

            if isinstance(input_value, ctypes.c_char_p):
                return input_value.value.decode(self._encoding)
            else:
                return input_value.value
        else:
            return None

    def getch(self):
        return self._lib.getch()
    
    def getchar(self):
        return self._lib.getch()

    def malloc(self, size, buffer_type=None):
        if buffer_type is None:
            buffer_type = ctypes.c_char

        ptr = self._lib.malloc(size)

        if not ptr:
            raise MemoryError("Failed to allocate memory")

        buffer = ctypes.cast(ptr, ctypes.POINTER(buffer_type * size))
        return buffer

    def free(self, buffer):
        self._lib.free(ctypes.cast(buffer, ctypes.c_void_p))

    def time(self, t):
        return int(time.time())

    def localtime(self, t):
        return time.localtime(t)

    def asctime(self, t):
        return time.asctime(t)

    def getpid(self):
        return os.getpid()

    def getppid(self):
        return os.getppid()

    def wait(self, status):
        return os.wait(status)
    
    def gettimeofday(self, tv=None, tz=None):
        return time.time()

    def create_thread(self, start_routine, arg=None):
        thread_id = ctypes.c_ulong()
        handle = self.m_CreateThread(None, 0, start_routine, arg, self.CREATE_SUSPENDED, ctypes.byref(thread_id))

        if handle == 0:
            error_code = self.m_GetLastError()
            raise OSError(f"Failed to create thread. Error code: {error_code}")

        self._kernel32.ResumeThread(handle)
        
        self.m_WaitForSingleObject(handle, self.INFINITE)

    def getenv(self, name):
        result = self._kernel32.GetEnvironmentVariableW(name, None, 0)
        if result == 0:
            return None
        buffer_size = result + 1
        buffer = ctypes.create_unicode_buffer(buffer_size)
        self._kernel32.GetEnvironmentVariableW(name, buffer, buffer_size)
        return buffer.value

    def setenv(self, name, value, overwrite=True):
        if not overwrite and name in os.environ:
            return 0
        return self._kernel32.SetEnvironmentVariableW(name, value)

    def unsetenv(self, name):
        return self._kernel32.SetEnvironmentVariableW(name, None)

    def getuid(self):
        return os.getuid()

    def getgid(self):
        return os.getgid()

    def geteuid(self):
        return os.geteuid()

    def getegid(self):
        return os.getegid()
    
    def chdir(self, path):
        return os.chdir(path)

    def getcwd(self, buf=None, size=0x0):
        return os.getcwd()

    def mkdir(self, path, mode):
        return os.mkdir(path)

    def rmdir(self, path):
        return os.rmdir(path)

    def close(self, fd):
        return os.close(fd)

    def read(self, fd, buf, count):
        return os.read(fd, buf, count)

    def write(self, fd, buf, count):
        return os.write(fd, buf, count)

    def lseek(self, fd, offset, whence):
        return os.lseek(fd, offset, whence)

    def unlink(self, path):
        return os.unlink(path)

    def sleep(self, seconds):
        time.sleep(seconds)

    def system(self, command):
        return os.system(command)

    def getenv(self, name):
        return os.getenv(name)
    
    def sizeof(self, obj):
        return ctypes.sizeof(obj)

    def alignof(self, data_type):
        return ctypes.alignment(data_type)

    def offsetof(self, data_type, field):
        return ctypes.offsetof(data_type, field)

    def mkstemp(self, suffix="", prefix="tmp", dir=None):
        template = f"{prefix}{suffix}"
        return os.mkstemp(suffix=suffix, prefix=prefix, dir=dir)

    def execvp(self, file, args):
        command_line = f'"{file}" {" ".join(args)}'
        self._kernel32.CreateProcessW(
            None, command_line, None, None, False, 0, None, None, None, None
        )

class CLibUnix(CLibCore):
    def __init__(self, base_logger = None) -> None:
        super().__init__()
        self._logger = base_logger

    def printf(self, text):
        _text_is_str: bool = isinstance(text, str)

        result = self.call(
            'printf', 
            text.encode(
                self._encoding
            ) if _text_is_str else text
        )

        return result
    
    def formatf(format_str, *args):
        return format_str.format(*args)

    def sprintf(self, char_buffer, format_str, *args):
        formatted_str = format_str % args
        encoded_str = formatted_str.encode()
        
        if len(encoded_str) + 1 > len(char_buffer):
            raise ValueError("Insufficient space in the character buffer")

        ctypes.memmove(char_buffer, encoded_str, len(encoded_str))
        char_buffer[len(encoded_str)] = 0

    def clearf(self):
        return self.system(
            'cls' if os.name == 'nt' else 'clear'
        )
    
    def copy_to_buffer(self, dest, data):
        if not isinstance(data, bytes):
            raise TypeError("Data must be of type bytes.")

        data_length = len(data)
        dest_size = ctypes.sizeof(dest) + 0x2

        if dest is None:
            raise ValueError("Invalid destination buffer.")

        if data_length > dest_size:
            raise ValueError("Insufficient space in the destination buffer.")

        ctypes.memmove(dest, data, data_length)

    def inputf(self, format_str: str | None = None, prompt: str | None = None, split: str | None = ''):
        if format_str:
            if '%' in format_str and format_str.index('%') < len(format_str) - 0x1:
                type_specifier = format_str[format_str.index('%') + 0x1]
                if type_specifier == 's':
                    input_value = ctypes.create_string_buffer(0x100)
                else:
                    input_value = ctypes.c_int()
            else:
                input_value = ctypes.c_int()

            prompt_bytes = prompt.encode(self._encoding) if prompt else None

            if prompt_bytes:
                self.printf(prompt_bytes)

            self.scanf(format_str, ctypes.byref(input_value))

            if isinstance(input_value, ctypes.c_char_p):
                return input_value.value.decode(self._encoding)
            else:
                return input_value.value
        else:
            return None

    def getch(self):
        return self.call('getch')
    
    def getchar(self):
        return self.call('getchar')

    def malloc(self, size, buffer_type=None):
        if buffer_type is None:
            buffer_type = ctypes.c_char

        ptr = self.call('malloc', size)

        if not ptr:
            raise MemoryError("Failed to allocate memory")

        buffer = ctypes.cast(ptr, ctypes.POINTER(buffer_type * size))
        return buffer

    def free(self, buffer):
        self.call('free', ctypes.cast(buffer, ctypes.c_void_p))

    def scanf(self, format_str: str, *output_variables):
        format_bytes = format_str.encode(self._encoding)
        output_pointers = [ctypes.byref(v) if isinstance(v, ctypes._SimpleCData) else v for v in output_variables]
        return self.call('scanf', format_bytes, *output_pointers)
        
    def fopen(self, filename, mode):
        return self.call('fopen', filename, mode)
    
    def fprintf(self, file, text, end='\n'):
        return self.call('fprintf', file, text+end)
    
    def fscanf(self, file, variable):
        return self.call('fprintf', file, variable)

    def fclose(self, file_ptr):
        return self.call('fclose', file_ptr)

    def fread(self, ptr, size, count, file_ptr):
        return self.call('fread', ptr, size, count, file_ptr)

    def fwrite(self, ptr, size, count, file_ptr):
        return self.call('fwrite', ptr, size, count, file_ptr)

    def ftell(self, file_ptr):
        return self.call('ftell', file_ptr)
    
    def fseek(self, file_ptr, offset, whence):
        return self.call('fseek', file_ptr, offset, whence)

    def strlen(self, s):
        return self.call('strlen', s)

    def strcpy(self, dest, src):
        return self.call('strcpy', dest, src)

    def strcat(self, dest, src):
        return self.call('strcat', dest, src)

    def strcmp(self, s1, s2):
        return self.call('strcmp', s1, s2)
    
    def dlopen(self, filename, flags):
        return self.call('dlopen', filename, flags)

    def dlsym(self, handle, symbol):
        return self.call('dlsym', handle, symbol)

    def dlclose(self, handle):
        return self.call('dlclose', handle)

    def abs(self, x):
        return self.call('abs', x)

    def sqrt(self, x):
        return self.call('sqrt', x)

    def pow(self, x, y):
        return pow(x, y)

    def ceil(self, x):
        return self.call('ceil', x)

    def floor(self, x):
        return self.call('floor', x)

    def round(self, x):
        return self.call('round', x)
    
    def time(self, t):
        return self.call('time', t)

    def localtime(self, t):
        return self.call('localtime', t)

    def asctime(self, t):
        return self.call('asctime', t)

    def calloc(self, nmemb, size):
        return self.call('calloc', nmemb, size)

    def realloc(self, ptr, size):
        return self.call('realloc', ptr, size)
    
    def getpid(self):
        return self.call('getpid')

    def getppid(self):
        return self.call('getppid')

    def wait(self, status):
        return self.call('wait', status)
    
    def gettimeofday(self, tv=None, tz=None):
        return self.call('gettimeofday', tv, tz)

    def signal(self, signum, handler):
        return self.call('signal', signum, handler)

    def getuid(self):
        return self.call('getuid')

    def getgid(self):
        return self.call('getgid')

    def geteuid(self):
        return self.call('geteuid')

    def getegid(self):
        return self.call('getegid')

    def setuid(self, uid):
        return self.call('setuid', uid)

    def setgid(self, gid):
        return self.call('setgid', gid)

    def chdir(self, path):
        return self.call('chdir', path)

    def getcwd(self, buf=None, size=0x0):
        return self.call('getcwd', buf, size)

    def mkdir(self, path, mode):
        return self.call('mkdir', path, mode)

    def rmdir(self, path):
        return self.call('rmdir', path)

    def close(self, fd):
        return self.call('close', fd)

    def read(self, fd, buf, count):
        return self.call('read', fd, buf, count)

    def write(self, fd, buf, count):
        return self.call('write', fd, buf, count)

    def lseek(self, fd, offset, whence):
        return self.call('lseek', fd, offset, whence)

    def unlink(self, path):
        return self.call('unlink', path)

    def sleep(self, seconds):
        return self.call('sleep', seconds)

    def srand(self, seed):
        return self.call('srand', seed)

    def rand(self):
        return self.call('rand')

    def system(self, command):
        return self.call('system', command)

    def getenv(self, name):
        return self.call('getenv', name)

    def setenv(self, name, value, overwrite=True):
        return self.call('setenv', name, value, overwrite)

    def unsetenv(self, name):
        return self.call('unsetenv', name)
    
    def isalnum(self, c):
        return self.call('isalnum', c)

    def isalpha(self, c):
        return self.call('isalpha', c)

    def isdigit(self, c):
        return self.call('isdigit', c)

    def islower(self, c):
        return self.call('islower', c)

    def isupper(self, c):
        return self.call('isupper', c)

    def tolower(self, c):
        return self.call('tolower', c)

    def toupper(self, c):
        return self.call('toupper', c)

    def atof(self, s):
        return self.call('atof', s)

    def atoi(self, s):
        return self.call('atoi', s)

    def atol(self, s):
        return self.call('atol', s)
    
    def sizeof(self, obj):
        return ctypes.sizeof(obj)

    def alignof(self, data_type):
        return ctypes.alignment(data_type)

    def offsetof(self, data_type, field):
        return ctypes.offsetof(data_type, field)

    def mkstemp(self, suffix="", prefix="tmp", dir=None):
        template = f"{prefix}{suffix}"
        return self.call('mkstemp', template.encode(), dir)

    def mknod(self, pathname, mode, dev):
        return self.call('mknod', pathname.encode(), mode, dev)

    def nanosleep(self, req, rem=None):
        return self.call('nanosleep', req, rem)

    def setjmp(self, env):
        return self.call('setjmp', env)

    def longjmp(self, env, val):
        return self.call('longjmp', env, val)

    def strerror(self, errnum):
        return self.call('strerror', errnum)

    def perror(self, s):
        return self.call('perror', s)

    def clock(self):
        return self.call('clock')

    def clock_gettime(self, clk_id, tp):
        return self.call('clock_gettime', clk_id, tp)

    def clock_settime(self, clk_id, tp):
        return self.call('clock_settime', clk_id, tp)

    def clock_getres(self, clk_id, res):
        return self.call('clock_getres', clk_id, res)

    def fcntl(self, fd, cmd, arg=None):
        return self.call('fcntl', fd, cmd, arg)

    def ioctl(self, fd, request, *args):
        return self.call('ioctl', fd, request, *args)

    def pipe(self, fds):
        return self.call('pipe', fds)

    def dup(self, oldfd):
        return self.call('dup', oldfd)

    def dup2(self, oldfd, newfd):
        return self.call('dup2', oldfd, newfd)

    def link(self, oldpath, newpath):
        return self.call('link', oldpath.encode(), newpath.encode())

    def symlink(self, target, link_name):
        return self.call('symlink', target.encode(), link_name.encode())

    def readlink(self, path, buf, bufsize):
        return self.call('readlink', path.encode(), buf, bufsize)

    def chown(self, path, uid, gid):
        return self.call('chown', path.encode(), uid, gid)

    def chmod(self, path, mode):
        return self.call('chmod', path.encode(), mode)

    def utime(self, filename, times=None):
        return self.call('utime', filename.encode(), times)
    
    def exit(self, code):
        return self.call('exit', code)

    def execv(self, path, argv):
        return self.call('execv', path.encode(), argv)

    def execlp(self, file, *args):
        return self.call('execlp', file.encode(), *args)
    
    def remap_file_pages(self, start, size, prot, pgoff, flags):
        return self.call('remap_file_pages', start, size, prot, pgoff, flags)

    def memfd_create(self, name, flags):
        return self.call('memfd_create', name.encode(), flags)

    def process_vm_readv(self, pid, lvec, liovcnt, rvec, riovcnt, flags):
        return self.call('process_vm_readv', pid, lvec, liovcnt, rvec, riovcnt, flags)

    def process_vm_writev(self, pid, lvec, liovcnt, rvec, riovcnt, flags):
        return self.call('process_vm_writev', pid, lvec, liovcnt, rvec, riovcnt, flags)

    def personality(self, persona):
        return self.call('personality', persona)

    def prlimit64(self, pid, resource, new_limit, old_limit):
        return self.call('prlimit64', pid, resource, new_limit, old_limit)

    def sendfile(self, out_fd, in_fd, offset, count):
        return self.call('sendfile', out_fd, in_fd, offset, count)

    def inotify_init(self):
        return self.call('inotify_init')

    def mincore(self, start, length, vec):
        return self.call('mincore', start, length, vec)

    def epoll_create(self, size):
        return self.call('epoll_create', size)

    def epoll_ctl(self, epfd, op, fd, event):
        return self.call('epoll_ctl', epfd, op, fd, event)

    def epoll_wait(self, epfd, events, maxevents, timeout):
        return self.call('epoll_wait', epfd, events, maxevents, timeout)

    def getpagesize(self):
        return self.call('getpagesize')

    def getrlimit(self, resource, rlim):
        return self.call('getrlimit', resource, rlim)

    def setrlimit(self, resource, rlim):
        return self.call('setrlimit', resource, rlim)

    def uname(self, buf):
        return self.call('uname', buf)

    def gethostname(self, name, len):
        return self.call('gethostname', name, len)

    def getdomainname(self, name, len):
        return self.call('getdomainname', name, len)

    def setdomainname(self, name, len):
        return self.call('setdomainname', name, len)

    def sched_setaffinity(self, pid, cpusize, mask):
        return self.call('sched_setaffinity', pid, cpusize, mask)

    def sched_getaffinity(self, pid, cpusize, mask):
        return self.call('sched_getaffinity', pid, cpusize, mask)

    def gettid(self):
        return self.call('gettid')
    
    def shm_open(self, name, flags, mode):
        return self.call('shm_open', name.encode(), flags, mode)

    def shm_unlink(self, name):
        return self.call('shm_unlink', name.encode())

    def posix_fadvise(self, fd, offset, length, advice):
        return self.call('posix_fadvise', fd, offset, length, advice)

    def posix_madvise(self, addr, length, advice):
        return self.call('posix_madvise', addr, length, advice)

    def posix_memalign(self, memptr, alignment, size):
        return self.call('posix_memalign', memptr, alignment, size)

    def gethostbyname(self, name):
        return self.call('gethostbyname', name.encode())

    def gethostbyaddr(self, addr, len, type):
        return self.call('gethostbyaddr', addr, len, type)

    def getpwuid(self, uid):
        return self.call('getpwuid', uid)

    def getpwnam(self, name):
        return self.call('getpwnam', name)

    def getgrgid(self, gid):
        return self.call('getgrgid', gid)

    def getgrnam(self, name):
        return self.call('getgrnam', name)

    def setsid(self):
        return self.call('setsid')

    def getresuid(self, ruid, euid, suid):
        return self.call('getresuid', ruid, euid, suid)

    def getresgid(self, rgid, egid, sgid):
        return self.call('getresgid', rgid, egid, sgid)

    def setresuid(self, ruid, euid, suid):
        return self.call('setresuid', ruid, euid, suid)

    def setresgid(self, rgid, egid, sgid):
        return self.call('setresgid', rgid, egid, sgid)

    def daemon(self, nochdir, noclose):
        return self.call('daemon', nochdir, noclose)

    def sigaction(self, signum, act, oldact):
        return self.call('sigaction', signum, act, oldact)

    def sigprocmask(self, how, set, oldset):
        return self.call('sigprocmask', how, set, oldset)

    def sigpending(self, set):
        return self.call('sigpending', set)

    def sigsuspend(self, mask):
        return self.call('sigsuspend', mask)

    def siginterrupt(self, signum, flag):
        return self.call('siginterrupt', signum, flag)

    def sigaltstack(self, ss, old_ss):
        return self.call('sigaltstack', ss, old_ss)

    def sigqueue(self, pid, signo, value):
        return self.call('sigqueue', pid, signo, value)

    def sigtimedwait(self, set, info, timeout):
        return self.call('sigtimedwait', set, info, timeout)
    
    def clock_getcpuclockid(self, pid, clock_id):
        return self.call('clock_getcpuclockid', pid, clock_id)

    def clock_nanosleep(self, clock_id, flags, req, rem):
        return self.call('clock_nanosleep', clock_id, flags, req, rem)

    def mq_open(self, name, oflag, mode, attr):
        return self.call('mq_open', name.encode(), oflag, mode, attr)

    def mq_close(self, mqdes):
        return self.call('mq_close', mqdes)

    def mq_unlink(self, name):
        return self.call('mq_unlink', name.encode())

    def mq_send(self, mqdes, msg_ptr, msg_len, msg_prio):
        return self.call('mq_send', mqdes, msg_ptr, msg_len, msg_prio)

    def mq_receive(self, mqdes, msg_ptr, msg_len, msg_prio):
        return self.call('mq_receive', mqdes, msg_ptr, msg_len, msg_prio)

    def sched_setparam(self, pid, param):
        return self.call('sched_setparam', pid, param)

    def sched_getparam(self, pid, param):
        return self.call('sched_getparam', pid, param)

    def sched_setscheduler(self, pid, policy, param):
        return self.call('sched_setscheduler', pid, policy, param)

    def sched_getscheduler(self, pid):
        return self.call('sched_getscheduler', pid)

    def sched_yield(self):
        return self.call('sched_yield')

    def sched_get_priority_max(self, policy):
        return self.call('sched_get_priority_max', policy)

    def sched_get_priority_min(self, policy):
        return self.call('sched_get_priority_min', policy)

    def sched_rr_get_interval(self, pid, tp):
        return self.call('sched_rr_get_interval', pid, tp)

    def chroot(self, path):
        return self.call('chroot', path.encode())

    def fsync(self, fd):
        return self.call('fsync', fd)

    def fdatasync(self, fd):
        return self.call('fdatasync', fd)

    def truncate(self, path, length):
        return self.call('truncate', path.encode(), length)

    def ftruncate(self, fd, length):
        return self.call('ftruncate', fd, length)

    def sync(self):
        return self.call('sync')

    def getdents(self, fd, buf, count):
        return self.call('getdents', fd, buf, count)

    def tkill(self, tid, sig):
        return self.call('tkill', tid, sig)

    def futex(self, uaddr, op, val, timeout, uaddr2, val3):
        return self.call('futex', uaddr, op, val, timeout, uaddr2, val3)
    
    def fpathconf(self, fd, name):
        return self.call('fpathconf', fd, name)

    def pathconf(self, path, name):
        return self.call('pathconf', path.encode(), name)

    def lockf(self, fd, cmd, size):
        return self.call('lockf', fd, cmd, size)

    def flock(self, fd, operation):
        return self.call('flock', fd, operation)

    def mkfifo(self, path, mode):
        return self.call('mkfifo', path.encode(), mode)

    def statvfs(self, path, buf):
        return self.call('statvfs', path.encode(), buf)

    def fstatvfs(self, fd, buf):
        return self.call('fstatvfs', fd, buf)

    def mlock(self, addr, length):
        return self.call('mlock', addr, length)

    def munlock(self, addr, length):
        return self.call('munlock', addr, length)

    def mlockall(self, flags):
        return self.call('mlockall', flags)

    def munlockall(self):
        return self.call('munlockall')

    def posix_spawn(self, pid, path, file_actions, attr, argv, envp):
        return self.call('posix_spawn', pid, path.encode(), file_actions, attr, argv, envp)

    def putenv(self, string):
        return self.call('putenv', string.encode())
    
    def msgget(self, key, msgflg):
        return self.call('msgget', key, msgflg)

    def msgsnd(self, msqid, msgp, msgsz, msgflg):
        return self.call('msgsnd', msqid, msgp, msgsz, msgflg)

    def msgrcv(self, msqid, msgp, msgsz, msgtyp, msgflg):
        return self.call('msgrcv', msqid, msgp, msgsz, msgtyp, msgflg)

    def semget(self, key, nsems, semflg):
        return self.call('semget', key, nsems, semflg)

    def semop(self, semid, sops, nsops):
        return self.call('semop', semid, sops, nsops)

    def semctl(self, semid, semnum, cmd, arg):
        return self.call('semctl', semid, semnum, cmd, arg)

    def shmat(self, shmid, shmaddr, shmflg):
        return self.call('shmat', shmid, shmaddr, shmflg)

    def shmdt(self, shmaddr):
        return self.call('shmdt', shmaddr)

    def shmctl(self, shmid, cmd, buf):
        return self.call('shmctl', shmid, cmd, buf)

    def getrusage(self, who, usage):
        return self.call('getrusage', who, usage)

    def times(self, buf):
        return self.call('times', buf)

    def getitimer(self, which, value):
        return self.call('getitimer', which, value)

    def setitimer(self, which, value, ovalue):
        return self.call('setitimer', which, value, ovalue)

    def settimeofday(self, tv, tz):
        return self.call('settimeofday', tv, tz)

    def adjtimex(self, buf):
        return self.call('adjtimex', buf)

    def get_thread_area(self, u_info):
        return self.call('get_thread_area', u_info)

    def set_thread_area(self, u_info):
        return self.call('set_thread_area', u_info)

    def epoll_create1(self, flags):
        return self.call('epoll_create1', flags)

    def eventfd(self, initval, flags):
        return self.call('eventfd', initval, flags)

    def timerfd_create(self, clockid, flags):
        return self.call('timerfd_create', clockid, flags)

    def signalfd(self, fd, mask):
        return self.call('signalfd', fd, mask)
    
    def epoll_ctl_old(self, epfd, op, fd, event):
        return self.call('epoll_ctl_old', epfd, op, fd, event)

    def epoll_wait_old(self, epfd, events, maxevents, timeout):
        return self.call('epoll_wait_old', epfd, events, maxevents, timeout)

    def sethostname(self, name, len):
        return self.call('sethostname', name.encode(), len)

    def getdents64(self, fd, buf, count):
        return self.call('getdents64', fd, buf, count)

    def epoll_pwait(self, epfd, events, maxevents, timeout, sigmask):
        return self.call('epoll_pwait', epfd, events, maxevents, timeout, sigmask)

    def utimes(self, filename, times):
        return self.call('utimes', filename.encode(), times)

    def acct(self, filename):
        return self.call('acct', filename.encode())

    def capget(self, header, dataptr):
        return self.call('capget', header, dataptr)

    def capset(self, header, dataptr):
        return self.call('capset', header, dataptr)

    def personachoice(self, persona):
        return self.call('personachoice', persona)

    def mount(self, source, target, filesystemtype, mountflags, data):
        return self.call('mount', source.encode(), target.encode(), filesystemtype.encode(), mountflags, data)

    def umount(self, target, flags):
        return self.call('umount', target.encode(), flags)

    def pivot_root(self, new_root, put_old):
        return self.call('pivot_root', new_root.encode(), put_old.encode())

    def prctl(self, option, arg2, arg3, arg4, arg5):
        return self.call('prctl', option, arg2, arg3, arg4, arg5)

    def arch_prctl(self, code, addr):
        return self.call('arch_prctl', code, addr)

    def setns(self, fd, nstype):
        return self.call('setns', fd, nstype)

    def tgkill(self, tgid, tid, sig):
        return self.call('tgkill', tgid, tid, sig)

    def mbind(self, start, len, mode, nmask, maxnode, flags):
        return self.call('mbind', start, len, mode, nmask, maxnode, flags)

    def set_mempolicy(self, mode, nmask, maxnode):
        return self.call('set_mempolicy', mode, nmask, maxnode)

    def get_mempolicy(self, mode, nmask, maxnode, addr, flags):
        return self.call('get_mempolicy', mode, nmask, maxnode, addr, flags)

    def mq_timedsend(self, mqdes, msg_ptr, msg_len, msg_prio, abs_timeout):
        return self.call('mq_timedsend', mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)

    def mq_timedreceive(self, mqdes, msg_ptr, msg_len, msg_prio, abs_timeout):
        return self.call('mq_timedreceive', mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)

    def sched_setattr(self, pid, attr, flags):
        return self.call('sched_setattr', pid, attr, flags)

    def sched_getattr(self, pid, attr, size, flags):
        return self.call('sched_getattr', pid, attr, size, flags)

    def setxattr(self, path, name, value, size, flags):
        return self.call('setxattr', path.encode(), name.encode(), value, size, flags)

    def getxattr(self, path, name, value, size):
        return self.call('getxattr', path.encode(), name.encode(), value, size)

    def listxattr(self, path, list, size):
        return self.call('listxattr', path.encode(), list, size)

    def removexattr(self, path, name):
        return self.call('removexattr', path.encode(), name.encode())

    def flistxattr(self, fd, list, size):
        return self.call('flistxattr', fd, list, size)

    def fremovexattr(self, fd, name):
        return self.call('fremovexattr', fd, name.encode())

    def ptrace(self, request, pid, addr, data):
        return self.call('ptrace', request, pid, addr, data)

    def prlimit(self, pid, resource, new_limit, old_limit):
        return self.call('prlimit', pid, resource, new_limit, old_limit)

    def tee(self, fdin, fdout, len, flags):
        return self.call('tee', fdin, fdout, len, flags)

    def splice(self, fdin, offin, fdout, offout, len, flags):
        return self.call('splice', fdin, offin, fdout, offout, len, flags)

    def vmsplice(self, fd, iov, nr_segs, flags):
        return self.call('vmsplice', fd, iov, nr_segs, flags)

    def sync_file_range(self, fd, offset, nbytes, flags):
        return self.call('sync_file_range', fd, offset, nbytes, flags)

    def fallocate(self, fd, mode, offset, len):
        return self.call('fallocate', fd, mode, offset, len)

    def fadvise64(self, fd, offset, len, advice):
        return self.call('fadvise64', fd, offset, len, advice)
    
    def signalfd4(self, fd, mask, sizemask, flags):
        return self.call('signalfd4', fd, mask, sizemask, flags)

    def quotactl(self, cmd, special, id, addr):
        return self.call('quotactl', cmd, special.encode(), id, addr)

    def timerfd_settime(self, fd, flags, new_value, old_value):
        return self.call('timerfd_settime', fd, flags, new_value, old_value)

    def timerfd_gettime(self, fd, curr_value):
        return self.call('timerfd_gettime', fd, curr_value)

    def clock_adjtime(self, clk_id, adj):
        return self.call('clock_adjtime', clk_id, adj)

    def perf_event_open(self, attr_uptr, pid, cpu, group_fd, flags):
        return self.call('perf_event_open', attr_uptr, pid, cpu, group_fd, flags)

    def fanotify_init(self, flags, event_f_flags):
        return self.call('fanotify_init', flags, event_f_flags)

    def fanotify_mark(self, fanotify_fd, flags, mask, dfd, pathname):
        return self.call('fanotify_mark', fanotify_fd, flags, mask, dfd, pathname.encode())

    def syncfs(self, fd):
        return self.call('syncfs', fd)

    def accept4(self, sockfd, addr, addrlen, flags):
        return self.call('accept4', sockfd, addr, addrlen, flags)

    def recvmmsg(self, sockfd, msgvec, vlen, flags, timeout):
        return self.call('recvmmsg', sockfd, msgvec, vlen, flags, timeout)

    def name_to_handle_at(self, dfd, name, handle, mnt_id, flags):
        return self.call('name_to_handle_at', dfd, name.encode(), handle, mnt_id, flags)

    def open_by_handle_at(self, mountdirfd, handle, flags):
        return self.call('open_by_handle_at', mountdirfd, handle, flags)

    def eventfd2(self, initval, flags):
        return self.call('eventfd2', initval, flags)

    def userfaultfd(self, flags):
        return self.call('userfaultfd', flags)

    def seccomp(self, op, flags, arg):
        return self.call('seccomp', op, flags, arg)

    def bpf(self, cmd, attr, size):
        return self.call('bpf', cmd, attr, size)

    def execve(self, filename, argv, envp):
        return self.call('execve', filename.encode(), argv, envp)

    def fork(self):
        return self.call('fork')

    def vfork(self):
        return self.call('vfork')

    def clone(self, fn, child_stack, flags, args):
        return self.call('clone', fn, child_stack, flags, args)

    def unshare(self, flags):
        return self.call('unshare', flags)

    def execvp(self, file, args):
        return self.call('execvp', file.encode(), args)

    def execvpe(self, file, args, env):
        return self.call('execvpe', file.encode(), args, env)

    def execl(self, path, args):
        return self.call('execl', path.encode(), *args)

    def execlpe(self, file, args, env):
        return self.call('execlpe', file.encode(), *args, env)

    def waitpid(self, pid, status, options):
        return self.call('waitpid', pid, status, options)

    def wait3(self, status, options, rusage):
        return self.call('wait3', status, options, rusage)

    def wait4(self, pid, status, options, rusage):
        return self.call('wait4', pid, status, options, rusage)
    
    def kcmp(self, pid1, pid2, type, idx1, idx2):
        return self.call('kcmp', pid1, pid2, type, idx1, idx2)

    def getgroups(self, size, list):
        return self.call('getgroups', size, list)

    def setgroups(self, size, list):
        return self.call('setgroups', size, list)

    def init_module(self, module_image, len, param_values):
        return self.call('init_module', module_image, len, param_values)

    def delete_module(self, name, flags):
        return self.call('delete_module', name.encode(), flags)

    def finit_module(self, fd, params, flags):
        return self.call('finit_module', fd, params, flags)

    def query_module(self, name, which, buf, size):
        return self.call('query_module', name.encode(), which, buf, size)

    def nfsservctl(self, cmd, argp, resp):
        return self.call('nfsservctl', cmd, argp, resp)

    def pthread_create(self, thread, attr, start_routine, arg):
        result = self.call('pthread_create', thread, attr, start_routine, arg)

    def pthread_join(self, thread, value_ptr):
        result = self.call('pthread_join', thread, value_ptr)

    def pthread_detach(self, thread):
        result = self.call('pthread_detach', thread)

    def pthread_mutex_init(self, mutex, attr):
        return self.call('pthread_mutex_init', mutex, attr)

    def pthread_mutex_destroy(self, mutex):
        return self.call('pthread_mutex_destroy', mutex)

    def pthread_mutex_lock(self, mutex):
        return self.call('pthread_mutex_lock', mutex)

    def pthread_mutex_trylock(self, mutex):
        return self.call('pthread_mutex_trylock', mutex)

    def pthread_mutex_unlock(self, mutex):
        return self.call('pthread_mutex_unlock', mutex)

    def pthread_cond_init(self, cond, attr):
        return self.call('pthread_cond_init', cond, attr)

    def pthread_cond_destroy(self, cond):
        return self.call('pthread_cond_destroy', cond)

    def pthread_cond_signal(self, cond):
        return self.call('pthread_cond_signal', cond)

    def pthread_cond_broadcast(self, cond):
        return self.call('pthread_cond_broadcast', cond)

    def pthread_cond_wait(self, cond, mutex):
        return self.call('pthread_cond_wait', cond, mutex)

    def pthread_key_create(self, key, destructor):
        return self.call('pthread_key_create', key, destructor)

    def pthread_key_delete(self, key):
        return self.call('pthread_key_delete', key)

    def pthread_setspecific(self, key, value):
        return self.call('pthread_setspecific', key, value)

    def pthread_getspecific(self, key):
        return self.call('pthread_getspecific', key)
    
    def read_process_memory(self, pid, address, size):
        buffer = ctypes.create_string_buffer(size)
        read_size = self.process_vm_readv(pid, buffer, 0x1, address, 0x1, 0x0)
        if read_size == size:
            return buffer.raw
        else:
            raise MemoryError("Failed to read process memory")

    def write_process_memory(self, pid, address, data):
        buffer = ctypes.create_string_buffer(data)
        write_size = self.process_vm_writev(pid, buffer, 0x1, address, 0x1, 0x0)
        if write_size == len(data):
            return True
        else:
            raise MemoryError("Failed to write process memory")
    
    def create_thread(self, start_routine, arg=None):
        pthread_create = self._libc.pthread_create
        pthread_create.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

        pthread_join = self._libc.pthread_join
        pthread_join.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
        
        start_routine_c = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(start_routine)

        thread_id = ctypes.c_ulong()
        handle = pthread_create(ctypes.byref(thread_id), None, start_routine_c, arg)

        if handle != 0:
            error_code = ctypes.get_errno()
            raise OSError(f"Failed to create thread. Error code: {error_code}")

        pthread_join(thread_id, None)

    def join_thread(self, thread):
        value_ptr = ctypes.pointer(ctypes.c_void_p())
        self.pthread_join(thread, value_ptr)
        return value_ptr.contents.value
    
    def calculate_file_checksum(self, filename):
        file_ptr = self.fopen(filename, 'rb')
        if file_ptr is not None:
            try:
                checksum = 0x0
                buffer_size = 0x1000
                buffer = ctypes.create_string_buffer(buffer_size)
                while True:
                    read_size = self.fread(buffer, 0x1, buffer_size, file_ptr)
                    if read_size == 0x0:
                        break
                    for i in range(read_size):
                        checksum += ctypes.c_uint8(buffer[i]).value
                return checksum
            finally:
                self.fclose(file_ptr)
        else:
            raise IOError(f"Failed to open file: {filename}")

    def create_and_write_binary_file(self, filename, data):
        file_ptr = self.fopen(filename, 'wb')
        if file_ptr is not None:
            try:
                buffer = ctypes.create_string_buffer(data)
                self.fwrite(buffer, 0x1, len(data), file_ptr)
            finally:
                self.fclose(file_ptr)
        else:
            raise IOError(f"Failed to create file: {filename}")

    def get_environment_variables(self):
        env_ptr = self.call('environ')
        result = {}
        if env_ptr is not None:
            i = 0x0
            while env_ptr[i] is not None:
                env_str = ctypes.string_at(env_ptr[i]).decode(self._encoding)
                key, value = env_str.split('=', 0x1)
                result[key] = value
                i += 0x1
        return result

    def reverse_string(self, input_string):
        reversed_str = ctypes.create_string_buffer(len(input_string) + 0x1)
        self.strcpy(reversed_str, input_string[::-0x1].encode(self._encoding))
        return reversed_str.value.decode(self._encoding)
    
    def concat_strings(self, str1, str2):
        result_str = ctypes.create_string_buffer(len(str1) + len(str2) + 0x1)
        self.strcpy(result_str, str1.encode(self._encoding))
        self.strcat(result_str, str2.encode(self._encoding))
        return result_str.value.decode(self._encoding)

    def matrix_multiply(self, matrix1, matrix2):
        rows1, cols1 = len(matrix1), len(matrix1[0x0])
        cols2 = len(matrix2[0x0])

        result_matrix = [[0x0 for _ in range(cols2)] for _ in range(rows1)]

        for i in range(rows1):
            for j in range(cols2):
                for k in range(cols1):
                    result_matrix[i][j] += matrix1[i][k] * matrix2[k][j]

        return result_matrix

    def custom_sort(self, array):
        array_type = ctypes.c_int * len(array)
        sorted_array = array_type()
        for i, value in enumerate(sorted(array)):
            sorted_array[i] = value

        self.qsort(sorted_array, len(array), ctypes.sizeof(ctypes.c_int), self.compare_int)

        return list(sorted_array)
    
    def get_current_time(self):
        time_struct = self.localtime(self.time(None))
        return self.asctime(time_struct).decode(self._encoding).strip()

    def get_square_root_and_power(self, x, y):
        sqrt_result = self.sqrt(x)
        power_result = self.pow(x, y)
        return sqrt_result, power_result
    
    def reverse_array(self, array):
        n = len(array)
        for i in range(n // 0x2):
            self.swap(array, i, n - i - 0x1)
        return array

    def swap(self, array, i, j):
        temp = array[i]
        array[i] = array[j]
        array[j] = temp

    def generate_fibonacci_sequence(self, n):
        fibonacci_sequence = [0x0, 0x1]
        for i in range(0x2, n):
            next_value = self.abs(self.add(fibonacci_sequence[i - 0x1], fibonacci_sequence[i - 0x2]))
            fibonacci_sequence.append(next_value)
        return fibonacci_sequence

    def add(self, a, b):
        return self.call('add', a, b)

    def subtract(self, a, b):
        return self.call('subtract', a, b)

    def multiply(self, a, b):
        return self.call('multiply', a, b)

    def divide(self, a, b):
        if b != 0x0:
            return self.call('divide', a, b)
        else:
            raise ValueError("Cannot divide by zero")

    def calculate_average(self, numbers):
        n = len(numbers)
        if n > 0x0:
            total = sum(numbers)
            return self.divide(total, n)
        else:
            raise ValueError("List is empty, cannot calculate average")
        
    def compare_int(self, a, b):
        return self.subtract(a, b)

    def find_max_element(self, array):
        max_element = array[0x0]
        for element in array[0x1:]:
            if self.compare_int(element, max_element) > 0x0:
                max_element = element
        return max_element

    def count_occurrences(self, array, target):
        count = 0x0
        for element in array:
            if self.compare_int(element, target) == 0x0:
                count += 0x1
        return count

    def custom_search(self, array, target):
        for i, element in enumerate(array):
            if self.compare_int(element, target) == 0x0:
                return i
        return -0x1

    def reverse_words(self, sentence):
        words = sentence.split()
        reversed_sentence = ' '.join(reversed(words))
        return reversed_sentence

    def compute_factorial(self, n):
        if n == 0x0:
            return 0x1
        else:
            result = 0x1
            for i in range(0x1, n + 0x1):
                result = self.multiply(result, i)
            return result

    def is_prime(self, num):
        if num < 0x2:
            return False
        for i in range(0x2, self.sqrt(num) + 0x1):
            if self.divide(num, i) == 0x0:
                return False
        return True
    
    def perform_matrix_operations(self, matrix1, matrix2):
        rows1, cols1 = len(matrix1), len(matrix1[0x0])
        rows2, cols2 = len(matrix2), len(matrix2[0x0])

        transposed_matrix1 = [[0x0 for _ in range(rows1)] for _ in range(cols1)]
        for i in range(rows1):
            for j in range(cols1):
                transposed_matrix1[j][i] = matrix1[i][j]

        result_matrix = [[0x0 for _ in range(cols2)] for _ in range(cols1)]
        for i in range(cols1):
            for j in range(cols2):
                for k in range(rows2):
                    result_matrix[i][j] += transposed_matrix1[i][k] * matrix2[k][j]

        return result_matrix
    
    def perform_advanced_math_operations(self, x, y, z):
        result1 = self.pow(self.add(x, y), self.subtract(z, x))
        result2 = self.sqrt(self.multiply(x, y))
        result3 = self.floor(self.divide(x, z))

        return result1, result2, result3

    def calculate_checksum(self, data):
        checksum = 0x0
        for byte in data:
            checksum = self.add(checksum, ctypes.c_uint8(byte).value)
        return checksum

    def manipulate_string_arrays(self, strings):
        reversed_strings = [self.reverse_string(s) for s in strings]
        concatenated_string = ' '.join(strings)
        uppercased_strings = [self.toupper(s) for s in strings]

        return reversed_strings, concatenated_string, uppercased_strings

    def perform_file_operations(self, input_filename, output_filename):
        input_data = self.open_and_read_file(input_filename, 'rb')
        reversed_data = self.reverse_string(input_data.decode(self._encoding)).encode(self._encoding)
        self.write_string_to_file(output_filename, 'wb', reversed_data)
        return len(input_data), len(reversed_data)
    
    def perform_advanced_array_operations(self, array1, array2):
        sum_array = [self.add(x, y) for x, y in zip(array1, array2)]
        product_array = [self.multiply(x, y) for x, y in zip(array1, array2)]
        unique_elements = set(array1) | set(array2)
        unique_sorted_array = sorted(list(unique_elements))

        return sum_array, product_array, unique_sorted_array

    def manipulate_linked_list(self, linked_list):
        reversed_list = self.reverse_linked_list(linked_list)
        list_length = self.get_linked_list_length(linked_list)

        return reversed_list, list_length

    def reverse_linked_list(self, head):
        prev = None
        current = head
        while current is not None:
            next_node = current.next
            current.next = prev
            prev = current
            current = next_node
        return prev

    def perform_custom_sort(self, data):
        sorted_data = sorted(data, key=lambda x: self.custom_sort_key(x))
        return sorted_data

    def custom_sort_key(self, item):
        return self.abs(self.subtract(item, 10))

    def perform_network_operation(self, url):
        response_code = self.simulate_network_request(url)
        return response_code

    def perform_data_conversion(self, binary_data):
        hex_representation = self.convert_binary_to_hex(binary_data)
        decimal_representation = self.convert_hex_to_decimal(hex_representation)
        binary_representation = self.convert_decimal_to_binary(decimal_representation)

        return hex_representation, decimal_representation, binary_representation

    def convert_binary_to_hex(self, binary_data):
        hex_buffer_size = len(binary_data) * 0x2 + 0x1
        hex_representation = ctypes.create_string_buffer(hex_buffer_size)
        self.call('binary_to_hex', binary_data, hex_representation, len(binary_data))
        return hex_representation.value.decode(self._encoding)

    def convert_hex_to_decimal(self, hex_data):
        return int(hex_data, 16)

    def convert_decimal_to_binary(self, decimal_value):
        binary_buffer_size = 32
        binary_representation = ctypes.create_string_buffer(binary_buffer_size)
        self.call('decimal_to_binary', decimal_value, binary_representation)
        return binary_representation.value.decode(self._encoding)

    def perform_complex_computation(self, real_part, imag_part):
        conjugate = self.compute_complex_conjugate(real_part, imag_part)
        magnitude = self.compute_complex_magnitude(real_part, imag_part)
        polar_coordinates = self.convert_to_polar_coordinates(real_part, imag_part)

        return conjugate, magnitude, polar_coordinates

    def compute_complex_conjugate(self, real_part, imag_part):
        conjugate_real = real_part
        conjugate_imag = self.negate(imag_part)
        return conjugate_real, conjugate_imag

    def compute_complex_magnitude(self, real_part, imag_part):
        return self.sqrt(self.add(self.square(real_part), self.square(imag_part)))

    def convert_to_polar_coordinates(self, real_part, imag_part):
        magnitude = self.compute_complex_magnitude(real_part, imag_part)
        angle = self.atan2(imag_part, real_part)
        return magnitude, angle
    
    def allocate_and_initialize_array(self, size, initial_value):
        array_ptr = self.calloc(size, ctypes.sizeof(ctypes.c_int))
        for i in range(size):
            self.set_int_array_element(array_ptr, i, initial_value)
        return array_ptr


class CLibCrypt():
    def __init__(self) -> None:
        self._clib = CLibUnix()   
    
    def caesar_encrypt(self, plaintext, shift):
        encrypted_text = ''.join(
            chr(
                (ord(char) + shift - 0x41) % 0x1A + 0x41
            ) if char.isalpha() else char for char in plaintext.upper()
        )
        return encrypted_text

    def vigenere_encrypt(self, plaintext, key):
        key = key.upper()
        key_len = len(key)
        encrypted_text = ''.join(
            chr(
                (ord(plaintext[i]) + ord(key[i % key_len]) - 0x2 * 0x41) % 0x1A + 0x41
            ) if plaintext[i].isalpha() else plaintext[i] for i in range(len(plaintext))
        )
        return encrypted_text
    
    def caesar_decrypt(self, ciphertext, shift):
        decrypted_text = ''.join(
            chr(
                (ord(char) - shift - 0x41) % 0x1A + 0x41
            ) if char.isalpha() else char for char in ciphertext.upper()
        )
        return decrypted_text

    def vigenere_decrypt(self, ciphertext, key):
        key = key.upper()
        key_len = len(key)
        decrypted_text = ''.join(
            chr(
                (ord(ciphertext[i]) - ord(key[i % key_len]) + 0x1A) % 0x1A + 0x41
            ) if ciphertext[i].isalpha() else ciphertext[i] for i in range(len(ciphertext))
        )
        return decrypted_text
    
    def xor_crypt(self, plaintext, key):
        encrypted_text = ''.join(
            chr(
                ord(char) ^ ord(key[i % len(key)])
            ) for i, char in enumerate(plaintext)
        )
        return encrypted_text
    
    def xor_crypt_bytes(self, data, key):
        encrypted_data = bytearray(len(data))
        key_length = len(key)

        for i in range(len(data)):
            encrypted_data[i] = data[i] ^ key[i % key_length]

        return bytes(encrypted_data)

    def array_encode(self, data):
        array_size = len(data)
        result_array = (ctypes.c_int * array_size)()

        for i, char in enumerate(data):
            char_code = ord(char)
            result_array[i] = (i << 0x8) | char_code

        return result_array

    def array_decode(self, array):
        decoded_data = []
        array_size = len(array)

        for i in range(array_size):
            char_index = i >> 0x8
            char_code = array[i] & 0xFF
            decoded_data.append(chr(char_code + char_index))

        return ''.join(decoded_data)

    def rot13_encrypt(self, plaintext):
        return codecs.encode(plaintext, 'rot_13')

    def rot13_decrypt(self, ciphertext):
        return self.rot13_encrypt(ciphertext)
    
    def polybius_encrypt(self, text):
        encrypted_text = ''
        for char in text:
            if char.isalpha():
                row = (ord(char.upper()) - ord('A')) // 0x5 + 0x1
                col = (ord(char.upper()) - ord('A')) % 0x5 + 0x1
                encrypted_text += f"{row}{col} "
            else:
                encrypted_text += char
        return encrypted_text.strip()
    
    def polybius_decrypt(self, encrypted_text):
        decrypted_text = ''
        pairs = encrypted_text.split()
        for pair in pairs:
            row, col = map(int, pair)
            decrypted_text += chr((row - 0x1) * 0x5 + col - 0x1 + ord('A'))
        return decrypted_text
    
    def vertical_encrypt(self, text, num_rows, direction: int = 0x1):
        rows = ['' for _ in range(num_rows)]
        index = 0x0

        for char in text:
            rows[index] += char
            index += direction

            if index == num_rows - 0x1 or index == 0x0:
                direction *= -0x1

        encrypted_text = ''.join(rows)
        return encrypted_text

    def vertical_decrypt(self, encrypted_text, num_rows, direction: int = 0x1):
        rows = ['' for _ in range(num_rows)]
        index = 0x0

        for char in encrypted_text:
            rows[index] += char
            index += direction

            if index == num_rows - 0x1 or index == 0x0:
                direction *= -0x1

        decrypted_text = ''.join(rows)
        return decrypted_text

    def transposition_encrypt(self, text, key):
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        encrypted_text = ''.join(text[i] for i in key_order)
        return encrypted_text

    def transposition_decrypt(self, encrypted_text, key):
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        decrypted_text = ''.join(encrypted_text[i] for i in key_order)
        return decrypted_text

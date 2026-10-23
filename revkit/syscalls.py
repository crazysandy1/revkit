"""Linux system-call tables (number -> (name, argument count)) for annotation and decompilation."""
from __future__ import annotations

from typing import Optional, Tuple

X86_64 = {
    0: ("read", 3), 1: ("write", 3), 2: ("open", 3), 3: ("close", 1), 4: ("stat", 2), 5: ("fstat", 2), 6: ("lstat", 2),
    7: ("poll", 3), 8: ("lseek", 3), 9: ("mmap", 6), 10: ("mprotect", 3), 11: ("munmap", 2), 12: ("brk", 1),
    13: ("rt_sigaction", 4), 14: ("rt_sigprocmask", 4), 16: ("ioctl", 3), 17: ("pread64", 4), 18: ("pwrite64", 4),
    20: ("writev", 3), 21: ("access", 2), 22: ("pipe", 1), 23: ("select", 5), 32: ("dup", 1), 33: ("dup2", 2),
    35: ("nanosleep", 2), 39: ("getpid", 0), 41: ("socket", 3), 42: ("connect", 3), 43: ("accept", 3),
    44: ("sendto", 6), 45: ("recvfrom", 6), 48: ("shutdown", 2), 49: ("bind", 3), 50: ("listen", 2),
    54: ("setsockopt", 5), 56: ("clone", 5), 57: ("fork", 0), 58: ("vfork", 0), 59: ("execve", 3), 60: ("exit", 1),
    61: ("wait4", 4), 62: ("kill", 2), 63: ("uname", 1), 72: ("fcntl", 3), 78: ("getdents", 3), 79: ("getcwd", 2),
    80: ("chdir", 1), 82: ("rename", 2), 83: ("mkdir", 2), 84: ("rmdir", 1), 87: ("unlink", 1), 89: ("readlink", 3),
    90: ("chmod", 2), 101: ("ptrace", 4), 102: ("getuid", 0), 157: ("prctl", 5), 202: ("futex", 6),
    217: ("getdents64", 3), 228: ("clock_gettime", 2), 231: ("exit_group", 1), 257: ("openat", 4), 262: ("newfstatat", 4),
    318: ("getrandom", 3),
}
X86_32 = {
    1: ("exit", 1), 2: ("fork", 0), 3: ("read", 3), 4: ("write", 3), 5: ("open", 3), 6: ("close", 1), 11: ("execve", 3),
    20: ("getpid", 0), 33: ("access", 2), 37: ("kill", 2), 45: ("brk", 1), 54: ("ioctl", 3), 90: ("mmap", 6),
    91: ("munmap", 2), 102: ("socketcall", 2), 125: ("mprotect", 3), 162: ("nanosleep", 2), 192: ("mmap2", 6),
    252: ("exit_group", 1), 295: ("openat", 4),
}


def lookup(num: int, bits: int = 64) -> Optional[Tuple[str, int]]:
    return (X86_64 if bits == 64 else X86_32).get(num)

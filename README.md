# Linux Syscalls & ptrace — C/C++ Tutorial for Post-Exploitation Research

**Author:** c0d3Ninja  
**Audience:** Intermediate C++ developers learning Linux internals for **authorized** red-team / malware analysis / kernel security labs  
**Platform:** Linux (x86_64 and aarch64 notes where relevant)

> **Legal & ethics:** Use only on systems you own or have **explicit written permission** to test. ptrace and raw syscalls are dual-use: debugging, security research, and abuse. Unauthorized use on third-party systems is illegal.

---

## Table of Contents

1. [Why This Matters for Post-Exploitation](#1-why-this-matters-for-post-exploitation)
2. [User Mode vs Kernel Mode](#2-user-mode-vs-kernel-mode)
3. [What Is a System Call?](#3-what-is-a-system-call)
4. [Invoking Syscalls from C/C++](#4-invoking-syscalls-from-cc)
5. [Learning Syscalls with strace](#5-learning-syscalls-with-strace)
6. [Syscalls You Will Use Constantly](#6-syscalls-you-will-use-constantly)
7. [ptrace — The Big Picture](#7-ptrace--the-big-picture)
8. [ptrace API Reference (Practical)](#8-ptrace-api-reference-practical)
9. [Classic Patterns: Trace Me, Attach, Inject](#9-classic-patterns-trace-me-attach-inject)
10. [Beyond ptrace: process_vm_* and pidfd_*](#10-beyond-ptrace-process_vm_-and-pidfd_)
11. [Yama, Capabilities & Hardening](#11-yama-capabilities--hardening)
12. [ptrace in Real Vulnerabilities (CVE-2026-46333)](#12-ptrace-in-real-vulnerabilities-cve-2026-46333)
13. [Detection & Blue-Team Angles](#13-detection--blue-team-angles)
14. [Hands-On Labs (Authorized VM Only)](#14-hands-on-labs-authorized-vm-only)
15. [Study Roadmap](#15-study-roadmap)
16. [References](#16-references)

---

## 1. Why This Matters for Post-Exploitation

After initial access, operators live in **userland** but need kernel-adjacent power:

| Goal | Often involves |
|------|----------------|
| Read another process’s memory | `ptrace`, `process_vm_readv` |
| Inject code / hijack execution | `ptrace` + register control |
| Hide from simple tools | `prctl`, `memfd_create`, syscall-only paths |
| Understand EDR behavior | Which syscalls are hooked/monitored |
| Exploit kernel bugs | Syscall surfaces (`pidfd_getfd`, `ptrace` permission checks) |

**Syscalls** are the boundary. **ptrace** is one of the oldest and most powerful **cross-process** interfaces on Linux — and one of the most audited in modern kernel security research.

---

## 2. User Mode vs Kernel Mode

```
+------------------+       syscall        +------------------+
|  Your process    |  ----------------->  |  Linux kernel    |
|  (ring 3)        |  <-----------------  |  (ring 0)        |
|  libc, C++ code  |       return         |  VFS, sched, mm  |
+------------------+                      +------------------+
```

- Your C++ code runs in **user mode**.
- It cannot read physical memory, modify page tables, or attach to arbitrary processes **unless the kernel allows it** via a syscall + permission checks (UID, capabilities, LSM, namespaces).

Every `open()`, `read()`, `mmap()`, `ptrace()` eventually becomes a **syscall**.

---

## 3. What Is a System Call?

A **system call** is a controlled entry into the kernel identified by a **number** and arguments (registers or memory).

### libc wrappers (what you usually call)

```cpp
#include <unistd.h>
write(1, "hi\n", 3);   // libc wraps syscall(__NR_write, ...)
```

### Direct syscall (bypass libc for research)

```cpp
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

long n = syscall(SYS_write, 1, "hi\n", 3);
```

**Why bypass libc in research?**

- libc may not expose a wrapper (new syscalls)
- libc hooks / IFUNC / sanitizers change behavior
- malware and some implants avoid libc for OPSEC
- you need exact control for exploit dev

### Where syscall numbers live

```bash
# x86_64
grep __NR_write /usr/include/asm/unistd_64.h

# aarch64
grep __NR_write /usr/include/asm-generic/unistd.h
```

Numbers differ by **architecture** — never hardcode from an x86_64 blog when building on ARM.

### x86_64 calling convention (intuition)

Syscall number in `rax`, arguments in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`, then `syscall` instruction.

### aarch64 calling convention (intuition)

Number in `x8`, arguments in `x0`–`x5`, then `svc #0`.

You rarely write asm in C++ tools — use `syscall()` from `<sys/syscall.h>`.

---

## 4. Invoking Syscalls from C/C++

### Pattern 1: `syscall()` macro (recommended for learning)

```cpp
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/memfd.h>
#include <fcntl.h>
#include <cstdio>

int main() {
    int fd = static_cast<int>(syscall(SYS_memfd_create, "anon", MFD_CLOEXEC));
    if (fd < 0) {
        perror("memfd_create");
        return 1;
    }
    std::printf("memfd fd = %d\n", fd);
    return 0;
}
```

Compile:

```bash
g++ -std=c++20 -D_GNU_SOURCE memfd_demo.cpp -o memfd_demo
```

### Pattern 2: libc functions (production default)

Prefer `open`, `read`, `mmap` when portability and errno handling matter. Your ShadowHarvester code already uses this style (`memfd_create()` wrapper in `memfd_hiding.cpp`).

### Pattern 3: read the kernel’s idea of your syscalls

```bash
man 2 syscalls
man 2 syscall
```

### Error handling

Syscalls return `-1` (or negative cast) and set **`errno`**:

```cpp
#include <cerrno>
#include <cstring>

if (syscall(SYS_ptrace, ...) == -1) {
    std::fprintf(stderr, "ptrace failed: %s\n", std::strerror(errno));
}
```

Common ptrace errno values:

| errno | Meaning |
|-------|---------|
| `EPERM` | Yama / capabilities / policy denied |
| `ESRCH` | Target PID does not exist |
| `EBUSY` | Already traced |

---

## 5. Learning Syscalls with strace

**strace** is your syscall textbook in motion.

```bash
strace -f -e trace=ptrace,process_vm_readv,openat,execve ./your_tool
strace -p <pid>                    # attach to running process (needs permission)
strace -e trace=file cat /etc/passwd
```

### Exercise

Run:

```bash
strace -f ls /tmp 2>&1 | head -30
```

Identify: `openat`, `getdents64`, `write`, `close`.

### Exercise: follow a debugger

Terminal A:

```bash
gdb -q ./hello
```

Terminal B:

```bash
sudo strace -f -e trace=ptrace gdb -q ./hello 2>&1 | head -40
```

You will see `ptrace(PTRACE_SEIZE/ATTACH/...)` — connects theory to real tools.

---

## 6. Syscalls You Will Use Constantly

| Syscall / family | Purpose in post-ex |
|------------------|-------------------|
| `read` / `write` | Pipes, files, `/proc` |
| `openat` | Paths, `/proc/<pid>/mem` (restricted) |
| `mmap` / `mprotect` | RWX shells, reflective loading |
| `memfd_create` + `execveat` | Fileless execution (`memfd_hiding`) |
| `clone` / `fork` / `execve` | Spawning, injection setup |
| `prctl` | Name hiding, dumpable, seccomp |
| `ptrace` | Debug/inject/introspect |
| `process_vm_readv` / `writev` | Cross-process memory I/O |
| `pidfd_open` / `pidfd_getfd` | Modern FD duplication from another process |
| `kill` / `tgkill` | Signals |

### Reading `/proc` is not a syscall by name

`fopen("/proc/self/maps")` → libc → `openat`. Learn to map **API → syscall** mentally.

---

## 7. ptrace — The Big Picture

`ptrace()` lets one process **observe and control** another: stop/resume, read/write memory, read/write registers, intercept signals.

Originally for **debuggers** (gdb, strace, lldb).

### Permission model (simplified)

```
Can I ptrace target T?
  ├─ Am I root / CAP_SYS_PTRACE?
  ├─ Yama ptrace_scope rules?
  ├─ Same user / parent-child relationship?
  ├─ Namespaces (PID, user)?
  └─ LSM (AppArmor, SELinux)?
```

### Core mental model

1. **Tracer** attaches to **tracee**
2. Tracee receives signal-like stops (`SIGTRAP`, `SIGSTOP`)
3. Tracer inspects state while stopped
4. Tracer mutates memory/regs if allowed
5. Tracer detaches or continues

```
Tracer (your code / gdb)
   | PTRACE_ATTACH / SEIZE
   v
Tracee (victim process)  -- stops on events
   | PTRACE_CONT / SYSCALL
   v
runs until next stop
```

---

## 8. ptrace API Reference (Practical)

```cpp
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <cstdio>
```

### Signature

```c
long ptrace(enum __ptrace_request request, pid_t pid,
            void *addr, void *data);
```

| Arg | Role |
|-----|------|
| `request` | Operation (`PTRACE_*`) |
| `pid` | Tracee TID/PID |
| `addr` | Address / request-specific |
| `data` | Payload / request-specific |

### Requests you must know

| Request | What it does |
|---------|----------------|
| `PTRACE_TRACEME` | Tracee asks parent to trace it (classic anti-debug check too) |
| `PTRACE_ATTACH` | Tracer attaches to running process (sends `SIGSTOP`) |
| `PTRACE_SEIZE` | Attach without immediate signal (modern gdb) |
| `PTRACE_DETACH` | Release tracee |
| `PTRACE_CONT` | Continue execution |
| `PTRACE_SYSCALL` | Stop at next syscall entry/exit |
| `PTRACE_PEEKDATA` | Read word of tracee memory |
| `PTRACE_POKEDATA` | Write word of tracee memory |
| `PTRACE_GETREGS` | Read CPU registers (`user_regs_struct`) |
| `PTRACE_SETREGS` | Write CPU registers |
| `PTRACE_GETREGSET` / `SETREGSET` | Modern reg/ioctl-style blocks |

Architecture-specific headers:

```cpp
#include <sys/user.h>   // user_regs_struct on x86_64
```

On **aarch64**, register layout differs — always use arch-specific structs.

### peek/poke caveat

`PTRACE_PEEKDATA` reads a **machine word** (8 bytes on x86_64). Strings need a loop.

---

## 9. Classic Patterns: Trace Me, Attach, Inject

### Pattern A: `PTRACE_TRACEME` (debugger detection)

Used by malware **and** debuggers:

```cpp
#include <sys/ptrace.h>
#include <cstdio>

bool debuggerPresent() {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
        return true;   // already traced
    return false;
}
```

**Bypass / nuance:** Parent can trace legitimately; kernel patches exist; not reliable alone.

---

### Pattern B: Parent traces child (minimal tracer)

```cpp
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdio>

int main() {
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        raise(SIGTRAP);   // stop so parent can inspect
        _exit(0);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status))
        std::printf("Child stopped with signal %d\n", WSTOPSIG(status));

    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    waitpid(pid, &status, 0);
    return 0;
}
```

**Study points:**

- `fork` → child calls `TRACEME`
- parent `waitpid` synchronizes on stop
- `PTRACE_CONT` resumes

This is the skeleton of **every** debugger.

---

### Pattern C: Attach to existing PID

```cpp
pid_t target = /* from argv */;
if (ptrace(PTRACE_ATTACH, target, nullptr, nullptr) == -1) {
    perror("PTRACE_ATTACH");
    return 1;
}

int status = 0;
waitpid(target, &status, 0);

// ... peek regs/mem ...

ptrace(PTRACE_DETACH, target, nullptr, nullptr);
```

Requires permission under Yama (see §11).

---

### Pattern D: Syscall tracing (conceptual)

```cpp
ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
// tracee runs until syscall entry
// analyze, single-step, modify — gdb does this at scale
```

Use **gdb** first to learn behavior, then replicate small pieces in C++.

---

### Pattern E: Injection (high-level only)

Real injection chains combine:

1. Attach + stop tracee
2. `mmap` in tracee (via `ptrace` calling injected shellcode or `process_vm_writev`)
3. Adjust instruction pointer (`RIP` / `PC`)
4. Continue or detach

**Do not cargo-cult shellcode injectors** until you understand registers, calling convention, and ASLR.

For training, use **gdb scripts** before writing your own injector.

---

## 10. Beyond ptrace: process_vm_* and pidfd_*

Modern Linux adds APIs that overlap ptrace use cases.

### `process_vm_readv` / `process_vm_writev`

Read/write another process’s memory **without classic ptrace attach** (still restricted):

```cpp
#include <sys/uio.h>
#include <unistd.h>

// man 2 process_vm_readv
```

Good for: dumpers, scanners.  
Blocked by: permissions, namespaces, some hardened profiles.

### `pidfd_open` + `pidfd_getfd` (Linux 5.6+)

Get a **file descriptor** representing a process, then duplicate FDs from it:

```cpp
// pidfd_open(pid, flags)
// pidfd_getfd(pidfd, target_fd, flags)
```

This is central to **CVE-2026-46333** research: permission checks intersect `ptrace` logic and process exit races.

**Lesson:** Post-exploitation research in 2025+ must include **pidfd** syscalls, not only classical ptrace.

---

## 11. Yama, Capabilities & Hardening

### Yama `ptrace_scope`

```bash
cat /proc/sys/kernel/yama/ptrace_scope
```

| Value | Behavior |
|-------|----------|
| 0 | Relaxed |
| 1 | **Default** — ptrace limited to children |
| 2 | `CAP_SYS_PTRACE` required for arbitrary attach |
| 3 | No attach |

Temporary hardening:

```bash
echo kernel.yama.ptrace_scope=2 | sudo tee /etc/sysctl.d/99-ptrace.conf
sudo sysctl -p /etc/sysctl.d/99-ptrace.conf
```

### Capabilities

```bash
getcap -r /usr/bin/gdb 2>/dev/null
grep CapEff /proc/self/status
```

`CAP_SYS_PTRACE` allows broader cross-process memory operations on many systems.

### Namespaces

Container escape and post-ex often hinge on whether tracer/tracee share **PID namespace**. `ps` can lie across namespaces — always check `/proc/<pid>/ns/pid`.

---

## 12. ptrace in Real Vulnerabilities (CVE-2026-46333)

**ssh-keysign-pwn / ptrace exit-race** is a teaching moment for syscall students.

### Bug class (simplified)

During process exit:

1. Memory descriptor (`mm`) is torn down → `mm == NULL`
2. FD table still open briefly
3. `__ptrace_may_access()` skips `dumpable` checks in that window
4. Attacker uses **`pidfd_getfd`** to duplicate sensitive FDs from exiting SUID helpers (`ssh-keysign`, `chage`)

### What to study in kernel source (read-only)

- `kernel/ptrace.c` — `ptrace_may_access`, `__ptrace_may_access`
- `kernel/exit.c` — teardown ordering
- `kernel/pidfd.c` — `pidfd_getfd`

### Userland detection (lab)

```bash
sysctl kernel.yama.ptrace_scope
ls -la /usr/lib/openssh/ssh-keysign /usr/bin/chage
grep pidfd_getfd /proc/kallsyms   # needs root for addresses
```

Connects syscall theory → **your `kernelpwn` / env tooling**.

---

## 13. Detection & Blue-Team Angles

| Signal | Idea |
|--------|------|
| `ptrace` syscall from unusual binary | auditd `auditctl -a always,exit -F arch=b64 -S ptrace` |
| Non-debugger process attaches | EDR kernel probes |
| `process_vm_readv` from sshd child | anomaly |
| `dumpable` / `Traced` in `/proc/pid/status` | `TracerPid:` non-zero |
| Sudden `gdb`/`strace` on production | ops alert |

Check trace status:

```bash
cat /proc/<pid>/status | egrep 'Name|TracerPid|State'
```

`TracerPid: 0` → not ptraced. Non-zero → being traced.

---

## 14. Hands-On Labs (Authorized VM Only)

Use a **local VM** (Kali, Ubuntu) you own. Snapshot before each lab.

### Lab 1 — Syscall inventory

1. Write `hello.cpp` that prints a message.
2. Run `strace ./hello`.
3. List every unique syscall name.

**Pass:** Explain what `write`, `exit_group` do.

---

### Lab 2 — Direct `syscall(SYS_write)`

Replace `std::cout` with raw `syscall(SYS_write, 1, msg, len)`.

**Pass:** Output matches; you can explain why FD `1` is stdout.

---

### Lab 3 — Minimal tracer

Build Pattern B (parent traces child).

**Pass:** Parent prints stop signal; child exits cleanly.

---

### Lab 4 — Attach to `sleep`

```bash
sleep 600 &
PID=$!
```

Write a program that `PTRACE_ATTACH`es, waits, reads one `PTRACE_PEEKDATA` word from `RIP` vicinity (will need `/proc/$PID/maps` + register read), detaches.

**Pass:** Understand `EPERM` when `ptrace_scope=2` without capability.

---

### Lab 5 — gdb under strace

Trace gdb while it steps a program. Map gdb operations → ptrace requests.

**Pass:** Document 5 ptrace ops gdb uses in 10 seconds of stepping.

---

### Lab 6 — memfd + syscall awareness

Study `tools/memfd_hiding.cpp` in this repo:

- `memfd_create` → anonymous file in RAM
- `write` → copy payload
- `exec` path → fileless run

Run `strace ./memfd_hiding` and label each stage.

---

### Lab 7 — CVE-2026-46333 exposure checklist

On your VM (no exploit required):

1. `uname -r`
2. `ptrace_scope`
3. SUID `ssh-keysign` / `chage`
4. Document mitigations (`ptrace_scope=2`, kernel patch)

**Pass:** Explain AND vs OR between checks.

---

## 15. Study Roadmap

### Phase 1 — Syscall fluency (2–3 weeks)

- `man 2` for top 20 syscalls
- strace everything you write
- one tool using `syscall()` directly

### Phase 2 — ptrace basics (2–3 weeks)

- fork/wait/traceme lab
- attach lab + Yama experiments
- read gdb internals blog posts

### Phase 3 — modern interfaces (2 weeks)

- `process_vm_readv`
- `pidfd_open` / `pidfd_getfd` man pages
- read Qualys / kernel mailing list threads on ptrace races

### Phase 4 — post-ex integration (ongoing)

- Map techniques to **your** toolkit (memfd, process hide, agent jack)
- write detection notes for each technique you implement

### Books & docs

| Resource | Focus |
|----------|-------|
| `man 2 ptrace`, `man 2 syscalls` | Canonical API |
| *The Linux Programming Interface* (Kerrisk) | Chapters on processes, signals, ptrace |
| `man 7 credentials` | UID/GID/capabilities |
| Linux kernel source `kernel/ptrace.c` | Advanced |
| Brendan Gregg / bpftrace blogs | Syscall tracing at scale |

---

## 16. References

- [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [syscall(2)](https://man7.org/linux/man-pages/man2/syscall.2.html)
- [process_vm_readv(2)](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
- [pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Yama LSM](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [Qualys CVE-2026-46333 advisory](https://blog.qualys.com/misc/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)

---

## Quick Reference Card

```cpp
// Syscall
syscall(SYS_write, fd, buf, count);

// Trace self (debugger check)
ptrace(PTRACE_TRACEME, 0, 0, 0);

// Attach
ptrace(PTRACE_ATTACH, pid, 0, 0);
waitpid(pid, &status, 0);

// Continue
ptrace(PTRACE_CONT, pid, 0, 0);

// Detach
ptrace(PTRACE_DETACH, pid, 0, 0);
```

```bash
# Learn
strace -f ./program
cat /proc/<pid>/status | grep TracerPid
sysctl kernel.yama.ptrace_scope
```

---

*Master syscalls first (what the kernel actually sees), then ptrace (how debuggers and some exploits cross the process boundary). Everything in post-exploitation userland eventually routes through one or both.*

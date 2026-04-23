# ezdbg

**ezdbg** is a lightweight, minimal debugger for Linux systems, built from scratch as a learning project. It uses the `ptrace` system call to control a child process and provides essential debugging features like breakpoints, register inspection, instruction stepping, and memory dumping.

---

## Features

- Set breakpoints by **function name** or **memory address**
- **Start** program execution and automatically stop at the first breakpoint (defaults to `main` if none set)
- **Single-step** through instructions with live RIP and memory display
- **Inspect** all CPU registers (RAX, RBX, RIP, RSP, EFLAGS, etc.)
- **Dump memory** contents over any address range
- **List** all active breakpoints with resolved function names
- **Clear** breakpoints by function name or address
- Supports both **PIE** and **non-PIE** binaries (automatic base address detection)

---

## How It Works

ezdbg forks the target program as a child process and attaches to it using `ptrace`. It then:

1. **Injects breakpoints** by replacing the target instruction byte with `INT 3` (`0xCC`), saving the original byte
2. **Pauses execution** when the child hits a breakpoint or `SIGTRAP`
3. **Resolves symbols** using DWARF debug info (via libdwarf) to support `break <function_name>`
4. **Detects the runtime base address** from `/proc/<pid>/maps` to correctly handle ASLR/PIE binaries
5. **Restores instructions** when continuing past a breakpoint via single-step + re-enable

---

## Dependencies

| Library | Purpose | Install |
|---|---|---|
| `libdwarf` | DWARF debug info parsing (symbol/address lookup) | `sudo apt install libdwarf-dev` |
| `libelf` | ELF binary parsing | `sudo apt install libelf-dev` |
| `gcc` | C compiler | `sudo apt install build-essential` |

> **Note:** ezdbg only runs on **Linux** (x86-64). It will not work on macOS or Windows.

---

## Building

```bash
# Clone the repo
git clone <repository_url>
cd ezdbg

# Release build (optimised)
make

# Debug build (with symbols, no optimisation — useful when debugging ezdbg itself)
make debug

# Install to /usr/local/bin so you can run it from anywhere
sudo make install

# Clean build artifacts
make clean
```

---

## Usage

The target program **must** be compiled with debug symbols (`-g`) for function name resolution to work:

```bash
gcc -g -o my_program my_program.c
./ezdbg my_program
```

---

## Commands

| Command | Description |
|---|---|
| `help` | Show all available commands |
| `break <func\|addr>` | Set a breakpoint at a function name or hex address |
| `clear <func\|addr>` | Remove a breakpoint |
| `list_bp` | List all active breakpoints with addresses and function names |
| `start` | Start execution, stopping at the first breakpoint (or `main` if none set) |
| `continue` | Resume execution until the next breakpoint or program exit |
| `step` | Execute one instruction and show the new RIP and memory |
| `inspect_regs` | Display current values of all CPU registers |
| `memory_dump <start> <end>` | Dump memory contents between two hex addresses |
| `quit` | Exit the debugger |

---

## Example Session

```bash
$ ./ezdbg test1
Program is ready for debugging...
Welcome to ezdbg
To view a list of all commands type 'help'
Type 'quit' to exit the application at anytime

ezdbg> break main
Breakpoint enabled at 0x401136

ezdbg> list_bp
No.     Address                 Function
1       0x401136                main

ezdbg> start
Stopping at first breakpoint.
Hit breakpoint at address: 0x401136

ezdbg> inspect_regs
RIP     0x0000000000401137
RAX     0x0000000000401136
RSP     0x00007fff8b3f2528
RBP     0x00007fff8b3f25c0
...

ezdbg> step
Single step executed successfully.
Instruction pointer (RIP): 0x000000000040113A
Memory at RIP: 0x10EC8348E5894855

ezdbg> memory_dump 0x401000 0x401030
0x0000000000401000:  0x08EC8348FA1E0FF3
0x0000000000401008:  0x4800002FD1058B48
0x0000000000401010:  0x8348D0FF0274C085
0x0000000000401018:  0x0000000000C308C4
0x0000000000401020:  0x25FF00002FCA35FF
0x0000000000401028:  0x00401F0F00002FCC

ezdbg> continue
Sum is : 6

ezdbg> quit
Exiting ezdbg. Goodbye!
```

---

## Project Structure

```
ezdbg/
├── ezdbg.c          # Entry point — forks child and starts debugger
├── run_program.c    # Child process setup (ptrace traceme + exec)
├── run_debugger.c   # Debugger init, base address detection, REPL launch
├── repl.c           # Read-eval-print loop, command parsing
├── commands.c       # Command implementations (break, step, cont, etc.)
├── breakpoint.c     # Breakpoint enable/disable, DWARF symbol resolution
├── dwarf.c          # libdwarf initialisation and cleanup
├── display.c        # Terminal save/restore, screen utilities
├── util.c           # procmsg(), is_numeric() helpers
├── defs.h           # Shared types, structs, and declarations
├── Makefile
└── tests/
    ├── test1.c
    └── test2.c
```

---

## Known Limitations

- Only supports **x86-64 Linux**
- Requires the target to be compiled with **`-g`** (DWARF debug info) for function name resolution; raw addresses still work without it
- Maximum of **100 simultaneous breakpoints**
- Memory dump addresses must be within a **mapped and readable region** of the process
- No support yet for **watchpoints**, **backtraces**, or **source-level** display
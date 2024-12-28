
# ezdbg

**ezdbg** is a lightweight and minimal debugger built for Linux systems. It leverages the `ptrace` system call to enable essential debugging functionalities like setting breakpoints, inspecting registers, stepping through instructions, and dumping memory.

The goal of this project is to provide a simple and extensible debugger for developers who want to understand low-level debugging techniques or build a foundation for more advanced debugging tools.

---

## Features
- Set breakpoints by address or function name.
- Single-step through instructions.
- View and modify CPU registers.
- Dump memory contents.
- List all active breakpoints.
- Start and continue program execution.

---

## How It Works
`ezdbg` works by using the `ptrace` system call to control a child process (the program being debugged). It allows the user to:

1. Inject breakpoints by replacing instructions with `INT 3` (0xCC).
2. Pause execution at breakpoints or specific instructions.
3. Manipulate the instruction pointer and other registers.
4. Inspect and dump memory from specific ranges.

---
## How to Build
1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd ezdbg
   ```

2. Run the Makefile to compile:
   ```bash
   make
   ```

3. Run the debugger:
   ```bash
   ./ezdbg <program_to_debug>
   ```

---

## Example Session
```bash
$ ./ezdbg test_program
Welcome to ezdbg
To view a list of all commands type 'help'
Type 'quit' to exit the application at anytime

ezdbg> break main
Breakpoint set at function: main (0x400123)

ezdbg> start
Stopping at first breakpoint.
Hit breakpoint at address: 0x400123

ezdbg> step
Single step executed successfully.

ezdbg> inspect
RIP    0x0000000000400123
RAX    0x0000000000000000
RBX    0x0000000000000000
...

ezdbg> memory_dump 0x400000 0x400010
Displaying PID: 12345's memory [0x400000 - 0x400010]
0x400000: 0x7f454c46
0x400004: 0x00010102
...

ezdbg> quit
Exiting ezdbg. Goodbye!
```

---

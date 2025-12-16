// Build: g++ -std=c++17 -Wall -Wextra -g -o dbg_part4 src/debugger_part4.cpp

#include <bits/stdc++.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h> // user_regs_struct
#include <unistd.h>
#include <errno.h>
#include <signal.h>

using namespace std;
using ull = unsigned long long;

struct BreakpointInfo
{
  ull addr;
  unsigned char original_byte;
  bool enabled;
};

pid_t debug_pid = -1;
unordered_map<ull, BreakpointInfo> breakpoints;

// --- Convert hex string to ull ---
bool convert_to_hex(const string &hex, ull &value)
{
  value = 0;

  for (char c : hex)
  {
    int digit;
    if (c >= '0' && c <= '9')
      digit = c - '0';
    else if (c >= 'a' && c <= 'f')
      digit = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
      digit = c - 'A' + 10;
    else
      return false;

    if (value > (ULLONG_MAX - digit) / 16)
      return false;

    value = value * 16 + digit;
  }

  return true;
}

// ---- Check if it is valid Hex address ---
bool parse_address(const string &str, ull &out)
{
  string s = str;
  if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
  if (s.size() >= 2 && s[0] == '0' &&
      (s[1] == 'x' || s[1] == 'X'))
    s = s.substr(2);

  if (s.empty())
    return false;

  return convert_to_hex(s, out);
}

// ---- ptrace word read/write helpers ----

unsigned long ptrace_read(pid_t pid, ull addr)
{
  errno = 0;
  unsigned long data = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, nullptr);
  if (data == (unsigned long)-1 && errno != 0)
  {
    perror("PTRACE_PEEKDATA");
  }
  return data;
}

void ptrace_write(pid_t pid, ull addr, unsigned long data)
{
  if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)data) == -1)
  {
    perror("PTRACE_POKEDATA");
  }
}

// --- breakpoint manage ---
bool set_breakpoint(pid_t pid, ull addr)
{
    if (breakpoints.count(addr))
    {
        cerr << "Breakpoint already exists at 0x"
             << hex << addr << dec << "\n";
        return false;
    }

    ull aligned = addr & ~(sizeof(unsigned long) - 1);
    unsigned long word = ptrace_read(pid, aligned);
    if (errno)
        return false;

    size_t offset = addr - aligned;
    unsigned long shift = 8 * offset;
    unsigned long mask  = 0xFFUL << shift;

    unsigned char original_byte = (word & mask) >> shift;

    unsigned long patched_word =
        (word & ~mask) | (0xCCUL << shift);

    ptrace_write(pid, aligned, patched_word);
    if (errno)
        return false;

    breakpoints[addr] = Breakpoint{addr, original_byte, true};

    cout << "Set breakpoint at 0x"
         << hex << addr << dec << "\n";
    return true;
}


bool remove_breakpoint(pid_t pid, ull addr)
{
  auto it = breakpoints.find(addr);
  if (it == breakpoints.end())
  {
    cerr << "No breakpoint at 0x" << hex << addr << dec << "\n";
    return false;
  }
  Breakpoint bp = it->second;

  ull aligned = addr & ~(sizeof(unsigned long) - 1);
  unsigned long word = ptrace_read(pid, aligned);
  if (errno)
    return false;

  size_t offset = addr - aligned;
  unsigned long restored = (word & ~((unsigned long)0xFF << (8 * offset))) | ((unsigned long)it->second.original_byte << (8 * offset));
  ptrace_write(pid, aligned, restored);
  if (errno)
    return false;

  breakpoints.erase(it);
  cout << "Removed breakpoint at 0x" << hex << addr << dec << "\n";
  return true;
}

void show_breakpoints()
{
  if (breakpoints.empty())
  {
    cout << "No breakpoints set.\n";
    return;
  }
  cout << "Breakpoints:\n";
  for (auto &p : breakpoints)
    cout << "  0x" << hex << p.first << dec << "\n";

}

// ----------------- register printing -----------------
void display_registers(pid_t pid)
{
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1)
  {
    perror("PTRACE_GETREGS");
    return;
  }
  cout << hex << showbase;
  cout << "RIP: " << regs.rip << "  RSP: " << regs.rsp << "  RBP: " << regs.rbp << "\n";
  cout << "RAX: " << regs.rax << "  RBX: " << regs.rbx << "  RCX: " << regs.rcx << "\n";
  cout << "RDX: " << regs.rdx << "  RSI: " << regs.rsi << "  RDI: " << regs.rdi << "\n";
  cout << "R8: " << regs.r8 << "  R9:  " << regs.r9 << "  R10: " << regs.r10 << "\n";
  cout << "R11: " << regs.r11 << "  R12: " << regs.r12 << "  R13: " << regs.r13 << "\n";
  cout << "R14: " << regs.r14 << "  R15: " << regs.r15 << "\n";
  cout << dec << nouppercase;
}

// ----------------- wait helpers -----------------
int wait_for_process(pid_t pid)
{
  int status = 0;
  if (waitpid(pid, &status, 0) == -1)
  {
    perror("waitpid");
    return -1;
  }
  return status;
}

void report_process_status(int status)
{
  if (WIFEXITED(status))
  {
    cout << "Child exited with status " << WEXITSTATUS(status) << "\n";
  }
  else if (WIFSIGNALED(status))
  {
    cout << "Child killed by signal " << WTERMSIG(status) << "\n";
  }
  else if (WIFSTOPPED(status))
  {
    cout << "Child stopped by signal " << WSTOPSIG(status) << "\n";
  }
  else
  {
    cout << "Child changed state (status=" << status << ")\n";
  }
}

// ----- Breakpoint hit handler ---
// Called when child stopped with SIGTRAP from executing INT3

bool handle_breakpoint_hit(pid_t pid, struct user_regs_struct &regs)
{
  ull rip = regs.rip;
  if (rip == 0)
    return false;
  ull bp_addr = rip - 1;

  auto it = breakpoints.find(bp_addr);
  if (it == breakpoints.end())
  {
    return false; // koi aur trap hamare breakpoint ke alawa
  }

  Breakpoint bp = it->second;
  cout << "Hit breakpoint at 0x" << hex << bp_addr << dec << "\n";

  ull aligned = bp_addr & ~(sizeof(unsigned long) - 1);
  unsigned long word = ptrace_read(pid, aligned);
  if (errno)
    return false;
  size_t offset = bp_addr - aligned;
  unsigned long cleared = word & ~((unsigned long)0xFF << (8 * offset));
  unsigned long restored = cleared | ((unsigned long)bp.original_byte << (8 * offset));
  ptrace_write(pid, aligned, restored);
  if (errno)
    return false;

  regs.rip = bp_addr;
  if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
  {
    perror("PTRACE_SETREGS");
    return false;
  }

  if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
  {
    perror("PTRACE_SINGLESTEP");
    return false;
  }
  int status = wait_for_process(pid);
  if (status == -1)
    return false;
  if (WIFEXITED(status))
  {
    report_process_status(status);
    return false;
  }

  unsigned long word_after = ptrace_read(pid, aligned);
  if (errno)
    return false;

  unsigned long new_word = (word_after & ~((unsigned long)0xFF << (8 * offset))) | ((unsigned long)0xCC << (8 * offset));
  ptrace_write(pid, aligned, new_word);
  if (errno)
    return false;

  cout << "Breakpoint at 0x" << hex << bp_addr << dec << " handled\n";
  return true;
}

// --- Execution Control ---
void continue_exec(pid_t pid)
{
  if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
  {
    perror("PTRACE_CONT");
    return;
  }

  int status = wait_for_process(pid);
  if (status == -1)
    return;

  if (WIFEXITED(status) || WIFSIGNALED(status))
  {
    report_process_status(status);
    return;
  }

  if (WIFSTOPPED(status))
  {
    int sig = WSTOPSIG(status);
    if (sig == SIGTRAP)
    {
      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
      {
        perror("PTRACE_GETREGS");
        return;
      }

      // handle breakpoint if present
      if (!handle_breakpoint_hit(pid, regs))
      {
        cout << "Stopped with SIGTRAP at RIP=0x" << hex << regs.rip << dec << "\n";
      }
    }
    else
    {
      cout << "Stopped by signal " << sig << "\n";
    }
  }
}


void do_step(pid_t pid)
{
  if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
  {
    perror("PTRACE_SINGLESTEP");
    return;
  }
  int status = wait_for_process(pid);
  if (status == -1)
    return;
  if (WIFEXITED(status) || WIFSIGNALED(status))
  {
    report_process_status(status);
    return;
  }
  if (WIFSTOPPED(status))
  {
    cout << "Child stopped by signal " << WSTOPSIG(status) << "\n";
  }
}

// ----------------- status printing using non-blocking wait -----------------
void print_status(pid_t pid)
{
  int status;
  pid_t r = waitpid(pid, &status, WNOHANG | WUNTRACED | WCONTINUED);
  if (r == 0)
  {
    cout << "Child running\n";
  }
  else if (r == pid)
  {
    if (WIFEXITED(status))
      cout << "Child exited with code " << WEXITSTATUS(status) << "\n";
    else if (WIFSTOPPED(status))
      cout << "Child stopped by signal " << WSTOPSIG(status) << "\n";
    else if (WIFSIGNALED(status))
      cout << "Child killed by signal " << WTERMSIG(status) << "\n";
    else
      cout << "Child changed state (status=" << status << ")\n";
  }
  else
  {
    perror("waitpid");
  }
}

// ----------------- main REPL and launch -----------------
int main(int argc, char **argv)
{
  if (argc < 2)
  {
    cerr << "Usage: dbg_part4 <program> [args...]\n";
    return 1;
  }

  // prepare child args
  vector<char *> child_args;
  for (int i = 1; i < argc; ++i)
    child_args.push_back(argv[i]);
  child_args.push_back(nullptr);

  child_pid = fork();
  if (child_pid == -1)
  {
    perror("fork");
    return 1;
  }

  if (child_pid == 0)
  {
    // Child (debuggee)
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
    {
      perror("PTRACE_TRACEME");
      _exit(1);
    }
    execvp(child_args[0], child_args.data());
    perror("execvp");
    _exit(1);
  }

  // Parent (debugger)
  cout << "Debugger started. Child pid: " << child_pid << "\n";
  int status = wait_for_process(child_pid);
  if (status == -1)
    return 1;
  if (WIFEXITED(status))
  {
    cout << "Child exited prematurely.\n";
    return 0;
  }
  cout << "Child stopped; ready. Type 'help' for commands.\n";

  string line;
  while (true)
  {
    cout << "dbg> " << flush;
    if (!getline(cin, line))
      break;
    if (line.empty())
      continue;

    stringstream ss(line);
    string cmd;
    ss >> cmd;

    if (cmd == "quit" || cmd == "q")
    {
      if (kill(child_pid, SIGKILL) == 0)
        waitpid(child_pid, nullptr, 0);
      cout << "Exiting debugger.\n";
      break;
    }
    else if (cmd == "help" || cmd == "h")
    {
      cout << "Commands:\n"
           << "  break <addr>    - set breakpoint (hex)\n"
           << "  delete <addr>   - remove breakpoint\n"
           << "  info breakpoints- list breakpoints\n"
           << "  continue | c    - continue execution\n"
           << "  step | s        - single-step one instruction\n"
           << "  regs            - print registers\n"
           << "  status          - print process status\n"
           << "  quit | q        - kill debuggee and exit\n";
      continue;
    }
    else if (cmd == "break" || cmd == "b")
    {
      string addr_s;
      ss >> addr_s;
      if (addr_s.empty())
      {
        cerr << "Usage: break <hexaddr>\n";
        continue;
      }
      ull addr;
      if (!parse_address(addr_s, addr))
      {
        cerr << "Bad address\n";
        continue;
      }
      set_breakpoint(child_pid, addr);
    }
    else if (cmd == "delete" || cmd == "d")
    {
      string addr_s;
      ss >> addr_s;
      if (addr_s.empty())
      {
        cerr << "Usage: delete <hexaddr>\n";
        continue;
      }
      ull addr;
      if (!parse_address(addr_s, addr))
      {
        cerr << "Bad address\n";
        continue;
      }
      remove_breakpoint(child_pid, addr);
    }
    else if (cmd == "info")
    {
      string sub;
      ss >> sub;
      if (sub == "breakpoints")
        show_breakpoints();
      else
        cout << "Unknown info command\n";
    }
    else if (cmd == "continue" || cmd == "c")
    {
      continue_exec(child_pid);
    }
    else if (cmd == "step" || cmd == "s")
    {
      do_step(child_pid);
    }
    else if (cmd == "regs")
    {
      display_registers(child_pid);
    }
    else if (cmd == "status")
    {
      print_status(child_pid);
    }
    else
    {
      cerr << "Unknown command: " << cmd << " (type help)\n";
    }
  }

  return 0;
}

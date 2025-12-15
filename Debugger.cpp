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

struct Breakpoint
{
  ull addr;
  unsigned char original_byte;
  bool enabled;
};

pid_t child_pid = -1;
unordered_map<ull, Breakpoint> breakpoints;

// ----------------- utility: parse hex address -----------------
bool parse_address(const string &s, ull &out)
{
  string t = s;
  if (t.size() >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X'))
    t = t.substr(2);
  char *end = nullptr;
  errno = 0;
  unsigned long long val = strtoull(t.c_str(), &end, 16);
  if (end == t.c_str() || *end != '\0' || errno != 0)
    return false;
  out = val;
  return true;
}

// ----------------- ptrace word read/write helpers -----------------
// read a machine word (unsigned long)
unsigned long ptrace_read_word(pid_t pid, ull addr)
{
  errno = 0;
  unsigned long data = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, nullptr);
  if (data == (unsigned long)-1 && errno != 0)
  {
    perror("PTRACE_PEEKDATA");
  }
  return data;
}

void ptrace_write_word(pid_t pid, ull addr, unsigned long data)
{
  if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)data) == -1)
  {
    perror("PTRACE_POKEDATA");
  }
}

// ----------------- breakpoint management -----------------
bool set_breakpoint(pid_t pid, ull addr)
{
  if (breakpoints.count(addr))
  {
    cerr << "Breakpoint already exists at 0x" << hex << addr << dec << "\n";
    return false;
  }

  // Read the machine word that contains the breakpoint byte
  ull aligned = addr & ~(sizeof(unsigned long) - 1);
  unsigned long word = ptrace_read_word(pid, aligned);
  if (errno)
    return false;

  size_t offset = addr - aligned;
  unsigned char orig_byte = (word >> (8 * offset)) & 0xFF;

  // write new word with 0xCC at the target byte
  unsigned long new_word = word & ~((unsigned long)0xFF << (8 * offset));
  new_word |= ((unsigned long)0xCC << (8 * offset));
  ptrace_write_word(pid, aligned, new_word);
  if (errno)
    return false;

  Breakpoint bp{addr, orig_byte, true};
  breakpoints[addr] = bp;
  cout << "Set breakpoint at 0x" << hex << addr << dec << "\n";
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
  unsigned long word = ptrace_read_word(pid, aligned);
  if (errno)
    return false;

  size_t offset = addr - aligned;
  unsigned long cleared = word & ~((unsigned long)0xFF << (8 * offset));
  unsigned long restored = cleared | ((unsigned long)bp.original_byte << (8 * offset));
  ptrace_write_word(pid, aligned, restored);
  if (errno)
    return false;

  breakpoints.erase(it);
  cout << "Removed breakpoint at 0x" << hex << addr << dec << "\n";
  return true;
}

void list_breakpoints()
{
  if (breakpoints.empty())
  {
    cout << "No breakpoints set.\n";
    return;
  }
  cout << "Breakpoints:\n";
  for (auto &p : breakpoints)
  {
    cout << "  0x" << hex << p.first << dec << "\n";
  }
}

// ----------------- register printing -----------------
void print_regs(pid_t pid)
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
int wait_for_pid(pid_t pid)
{
  int status = 0;
  if (waitpid(pid, &status, 0) == -1)
  {
    perror("waitpid");
    return -1;
  }
  return status;
}

void report_status(int status)
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

// ----------------- handle breakpoint hit properly -----------------
// Called when child stopped with SIGTRAP from executing INT3
// We assume regs.rip points to bp_addr + 1
bool handle_breakpoint_hit(pid_t pid, struct user_regs_struct &regs)
{
  ull rip = regs.rip;
  if (rip == 0)
    return false;
  ull bp_addr = rip - 1;

  auto it = breakpoints.find(bp_addr);
  if (it == breakpoints.end())
  {
    // not our software breakpoint (could be other trap)
    return false;
  }

  Breakpoint bp = it->second;
  cout << "Hit breakpoint at 0x" << hex << bp_addr << dec << "\n";

  // Restore original byte
  ull aligned = bp_addr & ~(sizeof(unsigned long) - 1);
  unsigned long word = ptrace_read_word(pid, aligned);
  if (errno)
    return false;
  size_t offset = bp_addr - aligned;
  unsigned long cleared = word & ~((unsigned long)0xFF << (8 * offset));
  unsigned long restored = cleared | ((unsigned long)bp.original_byte << (8 * offset));
  ptrace_write_word(pid, aligned, restored);
  if (errno)
    return false;

  // Move RIP back so instruction executes
  regs.rip = bp_addr;
  if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
  {
    perror("PTRACE_SETREGS");
    return false;
  }

  // Single-step the original instruction (now that it's restored)
  if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
  {
    perror("PTRACE_SINGLESTEP");
    return false;
  }
  int status = wait_for_pid(pid);
  if (status == -1)
    return false;
  if (WIFEXITED(status))
  {
    report_status(status);
    return false;
  }

  // After single-step, re-insert the breakpoint (0xCC) so it remains next time
  unsigned long word_after = ptrace_read_word(pid, aligned);
  if (errno)
    return false;
  unsigned long new_word = (word_after & ~((unsigned long)0xFF << (8 * offset))) | ((unsigned long)0xCC << (8 * offset));
  ptrace_write_word(pid, aligned, new_word);
  if (errno)
    return false;

  cout << "Breakpoint at 0x" << hex << bp_addr << dec << " handled (single-stepped).\n";
  return true;
}

// ----------------- continue with detection of breakpoint hits -----------------
void do_continue(pid_t pid)
{
  if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
  {
    perror("PTRACE_CONT");
    return;
  }

  int status = wait_for_pid(pid);
  if (status == -1)
    return;

  if (WIFEXITED(status) || WIFSIGNALED(status))
  {
    report_status(status);
    return;
  }

  if (WIFSTOPPED(status))
  {
    int sig = WSTOPSIG(status);
    if (sig == SIGTRAP)
    {
      // get registers to check if this is a breakpoint hit
      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
      {
        perror("PTRACE_GETREGS");
        return;
      }

      // handle breakpoint if present
      if (!handle_breakpoint_hit(pid, regs))
      {
        // Not a software breakpoint we set; just report
        cout << "Stopped with SIGTRAP at RIP=0x" << hex << regs.rip << dec << "\n";
      }
      else
      {
        // After handling, we are stopped (after single-step). Child is ready.
      }
    }
    else
    {
      cout << "Stopped by signal " << sig << "\n";
    }
  }
}

// ----------------- single step wrapper -----------------
void do_step(pid_t pid)
{
  if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
  {
    perror("PTRACE_SINGLESTEP");
    return;
  }
  int status = wait_for_pid(pid);
  if (status == -1)
    return;
  if (WIFEXITED(status) || WIFSIGNALED(status))
  {
    report_status(status);
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
  int status = wait_for_pid(child_pid);
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
        list_breakpoints();
      else
        cout << "Unknown info command\n";
    }
    else if (cmd == "continue" || cmd == "c")
    {
      do_continue(child_pid);
    }
    else if (cmd == "step" || cmd == "s")
    {
      do_step(child_pid);
    }
    else if (cmd == "regs")
    {
      print_regs(child_pid);
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

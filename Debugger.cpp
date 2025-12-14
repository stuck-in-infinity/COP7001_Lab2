// Debugger with ability to set/remove breakpoints
// New: break <addr>, delete <addr>, list breakpoints

#include <bits/stdc++.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <unistd.h>
using namespace std;

struct Breakpoint
{
  long original_byte;
  bool enabled;

  Breakpoint() : original_byte(0), enabled(false) {}
};

map<long, Breakpoint> breakpoints;

// Insert breakpoint at address
void set_breakpoint(pid_t child, long addr)
{
  long data = ptrace(PTRACE_PEEKDATA, child, addr, nullptr);
  if (data == -1)
  {
    perror("PTRACE_PEEKDATA");
    return;
  }

  Breakpoint bp;
  bp.original_byte = data & 0xFF; // lowest byte
  bp.enabled = true;

  long data_with_int3 = (data & ~0xFF) | 0xCC; // replace lowest byte with 0xCC
  ptrace(PTRACE_POKEDATA, child, addr, data_with_int3);

  breakpoints[addr] = bp;

  cout << "Breakpoint set at " << hex << showbase << addr << dec << "\n";
}

// Remove breakpoint at address
void remove_breakpoint(pid_t child, long addr)
{
  if (!breakpoints.count(addr))
  {
    cout << "No breakpoint at that address.\n";
    return;
  }

  Breakpoint &bp = breakpoints[addr];

  long data = ptrace(PTRACE_PEEKDATA, child, addr, nullptr);
  long restored = (data & ~0xFF) | (bp.original_byte & 0xFF);

  ptrace(PTRACE_POKEDATA, child, addr, restored);

  breakpoints.erase(addr);

  cout << "Breakpoint removed at " << hex << showbase << addr << dec << "\n";
}

// Print all breakpoints
void list_breakpoints()
{
  if (breakpoints.empty())
  {
    cout << "No breakpoints set.\n";
    return;
  }
  cout << "Current breakpoints:\n";
  for (auto &p : breakpoints)
  {
    cout << "  * " << hex << showbase << p.first << dec << "\n";
  }
}

bool wait_and_report(pid_t child)
{
  int status;
  waitpid(child, &status, 0);

  if (WIFEXITED(status))
  {
    cout << "Program exited with code " << WEXITSTATUS(status) << "\n";
    return false;
  }
  if (WIFSIGNALED(status))
  {
    cout << "Program terminated by signal " << WTERMSIG(status) << "\n";
    return false;
  }
  if (WIFSTOPPED(status))
  {
    cout << "Child stopped by signal " << WSTOPSIG(status) << "\n";
  }
  return true;
}

void print_regs(pid_t child)
{
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, child, nullptr, &regs) == -1)
  {
    perror("PTRACE_GETREGS");
    return;
  }

  cout << hex << showbase;
  cout << "RIP: " << regs.rip << "  RSP: " << regs.rsp << "\n";
  cout << "RAX: " << regs.rax << "  RBX: " << regs.rbx << "\n";
  cout << "RCX: " << regs.rcx << "  RDX: " << regs.rdx << "\n";
  cout << dec;
}

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    cerr << "Usage: dbg <program> [args...]\n";
    return 1;
  }

  vector<char *> args;
  for (int i = 1; i < argc; i++)
    args.push_back(argv[i]);
  args.push_back(nullptr);

  pid_t child = fork();
  if (child == 0)
  {
    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    execvp(args[0], args.data());
    perror("execvp");
    _exit(1);
  }

  cout << "Debugger started. Child PID: " << child << "\n";
  wait_and_report(child);

  string line;
  while (true)
  {
    cout << "dbg> " << flush;
    if (!getline(cin, line))
      break;

    if (line == "quit" || line == "q")
    {
      kill(child, SIGKILL);
      waitpid(child, nullptr, 0);
      cout << "Debugger exiting.\n";
      break;
    }

    if (line == "continue" || line == "c")
    {
      ptrace(PTRACE_CONT, child, nullptr, nullptr);
      if (!wait_and_report(child))
        break;
    }

    else if (line == "step" || line == "s")
    {
      ptrace(PTRACE_SINGLESTEP, child, nullptr, nullptr);
      if (!wait_and_report(child))
        break;
    }

    else if (line == "regs")
    {
      print_regs(child);
    }

    else if (line.starts_with("break "))
    {
      string addr_str = line.substr(6);
      long addr = stol(addr_str, nullptr, 16);
      set_breakpoint(child, addr);
    }

    else if (line.starts_with("delete "))
    {
      string addr_str = line.substr(7);
      long addr = stol(addr_str, nullptr, 16);
      remove_breakpoint(child, addr);
    }

    else if (line == "info breakpoints")
    {
      list_breakpoints();
    }

    else
    {
      cout << "Commands: continue, step, regs, break <addr>, delete <addr>, info breakpoints, quit\n";
    }
  }

  return 0;
}

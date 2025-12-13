// Part 2: Debugger with registers + single-step
// New features: regs, step, detailed stop messages

#include <bits/stdc++.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h> // struct user_regs_struct
#include <unistd.h>
using namespace std;

// Print CPU registers (x86_64)
void print_regs(pid_t child)
{
  struct user_regs_struct regs;

  if (ptrace(PTRACE_GETREGS, child, nullptr, &regs) == -1)
  {
    perror("PTRACE_GETREGS");
    return;
  }

  cout << hex << showbase;
  cout << "RIP: " << regs.rip << "  RSP: " << regs.rsp << "  RBP: " << regs.rbp << "\n";
  cout << "RAX: " << regs.rax << "  RBX: " << regs.rbx << "  RCX: " << regs.rcx << "\n";
  cout << "RDX: " << regs.rdx << "  RSI: " << regs.rsi << "  RDI: " << regs.rdi << "\n";
  cout << "R8: " << regs.r8 << "  R9: " << regs.r9 << "  R10: " << regs.r10 << "\n";
  cout << "R11: " << regs.r11 << "  R12: " << regs.r12 << "  R13: " << regs.r13 << "\n";
  cout << "R14: " << regs.r14 << "  R15: " << regs.r15 << "\n";
  cout << dec;
}

// Handle waiting for child & print info
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
    int sig = WSTOPSIG(status);
    cout << "Child stopped due to signal " << sig << "\n";
    if (sig == SIGTRAP)
      cout << "(SIGTRAP received)\n";
    return true;
  }

  return true;
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
  if (child == -1)
  {
    perror("fork");
    return 1;
  }

  if (child == 0)
  {
    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    execvp(args[0], args.data());
    perror("execvp");
    _exit(1);
  }

  // parent
  cout << "Debugger started. Child PID = " << child << "\n";
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
      cout << "Exiting debugger.\n";
      break;
    }

    else if (line == "continue" || line == "c")
    {
      ptrace(PTRACE_CONT, child, nullptr, nullptr);
      if (!wait_and_report(child))
        break;
    }

    else if (line == "regs")
    {
      print_regs(child);
    }

    else if (line == "step" || line == "s")
    {
      ptrace(PTRACE_SINGLESTEP, child, nullptr, nullptr);
      if (!wait_and_report(child))
        break;
    }

    else
    {
      cout << "Commands: continue(c), step(s), regs, quit(q)\n";
    }
  }

  return 0;
}

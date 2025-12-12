// Part 1: Minimal Debugger (C++)
// Features: launch target, continue, quit, basic REPL

#include <bits/stdc++.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
using namespace std;

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
    // child (debuggee)
    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    execvp(args[0], args.data());
    perror("execvp");
    _exit(1);
  }

  // parent (debugger)
  int status;
  waitpid(child, &status, 0);
  cout << "Debuggee started. PID: " << child << "\n";

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

    else if (line == "continue" || line == "c")
    {
      ptrace(PTRACE_CONT, child, nullptr, nullptr);
      waitpid(child, &status, 0);

      if (WIFEXITED(status))
      {
        cout << "Program exited with code " << WEXITSTATUS(status) << "\n";
        break;
      }
    }

    else
    {
      cout << "Unknown command. Available: continue, quit\n";
    }
  }

  return 0;
}

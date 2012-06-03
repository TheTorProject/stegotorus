/* Copyright 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef SUBPROCESS_H
#define SUBPROCESS_H

#include <string>
#include <vector>

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

// This API is inspired by the Python subprocess module.  While it
// could be extended to do everything that that does, at present it
// does much less.  If you add features, please consider matching
// Python's presentation of same.

#ifndef CLD_EXITED
#define CLD_EXITED 1
#endif
#ifndef CLD_KILLED
#define CLD_KILLED 2
#endif
#ifndef CLD_DUMPED
#define CLD_DUMPED 3
#endif

struct subprocess
{
  // Start a new subprocess with argument vector |args| and environment
  // vector |env|.  stdin and stdout are /dev/null.  stderr is inherited.
  // All file descriptors numbered 3 and higher are closed.
  // The current working directory is inherited.
  subprocess(std::vector<std::string> const& args,
             std::vector<std::string> const& env);

  // Convenience: spawn a subprocess and wait for it to terminate.
  static subprocess call(std::vector<std::string> const& args,
                         std::vector<std::string> const& env);

  // Check whether the child process has terminated.  Returns true if it
  // has, false otherwise; sets 'state' and 'returncode'.
  bool poll();

  // Wait for the child process to terminate.
  void wait();

  // Process ID of the child.  -1 on failure to spawn, in which case
  // an error message has already been logged.
  const pid_t pid;

  // Child state, either 0 (running) or one of the <signal.h> constants
  // CLD_EXITED, CLD_KILLED, or CLD_DUMPED.
  int state;

  // Exit status (if state == CLD_EXITED) or signal that terminated the
  // process (if state == CLD_KILLED or CLD_DUMPED); -1 otherwise.
  int returncode;
};

// Convert the global environment vector to a C++ vector.
// If 'exclude' is not NULL, then any environment variable whose name
// begins with those characters will be excluded from the result.
extern std::vector<std::string> get_environ(const char *exclude = 0);

#endif

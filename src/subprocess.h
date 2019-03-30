/* Copyright 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef SUBPROCESS_H
#define SUBPROCESS_H

#include <string>
#include <vector>

#include <sys/types.h>
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

// These are in here because they involve process management 'under the hood',
// and because (like other process management) their Unix and Windows
// implementations have to be radically different.

// Turn into a daemon; detach from the parent process and any
// controlling terminal.  Closes standard I/O streams and reopens them
// to /dev/null.  If this returns, it succeeded.
extern void daemonize();

// Instantiating this class causes a file to be created at the specified
// pathname, which contains the decimal process ID of the current process.
// On destruction, the file is deleted.
//
// If you're going to call daemonize(), you need to do it _before_ creating
// one of these, because daemonize() changes the process ID.

class pidfile
{
public:
  pidfile(const std::string& p);
  ~pidfile();

  const std::string& pathname() const { return path; }

  // True if pid-file creation succeeded.
  operator bool() const;

  // If pid-file creation did *not* succeed, returns the underlying system
  // error message.  You should combine that with the pathname and some
  // text to the effect that this is a process ID file for the actual error
  // message printed to the user.
  // If pid-file creation *did* succeed, returns NULL.
  const char *errmsg() const;

private:
  std::string path;
  int errcode;
};

#endif

/* Copyright 2012 SRI International
 * Portions copyright 2003-2011 Roger Dingledine, Nick Mathewson,
 *   and/or The Tor Project, Inc.
 * Portions copyright 1991-2012 The Regents of the University of California
 *   and/or various FreeBSD contributors.
 * See LICENSE for other credits and copying information.
 */

// N.B. This file will have to be rewritten more-or-less from scratch
// for the Windows port.  It should be acceptably portable to all Unix
// implementations still in wide use.

#include "util.h"
#include "subprocess.h"

#include <map>

#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#ifndef _PATH_DEFPATH
#define _PATH_DEFPATH "/usr/bin:/bin"
#endif

#ifndef PATH_MAX
# ifdef MAXPATHLEN
#  define PATH_MAX MAXPATHLEN
# else
#  define PATH_MAX 4096
# endif
#endif

#ifndef OPEN_MAX
# define OPEN_MAX 256
#endif

extern char **environ;

using std::map;
using std::vector;
using std::string;


// Space for hex values of child state, a slash, saved_errno (with
//    leading minus) and newline (no null)
#define HEX_ERRNO_SIZE (sizeof(int)*2 + 4)

// State codes for the child side of the fork.
#define CHILD_STATE_REDIRECT_STDIN 1
#define CHILD_STATE_REDIRECT_STDOUT 2
#define CHILD_STATE_REDIRECT_STDERR 3
#define CHILD_STATE_CLOSEFROM 4
#define CHILD_STATE_EXEC 5

// Some C libraries get very unhappy with you if you ignore the result
// of a write call, but where it's used in this file, there is nothing
// whatsoever we can do if it fails.
#define IGNORE_FAILURE(expr) do { if (expr) {} } while (0)

// We have not prevented copying of |subprocess| objects, so it is
// possible that |wait| will be called more than once for the same
// PID, with no state in the object to tell us so.  To prevent
// problems, maintain a table of processes that we have waited for.
// We make no attempt to prune this table; its memory requirements
// should be trivial for the expected uses of this API.
static map<pid_t, int> already_waited;

// Internal utilities and replacements for system library routines
// that may or may not exist.

#ifndef HAVE_CLOSEFROM
static void
closefrom(int lowfd)
{
#ifdef F_CLOSEM
  // Try F_CLOSEM if it's defined.  But it might not work.
  if (fcntl(lowfd, F_CLOSEM, 0) == 0)
    return;
#endif

  // If /proc/self/fd is available, use it.
  // N.B. Theoretically you are not allowed to use opendir() after fork()
  // as it's not async-signal-safe.  This is overwhelmingly unlikely to
  // cause problems in practice.
  DIR *dirp;
  if ((dirp = opendir("/proc/self/fd")) != 0) {
    struct dirent *dent;
    char *endp;
    while ((dent = readdir(dirp)) != NULL) {
      unsigned long fd = strtoul(dent->d_name, &endp, 10);
      if (dent->d_name != endp && *endp == '\0' &&
          fd <  (unsigned long)INT_MAX &&
          fd >= (unsigned long)lowfd   &&
          fd != (unsigned long)dirfd(dirp))
        close((int)fd);
    }
    closedir(dirp);
    return;
  }

  // As a last resort, blindly close all possible fd numbers
  // between lowfd and _SC_OPEN_MAX.
  unsigned long maxfd = sysconf(_SC_OPEN_MAX);
  if (maxfd == (unsigned long)(-1L))
    maxfd = OPEN_MAX;
  for (unsigned long fd = lowfd; fd < maxfd; fd++)
    close((int)fd);
}
#endif

#ifndef HAVE_EXECVPE
// Implementation courtesy FreeBSD 9.0 src/lib/libc/gen/exec.c
// some adjustments made with reference to the glibc implementation
static int
execvpe(const char *name, char * const argv[], char * const envp[])
{
  const char *path;
  const char *p, *q;
  size_t lp, ln;
  bool eacces = false;
  char buf[PATH_MAX];

  // If it's an empty path name, fail immediately.
  if (*name == '\0') {
    errno = ENOENT;
    return -1;
  }

  // If it's an absolute or relative pathname, do not search $PATH.
  if (strchr(name, '/')) {
    execve(name, argv, envp);
    return -1;
  }
  ln = strlen(name);

  // Get the path to search.  Intentionally uses the parent
  // environment, not 'envp'.
  if (!(path = getenv("PATH")))
    path = _PATH_DEFPATH;

  q = path;
  do {
    p = q;
    while (*q != '\0' && *q != ':')
      q++;

    // Double, leading and trailing colons mean the current directory.
    if (q == p) {
      p = ".";
      lp = 1;
    } else
      lp = q - p;
    q++;

    // If the path is too long, complain and skip it.  This is a
    // possible security issue; given a way to make the path too long
    // the user may execute the wrong program.
    if (lp + ln + 2 > sizeof(buf)) {
      IGNORE_FAILURE(write(2, "execvpe: ", 8));
      IGNORE_FAILURE(write(2, p, lp));
      IGNORE_FAILURE(write(2, ": path too long\n", 16));
      continue;
    }

    memcpy(buf, p, lp);
    buf[lp] = '/';
    memcpy(buf + lp + 1, name, ln);
    buf[lp + ln + 1] = '\0';

    execve(buf, argv, envp);
    switch (errno) {
      // These errors all indicate that we should try the next directory.
    case EACCES:
      // Remember that at least one failure was due to a permission check;
      // this will be preferentially reported, unless we hit something even
      // more serious.
      eacces = true;
    case ELOOP:
    case ENAMETOOLONG:
    case ENOENT:
    case ENOTDIR:
    case ESTALE:
    case ETIMEDOUT:
      continue;

    default:
      // On any other error, give up.
      // Shell fallback for ENOEXEC deliberately removed, as it is a
      // historical vestige and involves allocating memory.
      return -1;
    }
  } while (*q);

  if (eacces)
    errno = EACCES;
  return -1;
}
#endif

/** Format <b>child_state</b> and <b>saved_errno</b> as a hex string placed in
 * <b>hex_errno</b>.  Called between fork and _exit, so must be signal-handler
 * safe.
 *
 * <b>hex_errno</b> must have at least HEX_ERRNO_SIZE bytes available.
 *
 * The format of <b>hex_errno</b> is: "CHILD_STATE/ERRNO\n", left-padded
 * with spaces. Note that there is no trailing \0. CHILD_STATE indicates where
 * in the processs of starting the child process did the failure occur (see
 * CHILD_STATE_* macros for definition), and SAVED_ERRNO is the value of
 * errno when the failure occurred.
 */
static void
format_helper_exit_status(unsigned char child_state, int saved_errno,
                          char *hex_errno)
{
  unsigned int unsigned_errno;
  char *cur;
  size_t i;

  /* Fill hex_errno with spaces, and a trailing newline (memset may
     not be signal handler safe, so we can't use it) */
  for (i = 0; i < (HEX_ERRNO_SIZE - 1); i++)
    hex_errno[i] = ' ';
  hex_errno[HEX_ERRNO_SIZE - 1] = '\n';

  /* Convert errno to be unsigned for hex conversion */
  if (saved_errno < 0) {
    unsigned_errno = (unsigned int) -saved_errno;
  } else {
    unsigned_errno = (unsigned int) saved_errno;
  }

  /* Convert errno to hex (start before \n) */
  cur = hex_errno + HEX_ERRNO_SIZE - 2;

  /* Check for overflow on first iteration of the loop */
  if (cur < hex_errno)
    return;

  do {
    *cur-- = "0123456789ABCDEF"[unsigned_errno % 16];
    unsigned_errno /= 16;
  } while (unsigned_errno != 0 && cur >= hex_errno);

  /* Prepend the minus sign if errno was negative */
  if (saved_errno < 0 && cur >= hex_errno)
    *cur-- = '-';

  /* Leave a gap */
  if (cur >= hex_errno)
    *cur-- = '/';

  /* Check for overflow on first iteration of the loop */
  if (cur < hex_errno)
    return;

  /* Convert child_state to hex */
  do {
    *cur-- = "0123456789ABCDEF"[child_state % 16];
    child_state /= 16;
  } while (child_state != 0 && cur >= hex_errno);
}

/** Start a program in the background. If <b>filename</b> contains a '/',
 * then it will be treated as an absolute or relative path.  Otherwise the
 * system path will be searched for <b>filename</b>. The strings in
 * <b>argv</b> will be passed as the command line arguments of the child
 * program (following convention, argv[0] should normally be the filename of
 * the executable), and the strings in <b>envp</b> will be passed as its
 * environment variables.
 *
 * The child's standard input and output will both be /dev/null;
 * the child's standard error will be whatever it is in the parent
 * (unless it is closed in the parent, in which case it will also be
 * /dev/null)
 *
 * All file descriptors numbered higher than 2 will be closed.
 *
 * On success, returns the PID of the child; on failure, returns -1.
 */
static pid_t
do_fork_exec(const char *const filename,
             const char **argv,
             const char **envp)
{
  pid_t pid = fork();

  if (pid == -1) {
    log_warn("Failed to fork child process: %s", strerror(errno));
    return -1;
  }

  if (pid != 0) {
    // In parent.
    // If we spawn a child, wait for it, the PID counter wraps
    // completely around, and then we spawn another child which
    // happens to get exactly the same PID as the first one, we had
    // better remove the old record from the already_waited table or
    // we won't ever actually wait for the new child.  The odds of
    // this are small, but not ridiculously small.
    already_waited.erase(pid);
    return pid;
  }

  // In child
  char hex_errno[HEX_ERRNO_SIZE];
  unsigned int child_state = CHILD_STATE_REDIRECT_STDIN;

  close(0);
  if (open("/dev/null", O_RDONLY) != 0)
    goto error;

  child_state = CHILD_STATE_REDIRECT_STDOUT;

  close(1);
  if (open("/dev/null", O_WRONLY) != 1)
    goto error;

  child_state = CHILD_STATE_REDIRECT_STDERR;
  if (!isatty(2) && errno == EBADF) {
    if (open("/dev/null", O_WRONLY) != 2)
      goto error;
  }

  child_state = CHILD_STATE_CLOSEFROM;
  closefrom(3);

  child_state = CHILD_STATE_EXEC;

  // We need the casts because execvpe doesn't declare argv or envp
  // as const, even though it does not modify them.
  execvpe(filename, (char *const *) argv, (char *const *)envp);

 error:
  format_helper_exit_status(child_state, errno, hex_errno);

#define error_message "ERR: Failed to spawn child process: code "

  IGNORE_FAILURE(write(2, error_message, sizeof error_message - 1));
  IGNORE_FAILURE(write(2, hex_errno, sizeof hex_errno));

#undef error_message

  _exit(255);
}

// Wrapper: marshal the C++-y vector and map into the form the kernel
// expects.
static pid_t
do_fork_exec(vector<string> const& args,
             vector<string> const& env)
{
  char const* argv[args.size() + 1];
  char const* envp[env.size() + 1];

  for (size_t i = 0; i < args.size(); i++)
    argv[i] = args[i].c_str();
  argv[args.size()] = 0;

  for (size_t i = 0; i < env.size(); i++)
    envp[i] = env[i].c_str();
  envp[env.size()] = 0;

  return do_fork_exec(argv[0], argv, envp);
}

static void
decode_status(int status, int& state, int& rc)
{
  if (WIFEXITED(status)) {
    rc = WEXITSTATUS(status);
    state = CLD_EXITED;
  } else if (WIFSIGNALED(status)) {
    rc = WTERMSIG(status);
#ifdef WCOREDUMP
    if (WCOREDUMP(status))
      state = CLD_DUMPED;
    else
#endif
      state = CLD_KILLED;
  } else {
    // we do not use WUNTRACED, WCONTINUED, or ptrace, so the other
    // WIF* possibilities should never happen
    log_abort("impossible wait status %04x", (unsigned int)status);
  }
}

static bool
wait_common(pid_t pid, int& state, int& rc, bool wnohang)
{
  if (pid == -1) {
    // Map failure to fork into the same exit state that we get if
    // there's a failure in between fork and exec.
    state = CLD_EXITED;
    rc = 255;
    return true;
  }

  map<pid_t, int>::iterator p = already_waited.find(pid);
  if (p != already_waited.end()) {
    decode_status(p->second, state, rc);
    return true;
  }

  int status;
  pid_t rv = waitpid(pid, &status, wnohang ? WNOHANG : 0);
  if (rv == pid) {
    decode_status(status, state, rc);
    already_waited.insert(std::make_pair(pid, status));
    return true;
  } else if (rv == 0 && wnohang) {
    return false;
  } else {
    log_warn("waitpid(%d) failed: %s", pid, strerror(errno));
    return false;
  }
}

// subprocess methods

subprocess::subprocess(vector<string> const& args,
                       vector<string> const& env)
  : pid(do_fork_exec(args, env)),
    state(0),
    returncode(-1)
{
}

subprocess
subprocess::call(vector<string> const& args, vector<string> const& env)
{
  subprocess proc(args, env);
  proc.wait();
  return proc;
}

bool
subprocess::poll()
{
  return wait_common(pid, state, returncode, true);
}

void
subprocess::wait()
{
  wait_common(pid, state, returncode, false);
}

// public utilities

vector<string>
get_environ(const char *exclude)
{
  vector<string> result;
  size_t exlen = exclude ? strlen(exclude) : 0;

  for (char **p = environ; *p; p++)
    if (!exclude || strncmp(exclude, *p, exlen))
      result.push_back(*p);

  return result;
}

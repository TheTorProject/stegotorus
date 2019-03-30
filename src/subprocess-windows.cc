/* Copyright 2012 SRI International
 * See LICENSE for other credits and copying information.
 */

//#warning "Subprocess creation for Windows not yet implemented.n"

#include "util.h"
#include "subprocess.h"

using namespace std;

subprocess::subprocess(std::vector<std::string> const& args,
                       std::vector<std::string> const& env)
  : pid(0),
    state(0),
    returncode(-1)
{
  (void) args;
  (void) env;
}

std::vector<std::string>
get_environ(const char *exclude)
{
  std::vector<std::string> result;
  (void)exclude;
  log_abort("Subprocess creation for Windows not yet implemented.");

  return result;
}

void
daemonize()
{
  log_abort("Subprocess creation for Windows not yet implemented.");
}

subprocess
subprocess::call(vector<string> const& args, vector<string> const& env)
{
  subprocess proc(args, env);
  log_abort("Subprocess creation for Windows not yet implemented.");
  return proc;
}

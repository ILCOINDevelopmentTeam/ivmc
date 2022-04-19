// IVMC: Ethereum Client-VM Connector API.
// Copyright 2019-2020 The IVMC Authors.
// Licensed under the Apache License, Version 2.0.

#include <CLI/CLI.hpp>
#include <ivmc/hex.hpp>
#include <ivmc/loader.h>
#include <ivmc/tooling.hpp>
#include <fstream>

#include <dirent.h>
#include <iterator>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <vector>

namespace
{
/// Returns the input str if already valid hex string. Otherwise, interprets the str as a file
/// name and loads the file content.
/// @todo The file content is expected to be a hex string but not validated.
std::string load_hex(const std::string& str)
{
    const auto error_code = ivmc::validate_hex(str);
    if (!error_code)
        return str;

    // Must be a file path.
    std::ifstream file{str};
    return std::string(std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{});
}

struct HexValidator : public CLI::Validator
{
    HexValidator() : CLI::Validator{"HEX"}
    {
        name_ = "HEX";
        func_ = [](const std::string& str) -> std::string {
            const auto error_code = ivmc::validate_hex(str);
            if (error_code)
                return error_code.message();
            return {};
        };
    }
};

void do_heartbeat(int count)
{
   // TODO: implement processing code to be performed on each heartbeat
   std::string s = "do_heartbeat daemon-name: " + std::to_string(count);
   syslog(LOG_NOTICE, s.c_str());
}
}  // namespace

int main(int argc, const char** argv)
{
  pid_t pid, sid;

  // Fork the current process
  pid = fork();
  // The parent process continues with a process ID greater than 0
  if(pid > 0)
  {
   exit(EXIT_SUCCESS);
  }
  // A process ID lower than 0 indicates a failure in either process
  else if(pid < 0)
  {
   exit(EXIT_FAILURE);
  }
  // The parent process has now terminated, and the forked child process will continue
  // (the pid of the child process was 0)

  // Since the child process is a daemon, the umask needs to be set so files and logs can be written
  umask(0);

  // Open system logs for the child process
  openlog("daemon-named", LOG_NOWAIT | LOG_PID, LOG_USER);
  syslog(LOG_NOTICE, "Successfully started daemon-name");

  // Generate a session ID for the child process
  sid = setsid();
  // Ensure a valid SID for the child process
  if(sid < 0)
  {
   // Log failure and exit
   syslog(LOG_ERR, "Could not generate session ID for child process");

   // If a new session ID could not be generated, we must terminate the child process
   // or it will be orphaned
   exit(EXIT_FAILURE);
  }

  // Change the current working directory to a directory guaranteed to exist
  if((chdir("/")) < 0)
  {
   // Log failure and exit
   syslog(LOG_ERR, "Could not change working directory to /");

   // If our guaranteed directory does not exist, terminate the child process to ensure
   // the daemon has not been hijacked
   exit(EXIT_FAILURE);
  }

  // A daemon cannot use the terminal, so close standard file descriptors for security reasons
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  // Daemon-specific intialization should go here
  const int SLEEP_INTERVAL = 5;

  // Enter daemon loop
  int c = 0;
  while(1)
  {
    c = c + 1 > 65535 ? 0 : c + 1;

    // Execute daemon heartbeat, where your recurring activity occurs
    do_heartbeat(c);

    std::cout.flush();

    // Sleep for a period of time
    sleep(SLEEP_INTERVAL);
  }

  // Close system logs for the child process
  syslog(LOG_NOTICE, "Stopping daemon-name");
  closelog();

  // Terminate the child process when the daemon completes
  exit(EXIT_SUCCESS);
}

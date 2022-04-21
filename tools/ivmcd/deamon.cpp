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

#include <ios>
#include <memory>
#include <functional>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
#ifdef _XOPEN_SOURCE_EXTENDED
#include <arpa/inet.h>
#endif
#endif

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

/** libevent event log callback */
static void libevent_log_cb(int severity, const char *msg)
{
#ifndef EVENT_LOG_WARN
// EVENT_LOG_WARN was added in 2.0.19; but before then _EVENT_LOG_WARN existed.
# define EVENT_LOG_WARN _EVENT_LOG_WARN
#endif
    if (severity >= EVENT_LOG_WARN) // Log warn messages and higher without debug category
        syslog(LOG_NOTICE, msg);
    else
        syslog(LOG_NOTICE, msg);
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

  //! Bound listening sockets
  std::vector<evhttp_bound_socket *> boundSockets;
  struct evhttp* http = 0;
  struct event_base* base = 0;

  // Redirect libevent's logging to our own log
  // event_set_log_callback(&libevent_log_cb);

  base = event_base_new(); // XXX RAII
  if (!base) {
      syslog(LOG_ERR, "Couldn't create an event_base: exiting");
      return false;
  }

  /* Create a new evhttp object to handle requests. */
  http = evhttp_new(base); // XXX RAII
  if (!http) {
      syslog(LOG_ERR, "couldn't create evhttp. Exiting.");
      event_base_free(base);
      return false;
  }

  // Bind addresses
  int defaultPort = 5005;
  std::vector<std::pair<std::string, uint16_t> > endpoints;
  endpoints.push_back(std::make_pair("::1", defaultPort));
  endpoints.push_back(std::make_pair("127.0.0.1", defaultPort));

  for (std::vector<std::pair<std::string, uint16_t> >::iterator i = endpoints.begin(); i != endpoints.end(); ++i) {
    evhttp_bound_socket *bind_handle = evhttp_bind_socket_with_handle(http, i->first.empty() ? NULL : i->first.c_str(), i->second);
    if (bind_handle) {
        boundSockets.push_back(bind_handle);
    } else {
        std::string s = "Binding RPC on address " + i->first + " port " + std::to_string(i->second) + " failed.\n";
        syslog(LOG_ERR, s.c_str());
        return false;
    }
  }

  // Enter daemon loop
  uint c = 0;
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

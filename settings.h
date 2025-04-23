#ifndef SETTINGS_CMXSAFE
#define SETTINGS_CMXSAFE
  // Define timeout as unsigned int
  #define TIMEOUT_SECONDS 10  // Timeout only during login phase
  #define SSH_REMOTE_HOST "172.20.10.4"  // Replace with your SSH server's IP or hostname
  #define SSH_LOCAL_HOST "127.0.0.1"  // Replace with your SSH local IP or hostname
  #define SSH_REMOTE_PORT 2233                  // SSH server port
  #define USERNAME1 "user"      // SSH username
  #define PASSWORD1 "password"      // SSH password (optional if using key authentication)
  #define VERBOSITY SSH_LOG_NOLOG;
  #define SSHMULTICHANNEL 0;  //Multichannel in a single session is still not stable
#endif

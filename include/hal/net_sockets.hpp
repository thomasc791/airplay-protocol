#pragma once

#ifdef ESP_PLATFORM
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#endif

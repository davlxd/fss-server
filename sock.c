/*
 * network manipulate functions
 *
 * Copyright (c) 2010, 2011 lxd <edl.eppc@gmail.com>
 * 
 * This file is part of File Synchronization System(fss).
 *
 * fss is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, 
 * (at your option) any later version.
 *
 * fss is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with fss.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "fss.h"
#include "sock.h"

int fss_listen(int *listenfd)
{
  int rv;
  struct addrinfo hints, *result;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((rv = getaddrinfo(NULL, PORT_STR, &hints, &result)) != 0) {
    fprintf(stderr,
	    "@fss_listen(): getaddrinfo() fails: %s\n",
	    gai_strerror(rv));
    return 1;
  }

  if ((*listenfd = socket(result->ai_family, result->ai_socktype,
			  result->ai_protocol)) < 0) {
    perror("@fss_listen(): socket() fails");
    return 1;
  }

  int opt = SO_REUSEADDR;
  if (setsockopt(*listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))
      < 0) {
    perror("@fss_listen(): setsockopt() fails");
    return 1;
  }

  if (bind(*listenfd, result->ai_addr, result->ai_addrlen) < 0) {
    perror("@fss_listen(): bind() fails");
    return 1;
  }

  if (listen(*listenfd, LISTENQ) < 0) {
    perror("@fss_listen(): listen() fails");
    return 1;
  }

  freeaddrinfo(result);

  return 0;
}

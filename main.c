/*
 * main() 
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

#include "sock.h"
#include "protocol.h"
#include "client.h"
#include "params.h"
#include "files.h"
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdio.h>
extern int errno;


int main(int argc, char **argv)
{
  char path[VALUE_LEN];
  int listenfd;

  setbuf(stdout, NULL);
  
  if (get_param_value("Path", path)) {
    perror("@main(): get_param_value Path fails\n");
    exit(0);
  }
  if (set_rootpath(path)) {
    fprintf(stderr, "@main(): set_rootpath() failed");
    return 1;
  }

  if (update_files()) {
    fprintf(stderr, "@main(): update_files() fails");
    return 1;
  }

  if (fss_listen(&listenfd)) {
    fprintf(stderr,
	    "@main(): fss_listen() fails\n");
    return 1;
  }

  if (server_polling(&listenfd)) {
    fprintf(stderr,
	    "@main(): server_polling() failed\n");
    return 1;
  }
}
    
  
  

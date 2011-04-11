/*
 * core
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

#include "protocol.h"


int server_polling(int *listenfd)
{

  int i;
  int n, len;
  fd_set rset;

  char buf[BUF_LEN];

  if (remove_del_index_file()) {
    fprintf(stderr, "@server_polling(): remove_del_index_file() failed\n");
    return 1;
  }
  maxfd = *listenfd;
  maxi = -1;
  lock = -1;

  for (i = 0; i < CLIENTS_NUM ; i++) {
    clients[i].sockfd = -1;
    clients[i].status = WAIT_DEL_IDX_INFO_OR_ENTRY_INFO;
    clients[i].line_num = 0;
    memset(clients[i].rela_name, 0, strlen(clients[i].rela_name));
    clients[i].req_sz = 0;
  }

  FD_ZERO(&allset);
  FD_SET(*listenfd, &allset);

  while(1) {
    rset = allset;
    printf("\n>>>> block at select()  \n");
    if ((n = select(maxfd+1, &rset, NULL, NULL, NULL)) < 0) {
      perror("@server_polling(): select failed");
      return 1;
    }
    printf(">>>> select() returns\n");

    if (FD_ISSET(*listenfd, &rset)) {
      if (handle_listenfd(listenfd)) {
	fprintf(stderr, "@server_polling(): handle_listenfd() failed\n");
	return 1;
      }
    }

    for (i = 0; i <= maxi; i++) {
      if (clients[i].sockfd < 0)
	continue;
      if (FD_ISSET(clients[i].sockfd, &rset))
	printf(">>>> clinets[%d].sockfd readable\n", i);

      if ((lock < 0 || lock == i) && FD_ISSET(clients[i].sockfd, &rset)) {
	printf(">>>> client[%d].sockfd readable, add hold the lock\n", i);
	if (handle_client(i)) {
	  fprintf(stderr, "@server_polling(): handle_client(%d) failed\n",
		  i);
	  return 1;
	}
      }
      
    } //for(i = 0; i <= maxi; i++)
    
  } //while(1)
    

  return 0;
}

static int handle_listenfd(int *listenfd)
{
  int connfd;
  int i;
  struct sockaddr client_addr;
  socklen_t clilen;

	  
  clilen = sizeof(struct sockaddr);
  connfd = accept(*listenfd, &client_addr, &clilen);
  if (send_sha1_fss_info(connfd, SHA1_FSS_INFO, 0)) {
    fprintf(stderr, "@handle_listenfd(): send_sha1_file_info() failed\n");
    return 1;
  }
  
  for (i = 0; i < CLIENTS_NUM; i++) 
    if (clients[i].sockfd < 0) {
      clients[i].sockfd = connfd;
      clients[i].status = WAIT_MSG_CLI_REQ_SHA1_FSS;
      break;
    }
  lock = i;
  
  printf(">>>> client[%d], %d, connected, sha1.fss's size sent\n",
	 i, clients[i].sockfd);
  printf(">>>> lock set to %d\n", i);
  
  if (i == CLIENTS_NUM) {
    fprintf(stderr, "WARNING: TOO MANY clients, abort\n");
    return 0;
  }

  FD_SET(connfd, &allset);
  if (connfd > maxfd)
    maxfd = connfd;

  if (i > maxi)
    maxi = i;

  return 0;

}

static int reset_client(int i)
{
  // if (...) is unnecessry
  if (lock == i)
    lock = -1;
  
  clients[i].status = WAIT_DEL_IDX_INFO_OR_ENTRY_INFO;
  printf(">>>> client[%d]           reset\n",i);
  clients[i].line_num = 0;
  memset(clients[i].rela_name, 0, strlen(clients[i].rela_name));
  clients[i].req_sz = 0;

  return 0;
}


static int handle_client(int i)
{
  switch(clients[i].status) {
    
  case WAIT_MSG_CLI_REQ_SHA1_FSS:
    if (status_WAIT_MSG_CLI_REQ_SHA1_FSS(i)) {
      fprintf(stderr,
	      "@handle_clinet(): "\
	      "status_WAIT_MSG_CLI_REQ_SHA1_FSS() failed\n");
      return 1;
    }
    break;


    /* DONE
     * FIN
     * LINE_NUM ...
     * FILE_INFO ...
     * DEL_IDX_INFO ..
     */
  case WAIT_XXX:
    if (status_WAIT_XXX(i)) {
      fprintf(stderr,
	      "@handle_clinet(): "\
	      "status_XXX() failed\n");
      return 1;
    }
    break;


  case WAIT_MSG_CLI_REQ_FILE:
    if (status_WAIT_MSG_CLI_REQ_FILE(i)) {
      fprintf(stderr,
	      "@handle_client(): status_WAIT_MSG_CLI_REQ_FILE() failed\n");
      return 1;
    }
   
    break;


  case WAIT_MSG_DONE_OR_LINE_NUM:
    if (status_WAIT_MSG_DONE_OR_LINE_NUM(i)) {
      fprintf(stderr,
	      "@handle_client(): "\
	      "status_WAIT_MSG_DONE_OR_LINE_NUM() failed\n");
      return 1;
    }
    break;


  case WAIT_FILE:
    if (status_WAIT_FILE(i)) {
      fprintf(stderr,
	      "@handle_client(): status_WAIT_FILE() failed\n");
      return 1;
    }
    break;


  case WAIT_MSG_CLI_REQ_SHA1_FSS_INFO_OR_ENTRY_INFO:
    if (status_WAIT_MSG_CLI_REQ_SHA1_FSS_INFO_OR_ENTRY_INFO(i)) {
      fprintf(stderr,
	      "@handle_client(): "\
	      "status_WAIT_MSG_CLI_REQ_SHA1_FSS_INFO_OR_ENTRY_INFO() " \
	      "failed\n");
      return 1;
    }
    break;


  case WAIT_DEL_IDX_INFO_OR_ENTRY_INFO:
    if (status_WAIT_DEL_IDX_INFO_OR_ENTRY_INFO(i)) {
      fprintf(stderr,
	      "@handle_client(): "\
	      "status_WAIT_DEL_IDX_INFO_OR_ENTRY_INFO() failed\n");
      return 1;
    }
    break;


  case WAIT_DEL_IDX:
    if (status_WAIT_DEL_IDX(i)) {
      fprintf(stderr,
	      "@handle_client(): status_WAIT_DEL_IDX() failed\n");
      return 1;
    }
    break;


  default:
    fprintf(stderr,
	    "@handle_client(): unknow status %d captured from %d\n",
	    clients[i].status, i);
    return 1;
  }

  return 0;
}


static int status_WAIT_MSG_CLI_REQ_SHA1_FSS(int i)
{
  printf(">>>> ---> WAIT_MSG_CLI_REQ_SHA1_FSS\n");
  char buf[MAX_PATH_LEN];
  int rv, rvv;
  
  if ((rv = receive_line(i, buf, MAX_PATH_LEN)) == 1) {
    fprintf(stderr,
	    "@status_WAIT_MSG_CLI_REQ_SHA1_FSS(): :"\
	    "receive_line() failed\n");
    return 1;
    // receive 0 byte, means client disconnetced 
  } else if (rv == 2)
    return 0;

  if (strncmp(buf, CLI_REQ_SHA1_FSS, strlen(buf)) == 0) {
    if (send_sha1_fss(clients[i].sockfd)) {
      fprintf(stderr,
	      "@status_WAIT_MSG_CLI_REQ_SHA1_FSS(): "\
	      "send_sha1_file() failed\n");
      return 1;
    }
    clients[i].status = WAIT_XXX;
    printf(">>>> sha1.fss sent, status set to ---> WAIT_XXX\n");
  } else {
    printf("WARNING: client[%d] current status " \
	   "WAIT_MSG_CLI_REQ_SHA1_FSS received invalid message: %s\n",
	   i, buf);
    return 0;
  }
  return 0;
}


/* DONE
 * FIN
 * LINE_NUM ...
 * FILE_INFO ...
 * DEL_IDX_INFO ..
 */
static int status_WAIT_XXX(int i)
{
  printf(">>>> ---> WAIT_XXX\n");
  int rv, rvv;
  long linenum;
  char buf[MAX_PATH_LEN];
  
  if ((rv = receive_line(i, buf, MAX_PATH_LEN)) == 1) {
    fprintf(stderr,
	    "@status_WAIT_XXX(): receive_line() failed\n");
    return 1;

  } else if (rv == 2)
    return 0;

  if (strncmp(buf, DONE, strlen(buf)) == 0) {
    if (reset_client(i)) {
      fprintf(stderr,
	      "@status_WAIT_XXX(): reset_client[%d] failed\n", i);
      return 1;
    }
    printf(">>>> client[%d] sent DONE\n", i);

  } else if (strncmp(buf, FIN, strlen(buf)) == 0) {
    if (reset_client(i)) {
      fprintf(stderr,
	      "@status_WAIT_XXX(): reset_client[%d] failed\n", i);
      return 1;
    }
    printf(">>>> client[%d] sent FIN\n", i);

    if (broadcast(i)) {
      fprintf(stderr,
	      "@status_WAIT_XXX(): broadcast failed\n", i);
      return 1;
    }

  } else if (strncmp(buf, LINE_NUM, strlen(LINE_NUM)) == 0) {
    lock = i;
    printf(">>>> lock on \n");

    printf(">>>> client[%d] sent LINE_NUM...\n", i);
    linenum = strtol(buf+strlen(LINE_NUM), NULL, 10);
    if (linenum == 0) {
      perror("@status_WAIT_XXX(): strtol() failed");
      return 1;
    }
    if ((rvv = send_entryinfo_via_linenum(clients[i].sockfd, linenum,
					  FILE_INFO, DIR_INFO)) == 1) {
      fprintf(stderr,
	      "@status_WAIT_XXX(): send_entryinfo_via_linenum() failed\n");
      return 1;
      
    } else if (rvv == 0) {
    clients[i].line_num = linenum;
    clients[i].status = WAIT_MSG_CLI_REQ_FILE;

    } else if (rvv == 2) {
      clients[i].status = WAIT_MSG_DONE_OR_LINE_NUM;
    }


  } else if (strncmp(buf, DIR_INFO, strlen(DIR_INFO)) == 0) {
    char *token;
    token = strtok(buf+strlen(DIR_INFO), "\n");
    if (create_dir(token)) {
      fprintf(stderr,
	      "@status_XXX(): create_dir() failed\n");
      return 1;
    }

    if (send_msg(clients[i].sockfd, SER_RECEIVED)) {
      fprintf(stderr,
	      "@status_XXX send_msg() failed\n");
      return 1;
    }

    clients[i].status = WAIT_MSG_CLI_REQ_SHA1_FSS_INFO_OR_ENTRY_INFO;
      
  } else if (strncmp(buf, FILE_INFO, strlen(FILE_INFO)) == 0) {
    lock = i;
    if (set_fileinfo(i, buf+strlen(FILE_INFO))) {
      fprintf(stderr,
	      "@status_WAIT_XXX(): set_fileinfo() failed\n");
      return 1;
    }
    printf(">>>> fileinfo setted\n");
    if (send_msg(clients[i].sockfd, SER_REQ_FILE)) {
      fprintf(stderr,
	      "@status_WAIT_XXX(): send_msg() failed\n");
      return 1;
    }

    if (clients[i].req_sz == 0 ) {
      if (status_WAIT_FILE(i)) {
	fprintf(stderr,
		"@status_WAIT_XXX(): status_WAIT_FILE() failed\n");
	return 1;
      }
    } else 
      clients[i].status = WAIT_FILE;

    printf(">>>> SER_REQ_FILE sent\n"); 

  } else if (strncmp(buf, DEL_IDX_INFO, strlen(DEL_IDX_INFO)) == 0) {
    lock = i;
    if (set_fileinfo(i, buf+strlen(DEL_IDX_INFO))) {
      fprintf(stderr, "@status_WAIT_XXX(): set_fileinfo() failed\n");
      return 1;
    }
    printf(">>>> del_index info set\n");
        
    if (send_msg(clients[i].sockfd, SER_REQ_DEL_IDX)) {
      fprintf(stderr,
	      "@status_WAIT_XXX(): send_msg() failed\n");
      return 1;
    }

    if (clients[i].req_sz == 0) {
      if (status_WAIT_DEL_IDX(i)) {
	fprintf(stderr,
		"status_WAIT_XXX(): status_WAIT_DEL_IDX() failed\n");
	return 1;
      }
    } else 
      clients[i].status = WAIT_DEL_IDX;

    printf(">>>>> SER_REQ_DEL_IDX sent\n"); 

  } else {
    printf("WARNING: client[%d] current status WAIT_XXX "\
	   "received invalid message: %s\n",
	   i, buf);
    return 0;
  }
  return 0;
}


static int status_WAIT_MSG_CLI_REQ_FILE(int i)
{
  printf(">>>> ---> WAIT_MSG_CLI_REQ_FILE\n");

  int rv, rvv;
  char buf[MAX_PATH_LEN];
  
  if ((rv = receive_line(i, buf, MAX_PATH_LEN)) == 1) {
    fprintf(stderr,
	    "@status_WAIT_MSG_CLI_REQ_FILE(): receive_line() failed\n");
    return 1;

  } else if (rv == 2)
    return 0;

  if (strncmp(buf, CLI_REQ_FILE, strlen(CLI_REQ_FILE)) == 0) {
    if (send_file_via_linenum(clients[i].sockfd, clients[i].line_num)) {
      fprintf(stderr,
	      "@status_WAIT_MSG_CLI_REQ_FILE(): send_sha1_file() failed\n");
      return 1;
    }
    clients[i].status = WAIT_MSG_DONE_OR_LINE_NUM;
    printf(">>>> FILE %s sent\n", clients[i].rela_name); 

  } else {
    printf("WARNING: client[%d] current status " \
	   "WAIT_MSG_CLI_REQ_FILE received invalid message: %s\n",
	   i, buf);
    return 0;
  }
  return 0;
}

static int status_WAIT_MSG_DONE_OR_LINE_NUM(int i)
{
  printf(">>>> ---> WAIT_MSG_DONE_OR_LINE_NUM\n");

  int rv, rvv;
  long linenum;
  char buf[MAX_PATH_LEN];
  
  if ((rv = receive_line(i, buf, MAX_PATH_LEN)) == 1) {
    fprintf(stderr, "@status_WAIT_MSG_DONE_OR_LINE_NUM(): "\
	    "receive_line() failed\n");
    return 1;

  } else if (rv == 2)
    return 0;

  if (strncmp(buf, DONE, strlen(buf)) == 0) {
    if (reset_client(i)) {
      fprintf(stderr,
	      "@status_WAIT_MSG_DONE_OR_LINE_NUM(): "
	      "reset_client[%d] failed\n", i);
      return 1;
    }
    printf(">>>> client[%d] sent DONE\n", i); 
      
  } else if (strncmp(buf, LINE_NUM, strlen(LINE_NUM)) == 0) {
    linenum = strtol(buf+strlen(LINE_NUM), NULL, 10);
    if (linenum == 0) {
      perror("@status_WAIT_MSG_DONE_OR_LINE_NUM(): strtol() failed");
      return 1;
    }
    if ((rvv = send_entryinfo_via_linenum(clients[i].sockfd, linenum,
					  FILE_INFO, DIR_INFO)) == 1) {
      fprintf(stderr,
	      "@status_WAIT_MSG_DONE_OR_LINE_NUM(): "
	      "send_entryinfo_via_linenum() failed\n");
      return 1;

    } else if (rvv == 0) {
      clients[i].line_num = linenum;
      clients[i].status = WAIT_MSG_CLI_REQ_FILE;

    } else if (rvv == 2) {
      clients[i].status = WAIT_MSG_DONE_OR_LINE_NUM;
    }

      
  } else {
    printf("WARNING: client[%d] current status " \
	   "WAIT_MSG_DONE_OR_LINE_NUM_OR_FILE_INFO "\
	   "received invalid message: %s\n",
	   i, buf);
    return 0;
  }
  
  return 0;
}

static int status_WAIT_FILE(int i)
{
  printf(">>>> ---> WAIT_FILE\n");

  if (receive_common_file(clients[i].sockfd,
			  clients[i].rela_name,
			  clients[i].req_sz)) {
    fprintf(stderr, "@status_WAIT_FILE(): "
	    "receive_common_file() failed\n");
    return 1;
  }
  printf(">>>> file received\n");
  if (send_msg(clients[i].sockfd, SER_RECEIVED)) {
    fprintf(stderr,
	    "@status_WAIT_FILE(): send_msg() failed\n");
    return 1;
  }
  clients[i].status = WAIT_MSG_CLI_REQ_SHA1_FSS_INFO_OR_ENTRY_INFO;
  printf(">>>> SER_RECEIVED sent to client[%d]\n", i); 
  return 0;
}


static int status_WAIT_MSG_CLI_REQ_SHA1_FSS_INFO_OR_ENTRY_INFO(int i)
{
  int rv;
  char buf[MAX_PATH_LEN];

  if ((rv = receive_line(i, buf, MAX_PATH_LEN)) == 1) {
    fprintf(stderr, "@status_WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO(): "\
	    "receive_line() failed\n");
    return 1;

  } else if (rv == 2)
    return 0;

  if (strncmp(buf, CLI_REQ_SHA1_FSS_INFO, strlen(buf)) == 0) {

    if (update_files()) {
      fprintf(stderr, "@status_WAIT_MSG_CLI_REQ_SHA1_FSS_INFO" \
	      "_OR_ENTRY_INFO(): update_files() failed\n");
      return 1;
    }

    if (send_sha1_fss_info(clients[i].sockfd, SHA1_FSS_INFO, 1)) {
      fprintf(stderr,
	      "@status_WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO(): "\
	      "send_sha1_file_info() failed\n");
      return 1;
    }

    clients[i].status = WAIT_MSG_CLI_REQ_SHA1_FSS;
    printf(">>>> clinets[%d] status set to ---> WAIT_MSG_CLI_REQ_SHA1_FSS\n", i);

  } else if (strncmp(buf, DIR_INFO, strlen(DIR_INFO)) == 0) {
    char *token;
    token = strtok(buf+strlen(DIR_INFO), "\n");
    if (create_dir(token)) {
      fprintf(stderr,
	      "@status_WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO():" \
	      "create_dir() failed\n");
      return 1;
    }

    if (send_msg(clients[i].sockfd, SER_RECEIVED)) {
      fprintf(stderr,
	      "@status_WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO():" \
	      "send_msg() failed\n");
      return 1;
    }

    clients[i].status = WAIT_MSG_CLI_REQ_SHA1_FSS_INFO_OR_ENTRY_INFO;
      
  } else if (strncmp(buf, FILE_INFO, strlen(FILE_INFO)) == 0) {

    if (set_fileinfo(i, buf+strlen(FILE_INFO))) {
      fprintf(stderr,
	      "@status_WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO(): "\
	      "set_fileinfo() failed\n");
      return 1;
    }
    printf(">>>> fileinfo setted\n"); 
    if (send_msg(clients[i].sockfd, SER_REQ_FILE)) {
      fprintf(stderr,
	      "@status_WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO(): " \
	      "send_msg() failed\n");
      return 1;
    }

    if (clients[i].req_sz == 0 ) {
      if (status_WAIT_FILE(i)) {
	fprintf(stderr,
		"@status_WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO(): "\
		"status_WAIT_FILE() failed\n");
	return 1;
      }
    } else 
      clients[i].status = WAIT_FILE;
    
    printf(">>>> SER_REQ_FILE sent\n");

  } else {
    printf("WARNING: client[%d] current status "	\
	   "WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO " \
	   "received invalid message: %s\n",
	   i, buf);
    return 0;
  }
   
  return 0;
}

static int status_WAIT_DEL_IDX_INFO_OR_ENTRY_INFO(int i)
{
  printf(">>>> ---> IN status_WAIT_DEL_IDX_INFO_OR_ENTRY_INFO\n");
  
  int rv, rvv;
  off_t del_index_size;
  char buf[MAX_PATH_LEN];
  
  if ((rv = receive_line(i, buf, MAX_PATH_LEN)) == 1) {
    fprintf(stderr, "@status_WAIT_DEL_IDX_INFO_OR_ENTRY_INFO(): "\
	    "receive_line() failed\n");
    return 1;

  } else if (rv == 2)
    return 0;

  if (strncmp(buf, DEL_IDX_INFO, strlen(DEL_IDX_INFO)) == 0) {

    lock = i;
    printf(">>>> lock set to %d\n", i);

    if (set_fileinfo(i, buf+strlen(DEL_IDX_INFO))) {
      fprintf(stderr,
	      "@status_WAIT_DEL_IDX_INFO_OR_ENTRY_INFO(): " \
	      "set_fileinfo() failed\n");
      return 1;
    }
    printf(">>>> del index info setted\n");
    
    if (send_msg(clients[i].sockfd, SER_REQ_DEL_IDX)) {
      fprintf(stderr,
	      "@status_WAIT_DEL_IDX_INFO_OR_ENTRY_INFO(): "\
	      "send_msg() failed\n");
      return 1;
    }

    if (clients[i].req_sz == 0) {
      if (status_WAIT_DEL_IDX(i)) {
	fprintf(stderr,
		"status_WAIT_DEL_IDX_INFO_OR_ENTRY_INFO(): " \
		"status_WAIT_DEL_IDX() failed\n");
	return 1;
      }
    } else 
      clients[i].status = WAIT_DEL_IDX;

    printf(">>>>> SER_REQ_DEL_IDX sent\n");

  } else if (strncmp(buf, DIR_INFO, strlen(DIR_INFO)) == 0) {
    lock = i;
    char *token;
    token = strtok(buf+strlen(DIR_INFO), "\n");
    if (create_dir(token)) {
      fprintf(stderr,
	      "@status_WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO():" \
	      "create_dir() failed\n");
      return 1;
    }

    if (send_msg(clients[i].sockfd, SER_RECEIVED)) {
      fprintf(stderr,
	      "@status_WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO():" \
	      "send_msg() failed\n");
      return 1;
    }

    clients[i].status = WAIT_MSG_CLI_REQ_SHA1_FSS_INFO_OR_ENTRY_INFO;
    
  } else if (strncmp(buf, FILE_INFO, strlen(FILE_INFO)) == 0) {

    lock = i;
    printf(">>>> lock set to %d\n", i);
    
    if (set_fileinfo(i, buf+strlen(FILE_INFO))) {
      fprintf(stderr,
	      "@status_WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO(): "\
	      "set_fileinfo() failed\n");
      return 1;
    }
    printf(">>>> fileinfo setted\n"); 
    if (send_msg(clients[i].sockfd, SER_REQ_FILE)) {
      fprintf(stderr,
	      "@status_WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO(): " \
	      "send_msg() failed\n");
      return 1;
    }

    if (clients[i].req_sz == 0 ) {
      if (status_WAIT_FILE(i)) {
	fprintf(stderr,
		"@status_WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO(): "\
		"status_WAIT_FILE() failed\n");
	return 1;
      }
    } else 
      clients[i].status = WAIT_FILE;
    
    printf(">>>> SER_REQ_FILE sent\n"); 

  } else {
    printf("WARNING: client[%d] current status " \
	   "WAIT_MSG_CLI_REQ_SHA1_FSS_OR_ENTRY_INFO "\
	   "received invalid message: %s\n",
	   i, buf);
    return 0;
  }

  return 0;
}


static int status_WAIT_DEL_IDX(int i)
{
  printf(">>>> ---> WAIT_DEL_IDX\n");

  if (receive_del_index_file(clients[i].sockfd, clients[i].req_sz)) {
    fprintf(stderr,
	    "@status_WAIT_DEL_IDX(): receive_del_index_file() failed\n");
    return 1;
  }
  printf(">>>> del_index_file received\n");

  if (remove_files()) {
    fprintf(stderr, "@status_WAIT_DEL_IDX(): remove_files() failed\n");
    return 1;
  }
  printf(">>>> remove_files()      done\n"); 

  if (remove_del_index_file()) {
    fprintf(stderr,
	    "@status_WAIT_DEL_IDX(): remove_del_index_file() failed\n");
    return 1;
  }
  printf(">>>> remove_del_index_file()     done\n");

  if (update_files()) {
    fprintf(stderr, "@status_WAIT_DEL_IDX(): udpate_files() failed\n");
    return 1;
  }

  if (send_sha1_fss_info(clients[i].sockfd, SHA1_FSS_INFO, 1)) {
    fprintf(stderr,
	    "@status_WAIT_DEL_IDX(): send_sha1_file_info() failed\n");
    return 1;
  }

  clients[i].status = WAIT_MSG_CLI_REQ_SHA1_FSS;
  printf(">>>> clinets[%d] status set to ---> WAIT_MSG_CLI_REQ_SHA1_FSS\n", i);

  /* if (reset_client(i)) { */
  /*   fprintf(stderr, */
  /* 	    "@status_WAIT_XXX(): reset_client[%d] failed\n", i); */
  /*   return 1; */
  /* } */

  /* if (broadcast(i)) { */
  /*   fprintf(stderr, */
  /* 	    "@status_WAIT_XXX(): broadcast failed\n", i); */
  /*   return 1; */
  /* } */

  return 0;
}


/* return 2 -> client disconnected */
static int receive_line(int i, char *text, int len)
{
  int n;

  //TODO: A while() should be place here, within MAX_PATH_LEN
  if ((n = read(clients[i].sockfd, text, len)) < 0) {
    perror("@receive_line(): read failed");
    return 1;
  }
  text[n] = 0;

  printf(">>>> receive_line received %s\n", text);
  if (n == 0) {
    printf(">>>>clients[%d], %d disconnecting...    ",
	   i, clients[i].sockfd); 
    
    reset_client(i);	
    FD_CLR(clients[i].sockfd, &allset);
    clients[i].sockfd = -1;

    printf("done\n"); 

    return 2;
  }

  return 0;
}

static int set_fileinfo(int i, char *buf)
{
  printf(">>>> In set_fileinfo string is %s", buf); 

  char *token;
  token = strtok(buf, "\n");
  if(strncpy(clients[i].rela_name, token, strlen(token)) == NULL) {
    perror("@set_fileinfo(): strncpy failed");
    return 1;
  }
  (clients[i].rela_name)[strlen(token)] = 0;
  token = strtok(NULL, "\n");
  token = strtok(NULL, "\n");
  
  /* Attention:
   * I assign off_t and time_t to long */
  errno = 0;
  clients[i].req_sz = strtol(token, NULL, 10);
  if (clients[i].req_sz == 0 && errno != 0) {
    fprintf(stderr, "@set_fileinfo(): strtol failed\n");
    return 1;
  }

  printf("    set\n"); 
  return 0;
  
}

static int broadcast(int except_index)
{
  int i;
  
  for (i = 0; i <= maxi; i++) {
    if (clients[i].sockfd < 0 || i == except_index)
      continue;
    else {
      if (send_sha1_fss_info(clients[i].sockfd, SHA1_FSS_INFO, 0)) {
	fprintf(stderr, "@broadcase: send_sha1_file_info() failed\n");
	return 1;
      }
      clients[i].status = WAIT_MSG_CLI_REQ_SHA1_FSS;
      printf(">>>> client[%d], broadcasted\n", i); 
    }
  }
  
  return 0;
}
  
  

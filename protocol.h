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

#ifndef _FSS_PROTOCOL_H_
#define _FSS_PROTOCOL_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include "client.h"
#include "files.h"

extern int errno;

#define CLIENTS_NUM 10

#ifndef BUF_LEN
#define BUF_LEN 4096
#endif

#ifndef MAX_PATH_LEN
#define MAX_PATH_LEN 1024
#endif


#define CLI_REQ_SHA1_FSS "A"
#define CLI_REQ_FILE "B"
#define SER_REQ_FILE "D"
#define SER_REQ_DEL_IDX "E"
#define SER_RECEIVED "F"
#define DONE "G"
#define SHA1_FSS_INFO "H"
#define LINE_NUM "I"
#define FILE_INFO "J"
#define DEL_IDX_INFO "K"
#define FIN "L"
#define CLI_REQ_SHA1_FSS_INFO "M"
#define DIR_INFO "N"


/* server*/
#define WAIT_MSG_CLI_REQ_SHA1_FSS 2
#define WAIT_XXX 4 // it waits MSG_DONE, LINE_NUM..., FILE_INFO..., DEL_INDEX_SZ...
#define WAIT_MSG_CLI_REQ_FILE 6
#define WAIT_MSG_DONE_OR_LINE_NUM 8
#define WAIT_FILE 10
#define WAIT_MSG_CLI_REQ_SHA1_FSS_INFO_OR_ENTRY_INFO 12
#define WAIT_DEL_IDX_INFO_OR_ENTRY_INFO 14
#define WAIT_DEL_IDX 16

// read-write lock, -1 means release, >=0 refers to clinet index
static int lock;
static client clients[CLIENTS_NUM];
static fd_set allset;
static int maxfd;
static int maxi;



int server_polling(int *listenfd);
static int handle_listenfd(int *listenfd);
static int reset_client(int i);
static int handle_client(int i);
static int status_WAIT_MSG_CLI_REQ_SHA1_FSS(int i);
static int status_WAIT_XXX(int i);
static int status_WAIT_MSG_CLI_REQ_FILE(int i);
static int status_WAIT_MSG_DONE_OR_LINE_NUM(int i);
static int status_WAIT_FILE(int i);
static int status_WAIT_MSG_CLI_REQ_SHA1_FSS_INFO_OR_ENTRY_INFO(int i);
static int status_WAIT_DEL_IDX_INFO_OR_ENTRY_INFO(int i);
static int status_WAIT_DEL_IDX(int i);
static int receive_line(int i, char *text, int len);
static int set_fileinfo(int i, char *buf);

static int broadcast(int except_index);

#endif

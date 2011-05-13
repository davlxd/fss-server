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

#define CLIENTS_NUM 10

#define CLI_REQ_HASH_FSS "A"
#define CLI_REQ_FILE "B"
#define SER_REQ_FILE "D"
#define SER_REQ_DEL_IDX "E"
#define SER_RECEIVED "F"
#define DONE "G"
#define HASH_FSS_INFO "H"
#define LINE_NUM "I"
#define FILE_INFO "J"
#define DEL_IDX_INFO "K"
#define FIN "L"
#define CLI_REQ_HASH_FSS_INFO "M"
#define DIR_INFO "N"
#define CHKSUM_INFO "O"


// status 
enum {
  WAIT_MSG_CLI_REQ_HASH_FSS = 2,
  // it waits MSG_DONE, LINE_NUM..., FILE_INFO..., DEL_INDEX_SZ...
  WAIT_XXX = 4,
  WAIT_MSG_CLI_REQ_FILE = 6,
  WAIT_MSG_DONE_OR_LINE_NUM = 8,
  WAIT_FILE = 10,
  WAIT_MSG_CLI_REQ_HASH_FSS_INFO_OR_ENTRY_INFO = 12,
  WAIT_DEL_IDX_INFO_OR_ENTRY_INFO = 14,
  WAIT_DEL_IDX = 16,
  ENTRY_INFO_SENT = 18

};

int server_polling(int *listenfd);


#endif

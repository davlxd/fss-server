/*
 * maintain .fss file in monitored direcotory
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

#include "files.h"

int set_rootpath(const char *root_path)
{
  size_t strncpy_len, str_len;
  struct stat statbuf;
  char fullpath[MAX_PATH_LEN];

  if (stat(root_path, &statbuf) < 0) {
    perror("Path cannot be stat()");
    return 1;
  }

  str_len = strlen(root_path);

  strncpy_len = root_path[str_len-1] == '/' ? str_len-1 : str_len;

  if (!strncpy(rootpath, root_path, strncpy_len)) {
    fprintf(stderr,
	    "@update_files(): fail to strncpy %s to rootpath: %s\n",
	    fullpath, strerror(errno));
    return 1;
  }
  rootpath[strlen(rootpath)] = 0;

  return 0;

}
  
int update_files()
{
  printf(">>>>> IN update_files()\n"); fflush(stdout);
  struct stat statbuf;
  char fullpath[MAX_PATH_LEN];
  char fullpath0[MAX_PATH_LEN]; //temp.sha1.fss
  char fullpath1[MAX_PATH_LEN]; //sha1.fss

  if (get_temp_sha1_fss(fullpath0)) {
    fprintf(stderr, "@update_files(): get_temp_sha1_fss() failed\n");
    return 1;
  }

  if (get_sha1_fss(fullpath1)) {
    fprintf(stderr, "@update_files(): get_sha1_fss() failed\n");
    return 1;
  }

  if (!strncpy(fullpath, rootpath, strlen(rootpath))) {
    perror("@update_files(): strncpy failed");
    return 1;
  }
  fullpath[strlen(rootpath)] = 0;

  if (get_fss_dir(fullpath)) {
    fprintf(stderr, "@update_files(): get_fss_dir() failed\n");
    return 1;
  }

  if (create_fss_dir(fullpath)) {
    fprintf(stderr,
	    "@update_files(): create_fss_dir(%s) fails\n",
	    fullpath);
    return 1;
  }
  
  if (connect_path(fullpath, FNAME_FSS)) {
    fprintf(stderr,
	    "@update_files(): connect_path(%s, %s) fails\n",
	    fullpath, FNAME_FSS);
    return 1;
  }
  
  if (!(fname_fss = fopen(fullpath, "w+"))) {
    fprintf(stderr, "@update_files(): fopen(%s) fails\n", fullpath);
    return 1;
  }

  disconnect_path(fullpath, FNAME_FSS);
  
  if (connect_path(fullpath, TEMP_SHA1_FSS)) {
    fprintf(stderr,
	    "@update_files(): connect_path(%s, %s) fails\n",
	    fullpath, TEMP_SHA1_FSS);
    return 1;
  }

  if (!(temp_sha1_fss = fopen(fullpath, "w+"))) {
    fprintf(stderr, "@update_files(): fopen(%s) fails\n", fullpath);
    return 1;
  }
  disconnect_path(fullpath, TEMP_SHA1_FSS);
  disconnect_path(fullpath, FSS_DIR);


  if (nftw(fullpath, write_in, 10, FTW_DEPTH) != 0) {
    perror("@update_files(): ftw() failed");
    return 1;
  }

  if (0 != fflush(fname_fss)) {
    perror("@update_files(): fflush(fname_fss) fails.");
    return 1;
  }
  
  if (0 != fclose(fname_fss)) {
    perror("@update_files(): fclose(fname_fss) fails.");
    return 1;
  }

  if (0 != fflush(temp_sha1_fss)) {
    perror("@update_files(): fflush(sha1_fss) fails.");
    return 1;
  }
  
  if (0 != fclose(temp_sha1_fss)) {
    perror("@update_files(): fclose(sha1_fss) fails.");
    return 1;
  }
  
  if (stat(fullpath1, &statbuf) < 0) {
    if (errno == ENOENT) {
      if (rename(fullpath0, fullpath1) < 0) {
	perror("@update_files(): rename fullpath0 to fullpath1 failed");
	return 1;
      }
      return 0;

    } else {
      perror("@update_files(): stat fullpath1 failed");
      return 1;
    }
  }

  char digest_temp[41];
  char digest_local[41];

  if (sha1_digest_via_fname(fullpath0, digest_temp)) {
    fprintf(stderr, "@update_files(): sha1_digest_via_fnme() failed\n");
    return 1;
  }
  if (sha1_digest_via_fname(fullpath1, digest_local)) {
    fprintf(stderr, "@update_files(): sha1_digest_via_fname() failed\n");
    return 1;
  }
  
  if (strncmp(digest_temp, digest_local, 40) == 0) {
    
    if (remove(fullpath0) < 0) {
      perror("@update_files(): remove fullpath0 failed");
      return 1;
    }
  } else {
    if (remove(fullpath1) < 0) {
      perror("@update_files(): remove fullpath1 failed");
      return 1;
    }
    if (rename(fullpath0, fullpath1) < 0) {
      perror("@update_files(): rename fullpath0 to fullpath1 failed");
      return 1;
    }
  }
  
  return 0;
}

static int connect_path(char *path0, const char *path1)
{
  char *ptr;
  //char *ptr1;
  ptr = path0 + strlen(path0);
  
  if (*(ptr-1) != '/') {
    *ptr++ = '/';
    *ptr = 0;
  }

  if (*path1 != '/') {
    if (!strncpy(ptr, path1, strlen(path1))) {
      fprintf(stderr,
	      "@connect_path(): fail to strncpy %s to %s: %s\n",
	      path1, path0, strerror(errno));
      return 1;
    }
    *(ptr+strlen(path1)) = 0;
    
  } else {
    //ptr1 = path1 + 1;  
    if (!strncpy(ptr, path1 + 1, strlen(path1) - 1)) {
      fprintf(stderr,
	      "@connect_path(): fail to strncpy %s to %s: %s\n",
	      path1 + 1, ptr, strerror(errno));
      return 1;
    }
    *(ptr+strlen(path1)-1) = 0;
  }

  return 0;
}

static int disconnect_path(char *path0, const char *path1)
{
  char *ptr;
  ptr = path0 + strlen(path0);
  *(ptr - strlen(path1) - 1) = 0;
  return 0;
}

static int write_in(const char *path, const struct stat *sb,
		    int flag, struct FTW *fb)
{
  int rv;
  /* if (EOF == fputc(0, sha1_fss)) { */
  /*   perror("@write_in(): fputc NULL fails."); */
  /*   return 1; */
  /* } */

  // escape rootpath
  if (strncmp(path, rootpath, strlen(path)) == 0)
    return 0;
  if (!INCLUDE_HIDDEN && strstr(path, "/."))
    return 0;
  if (strncmp(FSS_DIR, path+fb->base, strlen(FSS_DIR) == 0))
    return 0;

      
  char digest[41];

  if ((rv = sha1_digest_via_fname_fss(path, rootpath, digest)) == 1) {
    fprintf(stderr, "@write_in(): sha1_file(%s) fails\n",
	    path);
    return 1;
  }

  if (rv == 0) {
  
    if (EOF == fputs(path, fname_fss)) {
      perror("@write_in(): fputs fails.");
      return 1;
    }
    if (EOF == fputc('\n', fname_fss)) {
      perror("@write_in(): fputc() \\n fails.");
      return 1;
    }

    // first we write to temp_sha1_fss, for ...
    // refers to update_files()
    if (EOF == fputs(digest, temp_sha1_fss)) {
      perror("@write_in(): fputs fails.");
      return 1;
    }
    if (EOF == fputc('\n', temp_sha1_fss)) {
      perror("@write_in(): fputc() \\n fails.");
      return 1;
    }
  }

  return 0;
}
  
  
static int create_fss_dir(const char *path)
{
  struct stat statbuf;

  if (lstat(path, &statbuf) < 0) {
    if (errno == ENOENT ) {
      if (mkdir(path, 0770) < 0) {
	fprintf(stderr,
		"@create_fss_dir(): fail to mkdir(%s): %s\n",
		path, strerror(errno));
	return 1;
      }
      return 0;
      
    } else {
      fprintf(stderr,
	      "@create_fss_dir(): fail to lstat(%s): %s\n",
	      path, strerror(errno));
      return 1;
    }
  }

  if (!S_ISDIR(statbuf.st_mode)) {
    if (remove(path) < 0) {
      fprintf(stderr,
	      "@create_fss_dir(): fail to remove(%s): %s",
	      path, strerror(errno));
      return 1;
    }
    if (mkdir(path, 0770) < 0) {
      fprintf(stderr,
	      "@create_fss_dir(): fail to mkdir(%s): %s",
	      path, strerror(errno));
      return 1;
    }
  }

  return 0;
}

static int get_line(const char *fname, long linenum,
		    char *buffer, int maxlen)
{
  FILE *file;
  int c;
  int num;
  
  if (!(file = fopen(fname, "rb"))) {
    fprintf(stderr, "@get_line(): fopen(%s) fails\n", fname);
    return 1;
  }
  
  num = 0;
  while((num < (linenum-1)) && (c = getc(file)) != EOF)
    if (c == '\n')
      num++;

  if (fgets(buffer, maxlen, file) == NULL && ferror(file)) {
    perror("@get_line(): fgets() failed\n");
    return 1;
  }

  /* if..., actually it must be */
  if (buffer[strlen(buffer)-1] == '\n') {
    buffer[strlen(buffer)-1] = 0;
  }
    

  if (0 != fclose(file)) {
    perror("@get_line(): fclose(file) failed");
    return 1;
  }

  return 0;
}

/* assume rela_path is big enought*/
static int get_rela_path(const char *fullpath, char *rela_path)
{
  size_t len;
  /* minus 1 means omit '/' between rootpath and rela_path */
  len = strlen(fullpath) - strlen(rootpath) -1;
  
  if (strncpy(rela_path,
	      fullpath+strlen(rootpath)+1,
	      len) == NULL) {
    perror("@get_rela_path(): strncpy() failed");
    return 1;
  }
  rela_path[len]= 0;
  
  return 0;
}


int remove_files()
{
  printf(">>>> IN remove_files\n");
  char fullpath0[MAX_PATH_LEN]; // del.index
  char fullpath1[MAX_PATH_LEN]; // fname.fss
  char buf[MAX_PATH_LEN];
  char record[MAX_PATH_LEN];
  long linenum_to_delete;
  struct stat statbuf;
  FILE *file;

  if (get_del_index(fullpath0)) {
    fprintf(stderr, "@remove_files(): get_del_index() failed\n");
    return 1;
  }
  if (get_fname_fss(fullpath1)) {
    fprintf(stderr, "@remove_files(): get_del_index() failed\n");
    return 1;
  }

  if (stat(fullpath0, &statbuf) < 0) {
    perror("@remove_files(): stat failed");
    return 1;
  }

  // if del.index.fss is empty
  if (statbuf.st_size == 0)
    return 0;

  if (!(file = fopen(fullpath0, "rb"))) {
    fprintf(stderr, "@remove_files(): fopen() failed\n");
    return 1;
  }

  while (fgets(buf, MAX_PATH_LEN, file) != NULL) {
    buf[strlen(buf)-1] = 0;
    if ((linenum_to_delete = strtol(buf, NULL, 10)) == 0) {
      perror("@remove_files(): strtol() failed");
      return 1;
    }

    if (get_line(fullpath1, linenum_to_delete, record, MAX_PATH_LEN)) {
      fprintf(stderr, "@remove_files(): get_line() failed\n");
      return 1;
    }

    if (stat(record, &statbuf) < 0) {
      perror("@remove_files(): stat failed\n");
      return 1;
    }
    if (S_ISDIR(statbuf.st_mode)) {
      if (remove_dir(record) < 0) {
	perror("@remove_files(): rmdir() failed\n");
	return 1;
      }
      continue;
    }

    if (remove(record) < 0 && errno !=ENOENT) {
      perror("@remove_files(): remove() failed");
      return 1;
    }
  }
  if (ferror(file)) {
    perror("@remove_files(): fgets() failed");
    return 1;
  }
  return 0;

}

int remove_del_index_file()
{
  char fullpath[MAX_PATH_LEN];

  if (get_del_index(fullpath)) {
    fprintf(stderr,
	    "@remove_del_index_file(): get_del_index() failed\n");
    return 1;
  }

  errno = 0;
  if (remove(fullpath) < 0 && errno != ENOENT) {
    perror("@remove_del_index_file(): remove fullpath failed");
    return 1;
  }

  return 0;
}



// if reset_mtime == 1, mtime = 1
int send_sha1_fss_info(int sockfd, const char *prefix,
		       int reset_mtime)
{
  char fullpath[MAX_PATH_LEN];

  if (get_sha1_fss(fullpath)) {
    fprintf(stderr, "@send_sha1_file_info(): get_sha1_fss() failed\n");
    return 1;
  }

  if (send_entryinfo(sockfd, fullpath, prefix, NULL, reset_mtime) == 1) {
    fprintf(stderr, "@send_sha1_file_size(): send_fileinfo() failed\n");
    return 1;
  }

  return 0;
}

int send_sha1_fss(int sockfd)
{
  char fullpath[MAX_PATH_LEN];

  if (get_sha1_fss(fullpath)) {
    fprintf(stderr, "@send_sha1_fss(): get_sha1_fss() failed\n");
    return 1;
  }

  if (send_file(sockfd, fullpath)) {
    fprintf(stderr, "@send_sha1_fss(): send_file() failed\n");
    return 1;
  }
  
  return 0;
}


int send_file_via_linenum(int sockfd, long linenum)
{

  char fullpath[MAX_PATH_LEN];
  char record[MAX_PATH_LEN];

  if (get_fname_fss(fullpath)) {
    fprintf(stderr, "@send_file_via_fname(): get_fname_fss() failed\n");
    return 1;
  }

  memset(record, 0, MAX_PATH_LEN);


  if (get_line(fullpath, linenum, record, MAX_PATH_LEN)) {
    fprintf(stderr, "@send_file_via_fname(): get_line() failed\n");
    return 1;
  }

  if (send_file(sockfd, record)) {
    fprintf(stderr, "@send_file_via_fname(): send_file() failed\n");
    return 1;
  }

  return 0;
}

int send_file(int sockfd, const char *fname)
{
  printf(">>>> IN send_file(), sending %s , size=%ld...", fname, size_to_send);

  char buf[BUF_LEN];
  size_t len;
  off_t size;
  FILE *file;

  if (!(file = fopen(fname, "rb"))) {
    fprintf(stderr, "@send_file(): fopen(%s) fails\n", fname);
    return 1;
  }

  size = 0;
  memset(buf, 0, BUF_LEN);
  while((size < size_to_send) &&
	(len = fread(buf, sizeof(char), BUF_LEN, file))) {
    size += len;
    if (write(sockfd, buf, len) < 0) {
      perror("@send_file(): write() fails");
      return 1;
    }
    memset(buf, 0, BUF_LEN);
  }

  printf("   DONE\n");
  
  if (0 != fclose(file)) {
    perror("@send_file(): fclose(file) fails.");
    return 1;
  }

  return 0;
}

/* return ...*/
int send_entryinfo_via_linenum(int sockfd, long linenum,
			       const char *prefix0, const char *prefix1)
{
  int rv;
  char fullpath[MAX_PATH_LEN];
  char record[MAX_PATH_LEN];


  if (get_fname_fss(fullpath)) {
    fprintf(stderr, "@send_file_via_fname(): get_fname_fss() failed\n");
    return 1;
  }


  memset(record, 0, MAX_PATH_LEN);
  if (get_line(fullpath, linenum, record, MAX_PATH_LEN)) {
    fprintf(stderr, "@send_file_via_fname(): get_line() failed\n");
    return 1;
  }

  if ((rv = send_entryinfo(sockfd, record, prefix0, prefix1, 0)) == 1) {
    fprintf(stderr, "@send_fileinfo_via_fname(): send_fileinfo() failed\n");
    return 1;

  } else if (rv == 2)
    return 2;
 
  return 0;
}

/* return 1 -> error
 * return 0 -> sent prefix0
 * return 2 -> sent prefix1
 */
int send_entryinfo(int sockfd, const char *fname,
		   const char *prefix0, const char *prefix1,
		   int reset_mtime)
{
  int rv;
  char rela_fname[MAX_PATH_LEN];
  char msg[MAX_PATH_LEN];
  struct stat statbuf;
  int len, str_len;

  if (stat(fname, &statbuf) < 0) {
    perror("@send_fileinfo_via_fname(): stat failed");
    return 1;
  }

  if (S_ISDIR(statbuf.st_mode)) {
    if (strncpy(msg, prefix1, strlen(prefix1)) == NULL) {
      perror("@send_entryinfo(): strncpy() failed");
      return 1;
    }
    msg[strlen(prefix1)] = 0;   rv = 2;

  } else {
    if (strncpy(msg, prefix0, strlen(prefix0)) == NULL) {
      perror("@send_entryinfo(): strncpy() failed");
      return 1;
    }
    msg[strlen(prefix0)] = 0;   rv = 0;
  }
  
  if (get_rela_path(fname, rela_fname)) {
    fprintf(stderr, "@send_fileinfo(): get_rela_path() failed\n");
    return 1;
  }

  str_len = strlen(msg);
  if (!strncpy(msg+str_len, rela_fname, strlen(rela_fname))) {
    fprintf(stderr, "@send_file_via_fname(): strncpy() failed");
    return 1;
  }
  msg[str_len+strlen(rela_fname)] = 0;
  
  str_len = strlen(msg);
  if (reset_mtime) {
    if ((len = snprintf(msg + str_len,
			BUF_LEN-str_len,
			"\n%ld", (time_t)1)) < 0) {
      perror("@send_fileinfo(): snprintf() failed");
      return 1;
    }
    
  } else {
    if ((len = snprintf(msg + str_len,
			MAX_PATH_LEN - str_len,
			"\n%ld", statbuf.st_mtime)) < 0) {
      perror("@send_fileinfo(): snprintf() failed");
      return 1;
    }
    
  }
  msg[str_len + len] = 0;

  str_len = strlen(msg);
  if ((len = snprintf(msg + str_len,
		      MAX_PATH_LEN - str_len,
		      "\n%ld", statbuf.st_size)) < 0) {
    perror("@send_fileinfo(): snprintf() failed");
    return 1;
  }

  msg[str_len + len] = 0;

  if (send_msg(sockfd, msg)) {
    fprintf(stderr, "@send_fileinfo(): send_msg() failed\n");
    return 1;
  }

  size_to_send = statbuf.st_size;

  printf(">>>> just send --%s--\n", msg);

  return rv;
}

int send_msg(int sockfd, const char *msg)
{
  if(write(sockfd, msg, strlen(msg)) < 0) {
    perror("@send_msg(): write() failed");
    return 1;
  }

  return 0;
}



int receive_del_index_file(int sockfd, off_t sz)
{
  char fullpath[MAX_PATH_LEN];

  if (get_del_index(fullpath)) {
    fprintf(stderr, "@receive_del_index_file(): get_del_index() failed\n");
    return 1;
  }

  if (receive_file(sockfd, fullpath, sz)) {
    fprintf(stderr, "@recive+sha1_file(): receive_file() fail\n");
    return 1;
  }
  return 0;
}

int receive_common_file(int sockfd, const char *rela_fname, off_t sz)
{
  char fullpath[MAX_PATH_LEN];
  char relaname[MAX_PATH_LEN];
  struct stat statbuf;
  char *token, *token1;
  mode_t default_mode;

  if (!strncpy(fullpath, rootpath, strlen(rootpath))) {
    perror("@receive_common_file(): strncpy rootpath to fullpath failed");
    return 1;
  }
  fullpath[strlen(rootpath)] = 0;

  /* set default mode_t */
  if (stat(fullpath, &statbuf) < 0) {
    perror("@receive_common_file(): stat failed");
    return 1;
  }
  default_mode = statbuf.st_mode;

  if (!strncpy(relaname, rela_fname, strlen(rela_fname))) {
    perror("@receive_common_file(): strncpy rela_fname to relaname failed");
    return 1;
  }
  relaname[strlen(rela_fname)] = 0;

  /* the following code mkdir if specific dir dosen't exist
   * token1 is next token of token,
   * if token1 is NULL, so token should be a file name,
   * then folowing  if-dir-exsist-judge-algorithm
   * should not include this particular token, so escape while() */
  token = strtok(relaname, "/");
  token1 = strtok(NULL, "/");
  while(token && token1) {
    if (connect_path(fullpath, token)) {
      fprintf(stderr, "@receive_common_file(): connect_path() failed\n");
      return 1;
    }
    if (stat(fullpath, &statbuf) < 0) {
      if (errno == ENOENT) {
	if (mkdir(fullpath, default_mode) < 0) {
	  perror("@receive_common_file(): mkdir() failed");
	  return 1;
	}
	printf(">>>> mkdir %s done\n", fullpath);
      } else {
	perror("@receive_common_file(): stat() failed\n");
	return 1;
      }
    }
    token = token1;
    token1 = strtok(NULL, "/");
  }
    
  if (connect_path(fullpath, token)) {
    fprintf(stderr, "@receive_common_file(): connect_path failed\n");
    return 1;
  }

  if (receive_file(sockfd, fullpath, sz)) {
    fprintf(stderr, "@recive_common_file(): receive_file() failed\n");
    return 1;
  }

  return 0;
}

int receive_file(int sockfd, const char *fname, off_t sz)
{
  printf(">>>> IN receive_file(), receving %s, sz %ld ....   ", fname, sz);
  char fullpath[MAX_PATH_LEN];
  char buf[BUF_LEN];
  ssize_t len;
  off_t size;
  FILE *file;

  if (!(file = fopen(fname, "w+"))) {
    fprintf(stderr,
	    "@receive_file(): fopen(%s) failed: %s\n",
	    fullpath, strerror(errno));
    return 1;
  }

  /* touch it if it is an empty file */
  if (sz == 0 ) {
    if (0 != fclose(file)) {
      perror("@receive_file(): fclose() failed");
      return 1;
    }
    return 0;
  }

  size = 0;
  memset(buf, 0, BUF_LEN);
  while((size < sz) && ((len = read(sockfd, buf, BUF_LEN)) > 0)) {
    size += len;
    if (fwrite(buf, sizeof(char), len, file) < len) {
      perror("@receive_file(): fwrite fails.");
      return 1;
    }
    memset(buf, 0, BUF_LEN);
  }
  printf("  DONE\n");
  if (len < 0) {
    perror("@receive_file(): read from socket fails");
    return 1;
  }
  
  if (0 != fflush(file)) {
    perror("@receive_file(): fflush(remote_sha1_file) fails.");
    return 1;
  }
  
  if (0 != fclose(file)) {
    perror("@receive_file(): fclose(remote_sha1_file) fails.");
    return 1;
  }

  return 0;
}

int create_dir(const char *relafname)
{
  char fullpath[MAX_PATH_LEN];
  struct stat statbuf;
  mode_t mode;

  if (stat(rootpath, &statbuf) < 0) {
    perror("@create_dir(): stat() failed\n");
    return 1;
  }
  mode = statbuf.st_mode;

  if (!strncpy(fullpath, rootpath, strlen(rootpath))) {
    fprintf(stderr,
	    "@create_dir(): strncpy rootpath:%s to fpath:%s failed: %s\n",
	    rootpath, fullpath, strerror(errno));
    return 1;
  }
  fullpath[strlen(rootpath)] = 0;

  if (connect_path(fullpath, relafname)) {
    fprintf(stderr, "@create_dir(): connect_path failed\n");
    return 1;
  }

  errno = 0;
  if (stat(fullpath, &statbuf) < 0 ) {
    if (errno == ENOENT) {
      if (mkdir(fullpath, mode) < 0) {
	perror("@create_dir(): mkdir() failed\n");
	return 1;
      }
    } else {
      perror("@create_dir(): stat() failed\n");
      return 1;
    }
  }
  

  return 0;
}


// remove dir even contain stuff
int remove_dir(const char *fname)
{
  //FTW_DEPTH is important here, refer manual
  if (nftw(fname, fn, 10, FTW_DEPTH) != 0) {
    perror("@remove_dir(): nftw() failed");
    return 1;
  }

  return 0;
}

static int fn(const char *fname, const struct stat *sb,
	      int typeflag, struct FTW *ftwbuf)
{
  if (remove(fname) < 0) {
    perror("@fn(): remove() failed");
    return 1;
  }

  return 0;
}


static int get_fss_dir(char *fpath)
{
  if (!strncpy(fpath, rootpath, strlen(rootpath))) {
    fprintf(stderr,
	    "@get_fss_dir(): strncpy rootpath:%s to fpath:%s failed: %s\n",
	    rootpath, fpath, strerror(errno));
    return 1;
  }
  fpath[strlen(rootpath)] = 0;

  if (connect_path(fpath, FSS_DIR)) {
    fprintf(stderr, "@get_fss_dir(): connect_path failed\n");
    return 1;
  }

  return 0;
}


static int get_xxx(char *fpath, const char *name)
{
  if (get_fss_dir(fpath)) {
    fprintf(stderr, "@get_xxx(): get_fss_dir() failed\n");
    return 1;
  }
  
  if (connect_path(fpath, name)) {
    fprintf(stderr, "@get_xxx(): connect_path(%s, %s) failed\n",
	    fpath, name);
    return 1;
  }

  return 0;
}

static int get_fname_fss(char *fpath)
{
  return get_xxx(fpath, FNAME_FSS);
}

static int get_sha1_fss(char *fpath)
{
  return get_xxx(fpath, SHA1_FSS);
}

static int get_temp_sha1_fss(char * fpath)
{

  return get_xxx(fpath, TEMP_SHA1_FSS);
}

static int get_remote_sha1_fss(char * fpath)
{

  return get_xxx(fpath, REMOTE_SHA1_FSS);
}

static int get_diff_remote_index(char * fpath)
{

  return get_xxx(fpath, DIFF_REMOTE_INDEX);
}

static int get_diff_local_index(char * fpath)
{

  return get_xxx(fpath, DIFF_LOCAL_INDEX);
}

static int get_del_index(char * fpath)
{
  return get_xxx(fpath, DEL_INDEX);
}


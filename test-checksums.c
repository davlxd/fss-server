#include "checksum.h"
#include "stdio.h"
#include <fcntl.h>


int main(int argc, char **argv)
{

  int fd;
  fd = open("output-another", O_WRONLY|O_CREAT); 

  send_checksums("/home/i/Desktop/input", fd, 700, "ROL_SHA1_CHKSUM");
  
  close(fd);

  return 0;
}

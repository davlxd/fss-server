#include "checksum.h"
#include "stdio.h"
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>


int main(int argc, char **argv)
{


  int fd;

  fd = open("../output", O_WRONLY|O_CREAT, 0755); 

  send_blk_checksums(fd, "../input", "input", 700, "M");
  
  close(fd);

  return 0;
}

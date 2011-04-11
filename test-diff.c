#include <stdio.h>

#include "diff.h"

int main()
{
  if (diff("remote.sha1.fss", "sha1.fss", "diff.remote.linenum.fss",
	   "diff.local.linenum.fss", "both.linenum.fss")) {
    fprintf(stderr, "diff failed\n");
    return 1;
  }


  return 0;
}

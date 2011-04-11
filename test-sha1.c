
#include "wrap-sha1.h"


int main()
{
  char digest[41];
  SHA1Context sha;
 

  sha1_str("test1.h.gch", digest);
  printf("--%s--\n", digest);

  sha1_digest_via_fname("/root/repo/lab/test1.h.gch",  digest);
  sha1_digest_via_fname("/root/repo/lab/test1.h.gc",  digest);
  printf("\n\n\ndigest is--%s--\n", digest);

  //sha1_digest_via_fname_fss("/root/repo/lab/test1.h.gch", "/root/repo", digest);
  sha1_digest_via_fname_fss("/root/repo/lab/test1.h.gch", "/root/repo", digest);
  printf("\n\n\ndigest of fss is--%s--\n", digest);

  return 0;
}

#include <string.h>
#include <sys/types.h>


#define REMAINING(data, len, x) ((len) - ((x) - (data)))


static u_char * memstr(const u_char *, const size_t,
		       const u_char *, const size_t);


unsigned char *find_exe(const u_char *data, const size_t len,
			u_char **exedata, size_t *exesize) {

  u_char *mz;
  unsigned int pe_offset, pe_magic;

  unsigned short pe_num_sect, pe_oh_size;

  unsigned int pe_cert_start, pe_cert_size;

  unsigned int i;
  char sname[8];
  unsigned int ssize, soffset;
  u_char *sptr;

  unsigned int max_pe_size = 0;

  /* Just plain too small for an EXE */
  if (len < 2048) {
    return (u_char *)data;
  }
    
  /* We're going to need an MZ... */
  if ((mz = memstr(data, len, (u_char *)"MZ", 2)) == 0) {
    /* fprintf(stderr, "Rejected because no MZ found\n"); */
    return (u_char *)(data + len - 2);
  }

  /* See if we have enough space after the MZ */
  if (REMAINING(data, len, mz) < 2048) {
    /* fprintf(stderr, "MZ Continued because we need at least 2k\n"); */
    return mz;
  }

  /* fprintf(stderr, "PE offset bytes are %x, %x, %x, %x\n", *(mz + 0x3c),
   *(mz + 0x3c + 1),
   *(mz + 0x3c + 2),
   *(mz + 0x3c + 3)); */

  pe_offset = *((unsigned int *)(mz + 0x3c));
  /*fprintf(stderr, "Got MZ and the PE offset is 0x%08x\n", pe_offset); */

  if (!((pe_offset > 0x3c) && (pe_offset < 2048))) {
    /* fprintf(stderr, "Rejected PE because offset is %08x\n", pe_offset); */
    return (mz + 2);
  }

  pe_magic = *((unsigned int *)(mz + pe_offset));

  if (pe_magic != 0x4550) {
    /* fprintf(stderr, "Rejected PE because pe_magic was %08x\n", pe_magic); */
    return (mz + 2);
  }

  pe_num_sect = *((unsigned short *)(mz + pe_offset + 4 + 2));
  pe_oh_size = *((unsigned short *)(mz + pe_offset + 4 + 16));

  /*
  fprintf(stderr, "Got %u sections\n", pe_num_sect);
  fprintf(stderr, "Got optional header size of %u\n", pe_oh_size);
  */

  if (pe_oh_size != 224) {
    /* fprintf(stderr, "Rejected PE because option header was %d bytes\n",
     * pe_oh_size); */
    return (mz + 2);
  }

  pe_cert_start = *((unsigned int *)(mz + pe_offset + 24 + 128));
  pe_cert_size = *((unsigned int *)(mz + pe_offset + 24 + 132));

  /*
  fprintf(stderr, "PE cert start=%u, size=%u\n", pe_cert_start, pe_cert_size);
  */

  /* loop through sections getting their info */
  for (i = 0; i < pe_num_sect; i++) {
    sptr = mz + pe_offset + pe_oh_size + 24 + (i * 40);

    memcpy(sname, sptr, sizeof sname);

    ssize = *((unsigned int *)(sptr + 16));
    soffset = *((unsigned int *)(sptr + 20));

    /* UNSAFE -- USE ONLY FOR DEBUGGING */
    /* fprintf(stderr, "Got section name: %8s; length %d, ofset %08x\n",
     * sname, ssize, soffset); */

    if (ssize + soffset > max_pe_size) {
      max_pe_size = ssize + soffset;
    }
  }

  /* Account for the certs that could be at the end */
  if (pe_cert_start + pe_cert_size > max_pe_size) {
    max_pe_size = pe_cert_start + pe_cert_size;
  }
  
  if (REMAINING(data, len, mz) < max_pe_size) {

    /* fprintf(stderr, "We don't have enough PE data yet, have %lu, need %u\n",
     * REMAINING(data, len, mz), max_pe_size); */

    return mz;
  }
  else {
    /* fprintf(stderr, "Finally found a PE\n"); */

    *exedata = mz;
    *exesize = max_pe_size;

    return mz + max_pe_size + 1;
  }

  /* go on */
  /* return (mz + 2); */

}


/* memstr:
 * Locate needle, of length n_len, in haystack, of length h_len, returning NULL
 * Uses the Boyer-Moore search algorithm. Cf.
 * http://www-igm.univ-mlv.fr/~lecroq/string/node14.html
 */
static u_char * memstr(const u_char *haystack, const size_t hlen,
		       const u_char *needle, const size_t nlen) {

  int skip[256], i, j, k;

  if (nlen == 0) {
    return (u_char *)haystack;
  }

  /* Set up the finite state machine */
  for (k = 0; k < 256; ++k) {
    skip[k] = nlen;
  }
  for (k = 0; k < nlen - 1; ++k) {
    skip[needle[k]] = nlen - k - 1;
  }

  /* Do the search. */
  for (k = nlen - 1; k < hlen; k += skip[haystack[k]]) {
    for (j = nlen - 1, i = k; ((j >= 0) && (haystack[i] == needle[j])); j--) {
      i--;
    }
    if (j == -1) {
      return (u_char *)(haystack + i + 1);
    }
  }

  return NULL;
}



/*  execap -- Snarf Windows executables off the wire (Driftnet for EXEs)
 *  Copyright (C) 2010-2011, Brandon Enright <bmenrigh@ucsd.edu>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  $Id$
 */

#include <string.h>
#include <sys/types.h>
#include <stdint.h>


#define EXE_DEBUG 0

#if EXE_DEBUG == 1
#include <stdio.h>
#endif

#define REMAINING(data, len, x) ((len) - ((x) - (data)))
#define PE_OH_OFFSET 24

static uint8_t * memstr(const uint8_t *, const size_t,
			const uint8_t *, const size_t);


u_char *find_exe(const u_char *data, const size_t len,
		 u_char **exedata, size_t *exesize,
		 u_short *machine, u_short *subsystem,
		 u_short *characteristics, u_char *newformat) {

  uint8_t *mz;
  uint32_t pe_offset, pe_magic;

  uint8_t is_pe32p;

  uint16_t pe_oh_magic;
  uint16_t pe_num_sect, pe_oh_size, pe_machine;
  uint16_t pe_subsystem, pe_characteristics;

  uint32_t pe_cert_start, pe_cert_size;

  uint32_t i;
  char sname[8];
  uint32_t ssize, soffset;
  uint8_t *sptr;

  uint32_t max_pe_size = 0;

  /* Just plain too small for an EXE */
  if (len < 2048) {
    return (u_char *)data;
  }
    
  /* We're going to need an MZ... */
  if ((mz = memstr(data, len, (uint8_t *)"MZ", 2)) == 0) {
#if EXE_DEBUG == 1
      fprintf(stderr, "Rejected because no MZ found\n");
#endif
    return (u_char *)(data + len - 2);
  }

  /* See if we have enough space after the MZ */
  if (REMAINING(data, len, mz) < 2048) {
#if EXE_DEBUG == 1
	  fprintf(stderr, "MZ Continued because we need at least 2k\n");
#endif
    return (u_char *)mz;
  }

#if EXE_DEBUG == 1
    /* fprintf(stderr, "PE offset bytes are %x, %x, %x, %x\n", *(mz + 0x3c),
     *(mz + 0x3c + 1),
     *(mz + 0x3c + 2),
     *(mz + 0x3c + 3)); */
#endif

  /* Find out where the PE header starts */
  pe_offset = *((uint32_t *)(mz + 0x3c));
#if EXE_DEBUG == 1
    fprintf(stderr, "Got MZ and the PE offset is 0x%08x\n", pe_offset);
#endif

  /* If the PE header offset doesn't make sense give up */
  if (!((pe_offset > 0x3c) && (pe_offset < 2048))) {
#if EXE_DEBUG == 1
      fprintf(stderr, "Rejected PE because offset is %08x\n", pe_offset);
#endif
    return (u_char *)(mz + 2);
  }

  /* Grab the PE magic */
  pe_magic = *((uint32_t *)(mz + pe_offset));

  /* Magic should be "PE" */
  if (pe_magic != 0x4550) {
#if EXE_DEBUG == 1
      fprintf(stderr, "Rejected PE because pe_magic was %08x\n", pe_magic);
#endif
    return (u_char *)(mz + 2);
  }

  /* Grab the basics from the PE header */
  pe_machine = *((uint16_t *)(mz + pe_offset + 4 + 0));
  pe_num_sect = *((uint16_t *)(mz + pe_offset + 4 + 2));
  pe_oh_size = *((uint16_t *)(mz + pe_offset + 4 + 16));
  pe_characteristics = *((uint16_t *)(mz + pe_offset + 4 + 18));

#if EXE_DEBUG == 1
    /*
      fprintf(stderr, "Got %u sections\n", pe_num_sect);
      fprintf(stderr, "Got optional header size of %u\n", pe_oh_size);
    */
#endif


  /* Grab the optional header magic */
  pe_oh_magic = *((uint16_t *)(mz + pe_offset + PE_OH_OFFSET + 0));

  /* This will tell us if we have a PE32 or a PE32+ (.Net or 64 bit PE) */
  if (pe_oh_magic == 0x010b) {
#if EXE_DEBUG == 1
      fprintf(stderr, "Got pe32\n");
#endif

    /* Make sure the optional header size makes sense for a PE32 */
    if (pe_oh_size != 224) {
#if EXE_DEBUG == 1
	fprintf(stderr, "Wrong oh size for pe32\n");
#endif
      return (u_char *)(mz + 2);
    }

    is_pe32p = 0;
  } else if (pe_oh_magic == 0x020b) {
#if EXE_DEBUG == 1
      fprintf(stderr, "Got pe32+; oh size: %d\n", pe_oh_size);
#endif

    /* Make sure the optional header size makes sense for a PE32+ */
    if (pe_oh_size != 240) {
#if EXE_DEBUG == 1
	fprintf(stderr, "Wrong oh size for pe32+\n");
#endif
      return (u_char *)(mz + 2);
    }
    
    is_pe32p = 1;
  }
  else {
    /* The OH magic wasn't right */
#if EXE_DEBUG == 1
      fprintf(stderr, "Unknown OH magic\n");
#endif
    return (u_char *)(mz + 2);
  }

  /* Grab the other optional header fields we care about */
  pe_subsystem = *((uint16_t *)(mz + pe_offset + PE_OH_OFFSET + 68));
  if (is_pe32p == 0) {
    pe_cert_start = *((uint32_t *)(mz + pe_offset + PE_OH_OFFSET + 128));
    pe_cert_size = *((uint32_t *)(mz + pe_offset + PE_OH_OFFSET + 132));
  }
  else {
    pe_cert_start = *((uint32_t *)(mz + pe_offset + PE_OH_OFFSET + 128 + 16));
    pe_cert_size = *((uint32_t *)(mz + pe_offset + PE_OH_OFFSET + 132 + 16));
  }


  /* loop through sections getting their info */
  for (i = 0; i < pe_num_sect; i++) {
    sptr = mz + pe_offset + pe_oh_size + 24 + (i * 40);

    memcpy(sname, sptr, sizeof sname);

    ssize = *((uint32_t *)(sptr + 16));
    soffset = *((uint32_t *)(sptr + 20));

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

#if EXE_DEBUG == 1
      fprintf(stderr, "We don't have enough PE data yet, have %lu, need %u\n",
	      REMAINING(data, len, mz), max_pe_size);
#endif

    return (u_char *)mz;
  }
  else {
    /* fprintf(stderr, "Finally found a PE\n"); */

    *exedata = mz;
    *exesize = max_pe_size;

    *machine = pe_machine;
    *subsystem = pe_subsystem;
    *characteristics = pe_characteristics;

    *newformat = is_pe32p;

    return (u_char *)(mz + max_pe_size + 1);
  }

  /* go on */
  /* return (mz + 2); */

}


/* memstr:
 * Locate needle, of length n_len, in haystack, of length h_len, returning NULL
 * Uses the Boyer-Moore search algorithm. Cf.
 * http://www-igm.univ-mlv.fr/~lecroq/string/node14.html
 *
 * This algorithm is very fast for longer needles but for very short ones like
 * "MZ" it is slower because of setup time.
 */
static uint8_t * memstr(const uint8_t *haystack, const size_t hlen,
			const uint8_t *needle, const size_t nlen) {

  uint8_t skip[256];
  int i, j, k;

  if (nlen == 0) {
    return (uint8_t *)haystack;
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
      return (uint8_t *)(haystack + i + 1);
    }
  }

  return NULL;
}



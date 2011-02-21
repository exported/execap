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
*/

#include "execap.h"
#include "pavl.h"


int main(int argc, char * const argv[]) {

  /* === PCAP vars === */
  char * dev = NULL; /* The device to sniff on */
  char pc_errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
  char base_filter_str[] = "ip and tcp"; /* The constant filter expression */
  char filter_str[BPF_FILTER_LEN]; /* The combined filter string */
  struct bpf_program filter_prog;/* The compiled filter */
  bpf_u_int32 mask;/* Our netmask */
  bpf_u_int32 net;/* Our IP */
  int pret; /* For holding on to return values */
  struct pcap_stat stats;

  /* === Signal stuff === */
  struct sigaction sa_new, sa_old;

  /* === Thread vars === */
  pthread_t connection_reaper;
  int thread_ret;

  /* === Argument parsing vars === */
  int arg_val;
  int option_index;

  /* === Daemonize vars === */
  pid_t fork_ret;
  char pidtext[128];
  int pipefd[2];
  char pipebuf = '\0';
  int devnullfd;

  /* == Scratch vars === */
  int i;
  int wlen;


  /* ===
   * Handle command line parameters
   * ===
   */
  struct option long_options[] = {
    {"interface", required_argument, 0, 'i'},
    {"logdir", required_argument, 0, 'l'},
    {"exedir", required_argument, 0, 'e'},
    {"verbose", no_argument, 0, 'v'},
    {"daemonize", no_argument, 0, 'D'},
    {"pidfile", required_argument, 0, 0},
    {"version", no_argument, 0, 'V'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };

  /* getopt_long() loop */
  while ((arg_val = getopt_long(argc, argv, "i:l:e:DhVv",
				long_options, &option_index)) != EOF) {
    
    if (arg_val == 'h') {
      printf("execap v%s\n"
	     "Usage: execap -i interface [OPTIONS] [CAPTURE FILTER]\n\n"
	     "Options:\n"
	     "-i, --interface         specify interface to capture on\n"
	     "-l, --logdir            save logs to this directory\n"
	     "-e, --exedir            save executables to this directory\n"
	     "-v, --verbose           turn on verbose output\n"
	     "-D, --daemonize         run as daemon in background\n"
	     "--pidfile               store daemon pid to this file\n"
	     "-V, --version           display version and exit\n"
	     "-h, --help              display this help and exit\n\n"
	     "execap web page:  http://code.google.com/p/execap\n"
	     "Report bugs to:   bmenrigh@ucsd.edu "
	     "/ http://code.google.com/p/execap/issues\n",
	     EXECAPVER);

      return 0;
    }
    else if (arg_val == 'V') {
      printf("execap v%s\n"
	     "Copyright (C) 2010-2011 Brandon Enright <bmenrigh@ucsd.edu>.\n"
	     "This is free software; see the source for copying conditions.  "
	     "There is NO\nwarranty; not even for MERCHANTABILITY or FITNESS "
	     "FOR A PARTICULAR PURPOSE.\n\n", EXECAPVER);

      return 0;
    }
    else if (arg_val == 'v') {
      /* fprintf(stderr, "Turning on verbose alerts\n"); */
    }
    else if (arg_val == 'i') {
      dev = strdup(optarg);
    }
    else if (arg_val == 'l') {
      strncpy(logdir, optarg, MAX_PATH_LEN);
      logdir[MAX_PATH_LEN - 1] = '\0';
    }
    else if (arg_val == 'e') {
      strncpy(exedir, optarg, MAX_PATH_LEN);
      exedir[MAX_PATH_LEN - 1] = '\0';
    }
    else if (arg_val == 'D') {
      daemonize = 1;
    }
    else if (arg_val == 0) {
      /* These are the long options only */
      if (strcmp(long_options[option_index].name, "pidfile") == 0) {
	strncpy(pidfile, optarg, MAX_PATH_LEN);
	pidfile[MAX_PATH_LEN - 1] = '\0';
      }
      else {
	fprintf(stderr, "Got unknown option, quitting!\n");
	return -1;
      }
    }
    else {
      fprintf(stderr, "Got unknown option, quitting!\n");
      return -1;
    }

  }

  /* Check for bpf filter at end of options */
  if (optind < argc) {
    snprintf(filter_str, BPF_FILTER_LEN, "(%s) and (%s)", base_filter_str,
	     argv[optind]);
  }
  else {
    snprintf(filter_str, BPF_FILTER_LEN, "%s", base_filter_str);
  }


  /* Make sure the arguments we need were provided or fill in defaults */
  if (dev == NULL) {
    fprintf(stderr, "A listening interface must be provided with -i / "
	    "--interface\n");

    return -1;
  }
  if (logdir[0] == '\0') {
    strncpy(logdir, "/var/log/execap", MAX_PATH_LEN);
    logdir[MAX_PATH_LEN - 1] = '\0';
  }
  if (exedir[0] == '\0') {
    strncpy(exedir, "/var/log/execap/exes", MAX_PATH_LEN);
    exedir[MAX_PATH_LEN - 1] = '\0';
  }
  if (pidfile[0] == '\0') {
    strncpy(pidfile, "/var/run/execap/execap.pid", MAX_PATH_LEN);
    pidfile[MAX_PATH_LEN - 1] = '\0';
  }
  else {
    if (daemonize == 0) {
      fprintf(stderr, "WARNING: pidfile specified but not in daemon mode!\n");
    }
  }

  /* ===
   * Daemonize if we need to
   * ===
   */
  if (daemonize == 1) {
    fprintf(stderr, "Daemonizing...\n");

    if (pipe(pipefd) == -1) {
      fprintf(stderr, "Failed to create pipe.\n");
      return -1;
    }

    /* === Become two processes === */
    fork_ret = fork(); /* fork into background */

    if (fork_ret == -1) {
      fprintf(stderr, "Forking into the background failed.\n");
      return -1;
    }
    else if (fork_ret != 0) {
      /* This is the parent */

      /* Close the write end of the pipe */
      close(pipefd[1]);

      /* Now read from the child */
      if (read(pipefd[0], &pipebuf, 1) != 1) {
	fprintf(stderr, "Background process died.\n");
	return -1;
      }
      close(pipefd[0]);

      fprintf(stderr, "execap successfully started in background.\n");

      return 0;
    }
    else {
      /* Break away from the parent */
      daemon_pid = setsid();

      /* Close the read end of the pipe */
      close(pipefd[0]);

      /* No idea how this could fail */
      if (daemon_pid == -1) {
	fprintf(stderr, "Unable to break away from parent.\n");
	return -1;
      }

      /* === Write our PID to a file === */

      /* Open up the pid file */
      if ((pid_fd = open(pidfile, O_CREAT | O_WRONLY | O_TRUNC, 0644)) == -1) {
	fprintf(stderr, "PID: Opening of %s for writing failed!\n", pidfile);

	return -1;
      }

      /* Make the pid text ready for write() */
      snprintf(pidtext, sizeof(pidtext), "%d\n", daemon_pid);
      wlen = write(pid_fd, pidtext, strlen(pidtext));

      /* Close the pid file now */
      close(pid_fd);

    }
  }


  /* Open the log file handle */
  snprintf(log_file, MAX_PATH_LEN,
	   "%s/log_execap.%d", logdir, (int)time(NULL));

  if ((log_fd = open(log_file, O_WRONLY | O_CREAT | O_EXCL, 0644)) == -1) {
    fprintf(stderr, "LOG: Opening of %s for writing failed!\n", log_file);

    return -1;
  }

  /* Report that we've started up */
  fprintf(stderr, "execap v%s started...\n\n", EXECAPVER);

  /* Report that we're about to do the PCAP stuff */
  fprintf(stderr, "PCAP: Going to listen on interface %s\n", dev);

  /* Get the netmask and IP from the device */
  if (pcap_lookupnet(dev, &net, &mask, pc_errbuf) != 0) {
    fprintf(stderr, "PCAP: Couldn't get netmask for device %s\n", pc_errbuf);
    net = 0;
    mask = 0;
  }

#ifdef OLDPCAP
    if ((pch = pcap_open_live(dev, SNAPLEN, 1, PCAPTIMEOUT, pc_errbuf)) == 0) {
    fprintf(stderr, "PCAP: Unable to get pcap handle for %s: %s\n",
	    dev, pc_errbuf);
    return -1;
  }
#else

  /* Get our pcap handle */
  if ((pch = pcap_create(dev, pc_errbuf)) == 0) {
    fprintf(stderr, "PCAP: Unable to get pcap handle for %s: %s\n",
	    dev, pc_errbuf);
    return -1;
  }

  /* Set a large pcap buffer */
  if (pcap_set_buffer_size(pch, CAPTUREBUFFER) != 0) {
    fprintf(stderr, "PCAP: Unable to set pcap buffer to %u bytes\n",
	    CAPTUREBUFFER);
  }

  /* Make sure we're capturing all of the packet */
  if (pcap_set_snaplen(pch, SNAPLEN) != 0) {
    fprintf(stderr, "PCAP: Unable to set snaplen to %u bytes\n", SNAPLEN);
  }

  /* Set the timeout */
  if (pcap_set_timeout(pch, PCAPTIMEOUT) != 0) {
    fprintf(stderr, "PCAP: Unable to set the timeout to %u\n", SNAPLEN);
  }

  /* Capture in PROMISC mode */
  if (pcap_set_promisc(pch, 1) != 0) {
    fprintf(stderr, "PCAP: Unable to set PROMISC capture mode\n");
  }

  /* Activate the pcap handle */
  if ((pret = pcap_activate(pch)) != 0) {
    fprintf(stderr, "PCAP: Activating the pcap handle failed\n");
    
    if ((pret == PCAP_WARNING) || (pret == PCAP_ERROR)) {
      fprintf(stderr, "PCAP: The activation error was %s\n", pcap_geterr(pch));
    }
    return -1;
  }
#endif

  /* Make sure the datalink is Ethernet */
  if (pcap_datalink(pch) != DLT_EN10MB) {
    fprintf(stderr, "PCAP: The datalink is not Ethernet, exiting!\n");
    return -1;
  }  

  /* The capture filter must be compiled after the handle is activated */
  if (pcap_compile(pch, &filter_prog, (char*)filter_str, 1, mask) != 0) {
    fprintf(stderr, "PCAP: Filter compilation failed: %s\n", pcap_geterr(pch));
    return -1;
  }

  /* Now apply the filter to an activated handle */
  fprintf(stderr, "PCAP: Setting capture filter to: %s\n", filter_str);
  if ((pret = pcap_setfilter(pch, &filter_prog)) != 0) {
    fprintf(stderr, "PCAP: Setting the filter failed with %d; err: %s\n",
	    pret, pcap_geterr(pch));
    return -1;
  }


  /* Before we start capturing packets we need to setup a signal
   * handler to be able to break out of pcap_loop() */
  memset(&sa_new, 0, sizeof(struct sigaction));
  sa_new.sa_handler = sig_stop_pcap;
  sigaction(SIGTERM, &sa_new, &sa_old);
  memset(&sa_new, 0, sizeof(struct sigaction));
  sa_new.sa_handler = sig_stop_pcap;
  sigaction(SIGINT, &sa_new, &sa_old);

  /* Create the connection trees */
  for (i = 0; i < TREES; i++) {
    connection_tree[i].tree = pavl_create(compare_connections, NULL, NULL);
    pthread_mutex_init(&(connection_tree[i].tree_mutex), NULL);
  }
  
  /* Start time */
  stats_start = time(NULL);

  /* Before listening, start the connection reaper thread */
  thread_ret = pthread_create(&connection_reaper, NULL,
			      thread_connection_reaper, NULL);


  /* 
   * Before we go into the pcap loop, we need to tell the parent
   * that we made it.
   */
  if (daemonize == 1) {
    if (write(pipefd[1], &pipebuf, 1) == -1) {
      fprintf(stderr, "Unable to notify parent of success.\n");
    }
    close(pipefd[1]);

    /* == Make stdin, stdout, and stderr all /dev/null === */
    if ((devnullfd = open("/dev/null", O_RDWR, 0)) == -1) {
      fprintf(stderr, "Unable to open /dev/null\n");
      return -1;
    }

    /* Force std{in,out,err} to /dev/null */
    dup2(devnullfd, STDIN_FILENO);
    dup2(devnullfd, STDOUT_FILENO);
    dup2(devnullfd, STDERR_FILENO);
    
    /* Close devnullfd if we need to */
    if (devnullfd > STDERR_FILENO) {
      close(devnullfd);
    }
  }
  

  /* Now start capturing and handling packets */
  pcap_loop(pch, -1, packet_callback, NULL);
  fprintf(stderr, "\nSignal caught, PCAP loop terminated.\n");

  /* There is a chance the pcap_loop() call returned for a reason
   * other than a signal.  We need to make sure the thread terminates.
   */
  terminate = 1;

  /* === Stopped listening, wait for the thread to die === */
  fprintf(stderr, "Waiting for threads to finish before exiting...\n");
  pthread_join(connection_reaper, NULL);


  /* End time */
  stats_end = time(NULL);


  /* Grab the capture statistics */
  if (pcap_stats(pch, &stats) != 0) {
    fprintf(stderr, "PCAP: Unable to get statistics: %s\n", pcap_geterr(pch));
    return -1;
  }

  fprintf(stderr, "\n-- \n");
  fprintf(stderr, "%llu bytes captured (%.02f Mbps average rate)\n",
	  stats_bytes, (((double)(stats_bytes * 8) /
			 (double)((stats_end - stats_start) + 1)) /
			(double)1000000));
  fprintf(stderr, "%llu packets captured\n", stats_packets);
  fprintf(stderr, "%u packets received by filter\n", stats.ps_recv);
  fprintf(stderr, "%u packets dropped by kernel\n", stats.ps_drop);

  /* Now close the pcap handle */
  pcap_close(pch);

  /* And flush and close our log file */
  fsync(log_fd);
  close(log_fd);

  /* Free some memory */
  free(dev);

  return 0;
}


void packet_callback(u_char * user, const struct pcap_pkthdr *header,
		     const u_char *packet) {
  
  struct ip iph;
  struct tcphdr tcph;
  size_t iphlen;
  size_t iplen;
  size_t tcphlen;
  size_t data_offset;
  size_t datalen;
  struct connection conn;
  struct connection *conn_copy;
  struct connection **conn_probe;
  struct packet_data cur_packet;
  struct packet_data **pp_working_packet;
  struct packet_data **pp_last_packet;
  struct packet_data **pp_next_packet;
  struct packet_data *p_temp_packet;
  time_t cur_time = time(NULL);
  tcp_seq thisseq;
  unsigned int pos = 0;
  u_char *temp_data;
  size_t overlap;
  u_char insert = 1;
  u_short tree_num;
  u_char handle_case = 0;

  /* The EXE search vars */
  u_char *next_offset;
  u_char *exe_offset;
  size_t exe_size;
  u_short exe_machine;
  u_short exe_subsystem;
  u_short exe_characteristics;
  u_char newformat;

  /* The log and exe saving vars */
  u_char exe_md5[33];
  struct tm time_detail;
  char exe_log[MAX_PATH_LEN];
  size_t exe_log_len;
  char exe_file[MAX_PATH_LEN];
  size_t exe_file_len;
  int exe_fd;
  struct stat file_stat;
  ssize_t write_len;

  /* Record some basic stats */
  stats_packets++;
  stats_bytes += header->caplen;

  /*fprintf(stderr, "Got packet\n");*/

  /* Now grab out the IP header */
  memcpy(&iph, packet + ETH_HDR_SIZE, sizeof(iph));

  iphlen = (iph.ip_hl << 2);

  /* Do some IP header sanity checks */
  if ((iph.ip_v != 4) || (iphlen < MIN_IP_HDR_SIZE)) {
    fprintf(stderr, "Got broken IP header (v=%d; hl=%d)\n",
	    iph.ip_v, iph.ip_hl);
    return;
  }


  /* Make sure this capture wasn't truncated */
  iplen = ntohs(iph.ip_len);
  if ((iplen + ETH_HDR_SIZE > header->caplen) || (iplen < iphlen)
      || ((iplen - iphlen) < MIN_TCP_HDR_SIZE)) {
    /*fprintf(stderr, "Got truncated IP packet (IP size=%u; caplen=%u)\n",
      (unsigned int)iplen, (unsigned int)header->caplen);*/
    return;
  }


  /* Now grab out the TCP header */
  memcpy(&tcph, packet + ETH_HDR_SIZE + iphlen, sizeof(tcph));
  
  /* Now do some TCP header sanity checks */
  tcphlen = (tcph.th_off << 2);
  if (tcphlen < MIN_TCP_HDR_SIZE) {
    /* fprintf(stderr, "Got broken TCP header (hl=%d)\n", tcphlen); */
    return;
  }

  /* Make sure we have a complete tcp header */
  if (iplen < (iphlen + tcphlen)) {
    /*fprintf(stderr, "Got truncated TCP header (IP size=%u; caplen=%u)\n",
      (unsigned int)iplen, (unsigned int)header->caplen);*/
    return;
  }

  /* We now know the data offset */
  data_offset = ETH_HDR_SIZE + iphlen + tcphlen;

  /* Sanity check the data offset */
  if (data_offset > header->caplen) {
    /* fprintf(stderr, "Got incomplete IP + TCP header\n"); */
    return;
  }

  /*
   * Now figure out the data length (must use IP length, not caplen because
   * Ethernet frames can have padding).
   */
  datalen = iplen - (iphlen + tcphlen);

  /* Sanity check size of data returned */
  if (datalen > SNAPLEN) {
    fprintf(stderr,
	    "Got unexpected packet length (caplen=%u, doff=%u, dlen=%u)\n",
	    header->caplen, (unsigned int )data_offset,
	    (unsigned int)datalen);
    return;
  }

    
  /* Fill out the connection struct */
  memcpy(&(conn.ip_src), &(iph.ip_src), sizeof(struct in_addr));
  memcpy(&(conn.ip_dst), &(iph.ip_dst), sizeof(struct in_addr));
  conn.th_sport = tcph.th_sport;
  conn.th_dport = tcph.th_dport;
  conn.last_seen = cur_time;
  conn.abandon = 0;
  conn.total_data = 0;
  conn.search_offset = 0;
  conn.datalist = NULL;

  conn_copy = copy_connection(&conn, NULL);

  tree_num = TREEHASH(conn_copy);

  /* === *** ACQUIRE TREE LOCK *** === */
  pthread_mutex_lock(&(connection_tree[tree_num].tree_mutex));

  conn_probe = (struct connection **)pavl_probe(connection_tree[tree_num].tree,
						conn_copy);

  if (conn_probe == NULL) {
    fprintf(stderr, "There was a failure inserting connection into tree.\n");
    goto unlock_and_return;
  }


  if (*conn_probe == conn_copy) {
    /* Just inserted, nothing to do */
  }
  else {

    /* Update the last seen time */
    (*conn_probe)->last_seen = conn.last_seen;

    /* We don't need the conn_copy anymore */
    free(conn_copy);
    conn_copy = NULL;
  }


  /* If we have data to insert, do it */
  if ((datalen > 0) && ((*conn_probe)->abandon == 0)) {
    thisseq = ntohl(tcph.th_seq);

    /* Find the packet spot or merge */
    pp_last_packet = NULL;
    pp_working_packet = &((*conn_probe)->datalist);
    pos = 0;
    while (*pp_working_packet != NULL) {

      /* ===
       * It isn't safe to pass sequences that exceed MAX_SEQ_DIST
       * to GT_32() and the like.  Make sure we don't since the rest
       * of the code assumes the GT/LT checks are always correct
       * and if they aren't a segfault could occur.  See issue 19 for
       * more details.
       * ===
       */
      if (EXCEEDS_DIST(thisseq, (*pp_working_packet)->seq)) {

	/* fprintf(stderr, "Sequence exceeds max dist, abandoning\n"); */

	abandon_packets((*conn_probe)->datalist);
	(*conn_probe)->datalist = NULL;
	(*conn_probe)->abandon = 1;
	insert = 0;
	
	break;
      }


      /* === 
       * If there are next packets and this one eclipses them then delete
       * === */
      while (((*pp_working_packet)->next != NULL) &&
	     (LT_32(thisseq, (((*pp_working_packet)->next)->seq))) &&
	     (GTE_32((thisseq + datalen) & 0xFFFFFFFF,
		     (((((*pp_working_packet)->next)->seq) +
		       ((*pp_working_packet)->next)->datalen) &
		      0xFFFFFFFF)))) {
	
	/* Account for this data removal */
	(*conn_probe)->total_data -= ((*pp_working_packet)->next)->datalen;
	
	/* Grab the next pointer before we break the pointer to it */
	p_temp_packet = (*pp_working_packet)->next;
	
	/* Now fix our next pointer */
	(*pp_working_packet)->next = ((*pp_working_packet)->next)->next;
	
	/* Now free old data */
	free(p_temp_packet->data);
	
	/* And free the struct */
	free(p_temp_packet);
      }


      /* ===
       * If this packet eclipses the working packet replace it
       * === */
      if ((LTE_32(thisseq, (*pp_working_packet)->seq)) &&
	  (GTE_32((thisseq + datalen) & 0xFFFFFFFF,
		  ((*pp_working_packet)->seq + (*pp_working_packet)->datalen) &
		  0xFFFFFFFF))) {

	/* Resize to fit new data */
	(*pp_working_packet)->data = realloc((*pp_working_packet)->data,
					     datalen);

	/* Copy in the new data */
	memcpy((*pp_working_packet)->data, packet + data_offset, datalen);

	/* Update seq */
	(*pp_working_packet)->seq = thisseq;

	/* Update datalen */
	(*pp_working_packet)->datalen = datalen;

	/* We changed this packet, reset searched */
	(*pp_working_packet)->searched = 0;

	insert = 0;
	handle_case = 1;
	break;
      } /* end eclipse */


      /* ===
       * This packet fits before a previous packet
       * === */
      if ((LT_32(thisseq, (*pp_working_packet)->seq)) &&
	  (GTE_32((thisseq + datalen) & 0xFFFFFFFF,
		  (*pp_working_packet)->seq))) {

	/* Find the overlap */
	overlap = (((thisseq + datalen) & 0xFFFFFFFF) -
		   (*pp_working_packet)->seq) & 0xFFFFFFFF;

	/* We need to make some space were we can combined the data */
	temp_data = malloc(((*pp_working_packet)->datalen + datalen) -
			   overlap);

	/* Now copy in this packet's data */
	memcpy(temp_data, packet + data_offset, datalen);

	/* Now copy in the existing packet data */
	memcpy(temp_data + datalen, (*pp_working_packet)->data + overlap,
	       (*pp_working_packet)->datalen - overlap);

	/* Now get rid of the old data */
	free((*pp_working_packet)->data);

	/* And set the pointer to the new data */
	(*pp_working_packet)->data = temp_data;

	/* We need to update the new sequence */
	(*pp_working_packet)->seq = thisseq;

	/* We need to record this new size */
	(*pp_working_packet)->datalen += (datalen - overlap);

	/* We changed this packet, reset searched */
	(*pp_working_packet)->searched = 0;

	/* Track this data */
	(*conn_probe)->total_data += (datalen - overlap);

	insert = 0;
	handle_case = 2;
	break;
      } /* END starts before */


      /* ===
       * If this packet starts after a previous packet starts
       * === */
      if ((GTE_32(thisseq, (*pp_working_packet)->seq)) &&
	  (LTE_32(thisseq, (((*pp_working_packet)->seq +
			     (*pp_working_packet)->datalen) & 0xFFFFFFFF)))) {

	/* If the packet is contained in the working packet just skip it */
	if (LTE_32((thisseq + datalen) & 0xFFFFFFFF,
		   (((*pp_working_packet)->seq +
		     (*pp_working_packet)->datalen) & 0xFFFFFFFF))) {

	  /* fprintf(stderr, "Got a duplicate packet, skipping\n"); */

	  insert = 0;
	  break;
	}

	/* Find the overlap */
	overlap = ((((*pp_working_packet)->seq +
		     (*pp_working_packet)->datalen) & 0xFFFFFFFF) - thisseq) &
	  0xFFFFFFFF;

	/* We need to realloc() the data from the working packet */
	(*pp_working_packet)->data = realloc((*pp_working_packet)->data,
					     (((*pp_working_packet)->datalen +
					       datalen) - overlap));

	/* We need to copy the new data in */
	memcpy((*pp_working_packet)->data + (*pp_working_packet)->datalen,
	       packet + data_offset + overlap, datalen - overlap);

	/* We need to record this new size */
	(*pp_working_packet)->datalen += (datalen - overlap);

	/* Track this data */
	(*conn_probe)->total_data += (datalen - overlap);

	insert = 0;
	handle_case = 3;
	break;
      } /* end after working packing */


      /* ===
       * If we aren't far enough along in the linked list
       * === */
      if (GTE_32(thisseq, (*pp_working_packet)->seq)) {

	/* Go on */
	pp_last_packet = pp_working_packet;
	pp_working_packet = &((*pp_working_packet)->next);

	/* We're going on to the next one, track it */
	pos++;
      }
      else {
	break;
      }
      
    } /* END while pp_working_packet != NULL */


    /* If the pos is too big we have too many fragments */
    if (pos > MAX_CONN_FRAG) {

      abandon_packets((*conn_probe)->datalist);
      (*conn_probe)->datalist = NULL;
      (*conn_probe)->abandon = 1;
      insert = 0;
    }


    /* We might need to insert a packet instead */
    if ((pp_working_packet != NULL) && (insert == 1) &&
	((*conn_probe)->abandon == 0)) {

      /* We can't combine with anything, insert infront of working packet */
      cur_packet.next = *pp_working_packet;
      cur_packet.seq = thisseq;
      cur_packet.searched = 0;
      cur_packet.datalen = datalen;
      
      /* Allocate our packet data space */
      if ((cur_packet.data = malloc(datalen)) == 0) {
	fprintf(stderr, "malloc() failed allocating space for data!\n");
	goto unlock_and_return;
      }
      /* Copy our data in */
      memcpy(cur_packet.data, packet + data_offset, datalen);
      
      /* Allocate our packet_data struct space */
      if ((*pp_working_packet = malloc(sizeof(struct packet_data))) == 0) {
	fprintf(stderr,
		"malloc() failed allocating space for struct packet_data!\n");
      }
      /* Copy our struct in */
      memcpy(*pp_working_packet, &cur_packet, sizeof(struct packet_data));
      
      /* Now fixup the previous packet pointer if we need to */
      if ((pp_last_packet != NULL) && (*pp_last_packet != NULL)) {
	(*pp_last_packet)->next = *pp_working_packet;
      }

      /* Track this data */
      (*conn_probe)->total_data += datalen;

	handle_case = 4;

    } /* END insert packet */

    
    /* See if we can merge some packets */
    pp_working_packet = &((*conn_probe)->datalist);

    
    /* Find the packets to merge */
    while ((*pp_working_packet != NULL) && ((*conn_probe)->abandon == 0)) {
      pp_next_packet = &((*pp_working_packet)->next);

      while (((*pp_next_packet) != NULL) &&
	     (GTE_32((((*pp_working_packet)->seq +
		       (*pp_working_packet)->datalen) & 0xFFFFFFFF),
		     (*pp_next_packet)->seq))) {

	/* Find the overlap */
	overlap = ((((*pp_working_packet)->seq +
		    (*pp_working_packet)->datalen) & 0xFFFFFFFF) -
		   (*pp_next_packet)->seq) & 0xFFFFFFFF;

	/* We need to realloc() the data from the working packet */
	(*pp_working_packet)->data = realloc((*pp_working_packet)->data,
					     (((*pp_working_packet)->datalen +
					       (*pp_next_packet)->datalen) -
					      overlap));

	/* We need to copy the new data in */
	memcpy((*pp_working_packet)->data + (*pp_working_packet)->datalen,
	       (*pp_next_packet)->data + overlap,
	       (*pp_next_packet)->datalen - overlap);

	/* We need to record this new size */
	(*pp_working_packet)->datalen += (*pp_next_packet)->datalen - overlap;

	/* Grab the next pointer before we break the pointer to it */
	p_temp_packet = *pp_next_packet;

	/* Now fix our next pointer */
	(*pp_working_packet)->next = (*pp_next_packet)->next;

	/* Now free old data */
	free(p_temp_packet->data);

	/* And free the struct */
	free(p_temp_packet);

	/* There in a new next packet now */
	pp_next_packet = &((*pp_working_packet)->next);
      }

      /* Go on with the merge checks */
      pp_working_packet = &((*pp_working_packet)->next);
    } /* end while merge packets */
	
  } /* END if datalen > 0 */


  /* If the data wasn't searched reset the search_offset */
  if (((*conn_probe)->abandon == 0) &&
      ((*conn_probe)->datalist != NULL) &&
      (((*conn_probe)->datalist)->searched == 0)) {

    (*conn_probe)->search_offset = 0;
  }


  /* Check if we should search for an EXE */
  if (((*conn_probe)->abandon == 0) && ((*conn_probe)->total_data >= 2048) &&
      ((*conn_probe)->datalist != NULL) &&
      (((*conn_probe)->datalist)->datalen > (*conn_probe)->search_offset) &&
      ((((*conn_probe)->datalist)->datalen -
	(*conn_probe)->search_offset) >= 2048) &&
      (((*conn_probe)->datalist)->next == NULL)) {

    exe_offset = NULL;
    exe_size = 0;

    /* Try to find an EXE */
    next_offset = find_exe(((*conn_probe)->datalist)->data +
			   (*conn_probe)->search_offset,
			   ((*conn_probe)->datalist)->datalen -
			   (*conn_probe)->search_offset,
			   &exe_offset, &exe_size, &exe_machine,
			   &exe_subsystem, &exe_characteristics,
			   &newformat);

    /* Find the new offset */
    (*conn_probe)->search_offset = next_offset -
      ((*conn_probe)->datalist)->data;

    /* Did we find an EXE? */
    if (exe_size != 0) {

      /* Get the detailed time info */
      gmtime_r(&cur_time, &time_detail);

      /* Compute the MD5*/
      md5_hex(exe_offset, exe_size, exe_md5);

      exe_log_len = 0;
      exe_log_len +=
	snprintf(exe_log + exe_log_len, MAX_PATH_LEN - exe_log_len,
		 "%04d-%02d-%02dT%02d:%02d:%02d (UTC) -- EXE -- %s:%u",
		 time_detail.tm_year + 1900, time_detail.tm_mon + 1,
		 time_detail.tm_mday, time_detail.tm_hour, time_detail.tm_min,
		 time_detail.tm_sec, inet_ntoa((*conn_probe)->ip_src),
		 ntohs((*conn_probe)->th_sport));
      if (exe_log_len >= MAX_PATH_LEN) {
	exe_log_len = MAX_PATH_LEN - 1;
      }

      exe_log_len +=
	snprintf(exe_log + exe_log_len, MAX_PATH_LEN - exe_log_len,
		 " -> %s:%u (Size=%u; Machine=0x%04x; "
		 "Subsystem=0x%04x; IsDLL=%u; IsPE32+=%u; MD5=%s)\n",
		 inet_ntoa((*conn_probe)->ip_dst),
		 ntohs((*conn_probe)->th_dport),
		 (unsigned int)exe_size,
		 exe_machine, exe_subsystem,
		 ((exe_characteristics & 0x2000) > 0),
		 newformat, exe_md5);
      if (exe_log_len >= MAX_PATH_LEN) {
	exe_log_len = MAX_PATH_LEN - 1;
      }

      /* Report this entry to the console */
      fprintf(stderr, "%s", exe_log);

      /* And write and sync it to the log */
      write_len = write(log_fd, exe_log, exe_log_len);
      fsync(log_fd);

      /* Make the EXE filename */
      exe_file_len = snprintf(exe_file, MAX_PATH_LEN,
			      "%s/exe_%s", exedir, exe_md5);
      if (exe_file_len >= MAX_PATH_LEN) {
	exe_file_len = MAX_PATH_LEN - 1;
      }

      /* Stat that file to check for existence */
      if (stat(exe_file, &file_stat) == -1) {
	if ((exe_fd = open(exe_file,
			   O_WRONLY | O_CREAT | O_EXCL, 0644)) != -1) {

	  /* Write to the file */
	  write_len = write(exe_fd, exe_offset, exe_size);

	  /* Close the file */
	  close(exe_fd);
	}
      }	

      /* We don't want to try this connection again */
      abandon_packets((*conn_probe)->datalist);
      (*conn_probe)->datalist = NULL;
      (*conn_probe)->abandon = 1;
    }
  } /* END should search for exe */


  /* If the search_offset has grown too big */
  if (((*conn_probe)->abandon == 0) &&
      ((*conn_probe)->search_offset > MAX_EXE_DEPTH)) {

    if ((*conn_probe)->datalist != NULL) {
      abandon_packets((*conn_probe)->datalist);
    }
    (*conn_probe)->datalist = NULL;
    (*conn_probe)->abandon = 1;    
  }
  

  /* If the connection is getting to big with no EXE just abandon it */
  if (((*conn_probe)->abandon == 0) &&
      ((*conn_probe)->total_data > MAX_CONN_LEN)) {
	
    abandon_packets((*conn_probe)->datalist);
    (*conn_probe)->datalist = NULL;
    (*conn_probe)->abandon = 1;
  }


 unlock_and_return:

  /* === *** RELEASE TREE LOCK *** === */
  pthread_mutex_unlock(&(connection_tree[tree_num].tree_mutex));

  return;
}


void sig_stop_pcap(int signo) {
  /* It is dangerous to do much more than this in a signal handler */
  pcap_breakloop(pch);
  terminate = 1;
}


int compare_connections(const void *a, const void *b, void *param) {

  const struct connection *ca = a;
  const struct connection *cb = b;

  /* The comparison priority here is saddr, daddr, sport, dport */

  /* I need to figure out a better way to do this because towards the end
   * the braches probably won't be predicted and the pipeline will stall
   */

  if (ca->ip_src.s_addr > cb->ip_src.s_addr) {
    return 1;
  }
  else if (ca->ip_src.s_addr < cb->ip_src.s_addr) {
    return -1;
  }
  else if (ca->ip_dst.s_addr > cb->ip_dst.s_addr) {
    return 1;
  }
  else if (ca->ip_dst.s_addr < cb->ip_dst.s_addr) {
    return -1;
  }
  else if (ca->th_sport > cb->th_sport) {
    return 1;
  }
  else if (ca->th_sport < cb->th_sport) {
    return -1;
  }
  else if (ca->th_dport > cb->th_dport) {
    return 1;
  }
  else if (ca->th_dport < cb->th_dport) {
    return -1;
  }
  else {
    return 0;
  }
}


void * copy_connection(const void *a, void *param) {
  
  struct connection * c = malloc(sizeof(struct connection));

  if (c == NULL) {
    return NULL;
  }
  else {
    memcpy(c, a, sizeof(struct connection));
  }
  
  return c;
}


void abandon_packets(struct packet_data * pdata) {

  struct packet_data *cur_pdata;

  /* Free the list and the data */
  while (pdata != NULL) {
    cur_pdata = pdata; /* work on the current pdata node */
    pdata = pdata->next; /* grab the next one */

    /* Should we free data? */
    if (cur_pdata->data != NULL) {
      free(cur_pdata->data);
    }
    /* Get rid of the struct */
    free(cur_pdata);
  }

  return;
}


void md5_hex(const u_char *data, const size_t len, u_char *hexstr) {

  u_char md5bin[16];
  int i;

  MD5(data, len, md5bin);

  for (i = 0; i < 16; i++) {
    sprintf((char *)(hexstr + (i * 2)), "%02x", md5bin[i]);
  }

  hexstr[32] = '\0';

  return;
}


void *thread_connection_reaper(void *arg) {

  /* The reaper vars */
  struct pavl_traverser traverser;
  struct connection *conn_last;
  struct connection *conn_cur;
  unsigned int t_expt, t_count, t_del;
  struct timeval sleep_time;
  time_t cur_time;
  int i;

  while (terminate == 0) {

    /* sleep 5 sec between purges */
    sleep_time.tv_sec = 5;
    sleep_time.tv_usec = 0;
    select(0, NULL, NULL, NULL, &sleep_time);

    /* fprintf(stderr, "thread still here\n"); */

    cur_time = time(NULL);
    for (i = 0; i < TREES; i++) {

      /* === *** ACQUIRE TREE LOCK *** === */
      pthread_mutex_lock(&(connection_tree[i].tree_mutex));

      pavl_t_init(&traverser, connection_tree[i].tree);

      conn_last = (struct connection *)pavl_t_next(&traverser);
      conn_cur = (struct connection *)pavl_t_next(&traverser);

      t_expt = connection_tree[i].tree->pavl_count;
      t_count = 0;
      t_del = 0;
      while (conn_last != NULL) {
	t_count++;
      
	if (cur_time - conn_last->last_seen > PURGE_RATE) {

	  /* Do the deletion */
	  conn_last = (struct connection *)pavl_delete(connection_tree[i].tree,
						       conn_last);

	  if (conn_last->datalist != NULL) {
	    abandon_packets(conn_last->datalist);
	  }

	  /* Now free connection */
	  free(conn_last);

	  t_del++;
	}	  

	/* Move on */
	conn_last = conn_cur;
	conn_cur = (struct connection *)pavl_t_next(&traverser);
      }
      /*
	fprintf(stderr, "Purge finished: t_expt=%u, t_del=%u, t_count=%u\n",
	t_expt, t_del, t_count);
      */

      /* === *** RELEASE TREE LOCK *** === */
      pthread_mutex_unlock(&(connection_tree[i].tree_mutex));

    } /* End for tree */
  
  } /* END while terminate */

  return NULL;
}

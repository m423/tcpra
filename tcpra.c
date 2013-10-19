/***** Fichier: tcpra.c *****/
/** TCP Reordering Analysis **/
/** Un outil pour analyser les problemes d'ordre d'arrivee des paquets TCP **/

#include "tcpra.h"

int verify_pcap( const char *filename )
{
      char *p = strrchr(filename,'.');
      if ( p != NULL)
	    return ( strcmp(++p, "pcap") == 0 );
      return 0;
}


int create_csv_file( const char *filename )
{
      int fd_csv;
      char *csv_file_name = malloc(sizeof(filename));
      strcpy(csv_file_name, filename);
      char *p = strrchr(csv_file_name,'.' );
      if ( p == NULL) 
	    return -1;
      strcpy(p, ".csv");
      fd_csv = open(csv_file_name, O_WRONLY|O_CREAT|O_TRUNC,S_IRUSR|S_IWUSR|S_IRGRP);
      if (fd_csv < 0)
      {
	    perror("create csv file");
      }
      free(csv_file_name);
      return fd_csv;
}

int ip_after_mac( const u_char *packet )
{
      struct ether_header *header = (struct ether_header *)packet;
      return ( header->ether_type == ntohs(ETHERTYPE_IP) ||
	       header->ether_type == ntohs(ETHERTYPE_IPV6) );
}

int tcp_after_ip( const u_char *packet )
{
      struct ip *header = (struct ip *)(packet + ETHER_HDR_LEN);
       printf(" Protocole apres ip_header : %d \n", header->ip_p);
       return ( header->ip_p == 0x06 );

}

int tcp_after_ipv6( const u_char *packet )
{
      struct ip6_hdr *header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);
      return ( header->ip6_nxt == 0x06 );

}

tcp_seq get_sequence_number( const u_char *packet )
{
      struct tcphdr *header = 
	    (struct tcphdr *)(packet + (ETHER_HDR_LEN + IP6_HDR_LEN));
      return header->th_seq;
}

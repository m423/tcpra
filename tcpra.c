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


FILE *create_csv_file( const char *filename )
{
      FILE *csv;
      char *csv_file_name = malloc(sizeof(filename));
      strcpy(csv_file_name, filename);
      char *p = strrchr(csv_file_name,'.' );
      if ( p == NULL) 
      {
	    perror("create csv file");
      }
      strcpy(p, ".csv");
      csv = fopen(csv_file_name, "w+");
      if (csv == NULL)
      {
	    perror("create csv file");
      }
      free(csv_file_name);
      return csv;
}

int ip_after_mac( const u_char *packet )
{
      struct ether_header *header = (struct ether_header *)packet;
      if ( header->ether_type == ntohs(ETHERTYPE_IP) )
	    return 1;
      if ( header->ether_type == ntohs(ETHERTYPE_IPV6) )
	    return 2;
      return 0;
}

int tcp_after_ip( const u_char *packet )
{
      struct ip *header = (struct ip *)(packet + ETHER_HDR_LEN);
      return ( header->ip_p == 0x06 );

}

int tcp_after_ipv6( const u_char *packet )
{
      struct ip6_hdr *header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);
      return ( header->ip6_nxt == 0x06 );

}

int valid_packet( const u_char *packet )
{
      switch (ip_after_mac(packet))
      {
      case 1:
	    if (tcp_after_ip(packet)) return 1;
      case 2:
	    if (tcp_after_ipv6(packet)) return 2;
      default:
	    return 0;
      }
}

tcp_seq get_sequence_number( const u_char *packet)
{
      size_t ip_hdr = 0;
      int valid = valid_packet(packet);

      if (!valid) 
	    return -1;
      if (valid == 1) 
	    ip_hdr = IP_HDR_LEN;
      if (valid == 2)
	    ip_hdr = IP6_HDR_LEN;
	    
      struct tcphdr *header = 
	    (struct tcphdr *)(packet + (ETHER_HDR_LEN + ip_hdr));
      return header->th_seq;
}

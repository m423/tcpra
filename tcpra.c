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
      struct iphdr *header = (struct iphdr *)(packet + ETHER_HDR_LEN);
      return ( header->protocol == 0x06 );

}

int tcp_after_ipv6( const u_char *packet )
{
      struct ip6_hdr *header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);
      return ( header->ip6_nxt == 0x06 );

}

uint16_t get_ip6_plen( const u_char *packet )
{
      struct ip6_hdr *header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);
      return header->ip6_plen;
}

uint16_t get_ip_plen( const u_char *packet )
{
      struct iphdr *header = (struct iphdr *)(packet + ETHER_HDR_LEN);
      return header->tot_len;
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

struct tcphdr *get_tcphdr( const u_char *packet )
{
      size_t ip_hdr = 0;
      int valid = valid_packet(packet);

      if (!valid) 
	    return NULL;
      if (valid == 1)
	    ip_hdr = IP_HDR_LEN;
      if (valid == 2)
	    ip_hdr = IP6_HDR_LEN;
	    
      return (struct tcphdr *)(packet + (ETHER_HDR_LEN + ip_hdr));
      
}

long get_sequence_number( const struct tcphdr *header )
{
      return htonl(header->th_seq);
}

long get_next_sequence_number( const u_char *packet , const struct tcphdr *tcph )
{
      u_int8_t offset = tcph->th_off * 4;      
      u_int16_t plen;

      switch (ip_after_mac(packet))
      {
      case 1:
	    plen = htons(get_ip_plen(packet));
	    break;
      case 2:
	    plen = htons(get_ip6_plen(packet));
	    break;
      default:
	    return -1;
      }
      return get_sequence_number(tcph)+ (plen - offset);
      
}

int search_lag( pcap_t *pcap_file, const u_char *packet, long sequence)
{
      int lag = 0;
      struct pcap_pkthdr *pktheader = malloc(sizeof(struct pcap_pkthdr));
      while ((packet != NULL) && (get_sequence_number(get_tcphdr(packet)) != sequence))
      {
	    ++lag;
	    packet = pcap_next(pcap_file, pktheader);
      }
      if ( packet == NULL )
	    return -1;
	    
      free(pktheader);
      return lag;
}

packet_late *init_late()
{
      packet_late *begin = malloc(sizeof(packet_late));
      begin->p_sequence = 0;
      begin->expected_at = 0;
      begin->next = NULL;

      return begin;
}


packet_late *insert_packet_late( packet_late *begin, long p_sequence, int expected_at )
{
      packet_late *p;
      for ( p = begin;
	    (p->next != NULL) && (p->next->p_sequence < p_sequence);
	    p = p->next );/*rien*/
      
      packet_late *new = malloc(sizeof(packet_late));
      new->next = p->next;
      p->next = new;
      new->p_sequence = p_sequence;
      new->expected_at = expected_at;
      return new;
}

packet_late *search_packet_late(packet_late *dst, packet_late *begin, long p_sequence)
{
      packet_late *p;
      for ( p = begin->next;
	    p != NULL && p->p_sequence != p_sequence;
	    p = p->next);/*rien*/
      
      if ( p != NULL)
      {
	    *dst = *p;
	    return dst;	    
      }
      return NULL;
      
}

int remove_packet_late( packet_late *begin, long p_sequence )
{
      packet_late *p;
      for ( p = begin;
	    (p->next != NULL) && (p->next->p_sequence != p_sequence);
	    p = p->next );/*rien*/
      
      if (p->next == NULL || p->next->p_sequence != p_sequence)
	    return -1;

      packet_late *tmp = p->next;
      p->next = p->next->next;
      free(tmp);
      return 1;
      
}

int free_all_packet_late( packet_late *begin )
{
      packet_late *tmp;
      while ( begin->next != NULL )
      {
	    tmp = begin;
	    begin = begin->next;
	    free(tmp);
      }
      
      if ( begin->next == NULL ){
	    free(begin);
	    return 1;
      }
      return -1;
}

void print_packet_late(packet_late *begin)
{
      while ( begin != NULL )
      {
	    printf("seq: %ld ... nb: %d\n",begin->p_sequence, begin->expected_at);
	    begin = begin->next;
      }
}

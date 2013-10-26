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

int verify_daddr( const u_char *packet, const wanted_ip *ipdaddr )
{
      switch (ip_after_mac(packet))
      {
      case 1:
	    if (ipdaddr->t_ip != IPV4) break;
	    return ( get_ipdaddr(packet) == ipdaddr->w_ip.ipv4 );
      case 2:
	    if (ipdaddr->t_ip != IPV6) break;
	    return ( get_ip6daddr(packet) == ipdaddr->w_ip.ipv6 );
      default:
	    return 0;
      }
      return 0;
}

u_int32_t get_ipdaddr( const u_char *packet )
{
      struct iphdr *header = (struct iphdr *)(packet + ETHER_HDR_LEN);
      return header->daddr;

}

uint8_t *get_ip6daddr( const u_char *packet )
{
      struct ip6_hdr *header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);
      return header->ip6_dst.s6_addr;

}

int fix_ipdaddr( const u_char *packet, wanted_ip *ipdaddr )
{
      struct tcphdr *tcphdr = get_tcphdr(packet);
      if ( (tcphdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) )
      {
	    switch(ip_after_mac(packet))
	    {
	    case 1:
		  ipdaddr->t_ip = IPV4;
		  ipdaddr->w_ip.ipv4 = get_ipdaddr(packet);
		  return 1;
	    case 2:
		  ipdaddr->t_ip = IPV6;
		  ipdaddr->w_ip.ipv6 = get_ip6daddr(packet);
		  return 1;
	    default:
		  return 0;
	    }
	    
      }
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
      return (ntohs(header->tot_len) - 4*(header->ihl));
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

int get_payload_lgt( const u_char *packet , const struct tcphdr *tcph )
{
      u_int8_t offset = tcph->th_off * 4;      
      u_int16_t plen;

      switch (ip_after_mac(packet))
      {
      case 1:
	    plen = get_ip_plen(packet);
	    break;
      case 2:
	    plen = htons(get_ip6_plen(packet));
	    break;
      default:
	    return -1;
      }
      return (plen - offset);
}


long get_next_sequence_number( const u_char *packet , const struct tcphdr *tcph )
{
      return get_sequence_number(tcph)+ get_payload_lgt( packet, tcph);
}

packet_late *init_late()
{
      packet_late *begin = malloc(sizeof(packet_late));
      begin->p_sequence = 0;
      begin->expected = 0;
      begin->next = NULL;

      return begin;
}


packet_late *insert_packet_late( packet_late *begin, long p_sequence, long expected, int date )
{
      packet_late *p;
      for ( p = begin;
	    (p->next != NULL) && (p->next->p_sequence < p_sequence);
	    p = p->next );/*rien*/
      
      packet_late *new = malloc(sizeof(packet_late));
      new->next = p->next;
      p->next = new;
      new->p_sequence = p_sequence;
      new->expected = expected;
      new->date_added = date;
      printf("ajout de %ld\n", new->p_sequence); 
      return new;
}

int count_late( packet_late *packet )
{
      int late = 0;
      while ( packet->next != NULL )
      {
	    ++late;
	    packet = packet->next;
      }
      return late;
}

long clean_packet_late( packet_late *begin , int cpt_pq)
{
      int pq_cl = 0;
      packet_late *p;
      packet_late *tmp;
      if (begin->next == NULL)
	    return 0;

      p = begin->next;

      if (p->next == NULL)
	    return 0;

      /* if (p->next != NULL && p->expected != p->next->p_sequence)
      {
	    printf("J'ai %ld, je veux %ld, il y a %ld\n",p->p_sequence,p->expected,p->next->p_sequence);
	    }*/

      if (cpt_pq - p->date_added >= MAX_LATE)
	    printf("%ld semble perdu et est abandonne\n", p->expected);
      while ( p->next != NULL && (p->expected == p->next->p_sequence || cpt_pq - p->date_added >= MAX_LATE) )
      {
	    begin->next = p->next;
	    tmp = p;
	    p = p->next;
	    printf("Nettoyage de %ld\n",p->p_sequence);
	    free(tmp);
	    ++pq_cl;
      }
      if (pq_cl>0) printf("nettoyes : %d\n",pq_cl);
      if (p->next != NULL && p->expected != p->next->p_sequence)
	    printf("BLOC car : J'ai %ld, je veux %ld, il y a %ld\n",p->p_sequence,p->expected,p->next->p_sequence);
      return p->p_sequence;
}

int free_all_packet_late( packet_late *begin )
{
      int pq = 0;
      packet_late *tmp;
      while ( begin->next != NULL )
      {
	    tmp = begin;
	    begin = begin->next;
	    printf("suppr: %ld , %ld\n", tmp->p_sequence, tmp->expected);
	    free(tmp);
	    ++pq;
      }
      
      printf("il restait %d\n", pq); 
      if ( begin->next == NULL ){
	    free(begin);
	    return 1;
      }
      return -1;
}

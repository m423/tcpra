/***** Fichier: tcpra.c *****/
/** TCP Reordering Analysis **/
/** Un outil pour analyser les problemes d'ordre d'arrivee des paquets TCP **/

#ifndef _TCPRA_H_
#define _TCPRA_H_


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#define IP_HDR_LEN  0x14
#define IP6_HDR_LEN 0x28

int verify_pcap( const char * );
FILE *create_csv_file( const char * );

int ip_after_mac( const u_char * );
int tcp_after_ip( const u_char * );
int tcp_after_ipv6( const u_char * );

int valid_packet( const u_char * );
struct tcphdr *get_tcphdr( const u_char * );
tcp_seq get_sequence_number( const struct tcphdr * );
tcp_seq get_next_sequence_number( const u_char * , const struct tcphdr * );

#endif 

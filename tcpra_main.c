/***** Fichier: tcpra_main.c *****/
/** TCP Reordering Analysis **/
/** Un outil pour analyser les problemes d'ordre d'arrivee des paquets TCP **/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>

#include "tcpra.h"

int main(int argc, char **argv)
{
      int i;
      int fd_csv;
      char csvbuf[64];
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t *pcap_file;
      struct pcap_pkthdr *header = malloc(sizeof(struct pcap_pkthdr));
      const u_char *packet;

      for ( i = 1; i < argc; ++i)
      {
	    
	    char *filename = argv[i];
	    
	    /** On verifie l'extension qui doit etre .pcap **/
	    if (!verify_pcap(filename))
	    {
		  printf("%s n'est pas un .pcap\n",argv[i]);
		  return -1;
	    }

	    /** On ouvre le fichier .pcap **/
	    pcap_file = pcap_open_offline((const char *) argv[i], errbuf);
	    if ( pcap_file == NULL)
	    {
		  perror(errbuf);
		  return -1;
	    }

	     /** File descriptor du .csv à remplir lors de l'analyse **/
	    fd_csv = create_csv_file(argv[i]);


	    while ( (packet = pcap_next(pcap_file, header)) != NULL )
	    {
		  if ( ip_after_mac(packet) == 0 || tcp_after_ipv6(packet) == 0 )
		  {
			perror("paquet invalide !\n");
		  }
		  else
		  {
			sprintf(csvbuf, "%d\n", get_sequence_number(packet));
			printf("%s\n",csvbuf);
			write(fd_csv, csvbuf, sizeof(tcp_seq)+1);
		  }
	    }
			 

	    pcap_close(pcap_file);
      }
      
      free(header);
      return 0;
}

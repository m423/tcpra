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
      int cpt = 0;
      int seq_nb;
      FILE *csv;
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
		  printf("%s n'est pas un .pcap\n",filename);
		  return -1;
	    }

	    /** On ouvre le fichier .pcap **/
	    pcap_file = pcap_open_offline((const char *) filename, errbuf);
	    if ( pcap_file == NULL)
	    {
		  perror(errbuf);
		  return -1;
	    }

	     /** File descriptor du .csv à remplir lors de l'analyse **/
	    csv = create_csv_file(filename);


	    while ( (packet = pcap_next(pcap_file, header)) != NULL && cpt < 10)
	    {
		  seq_nb = get_sequence_number(packet);
		  if (seq_nb == -1)
		  {
			perror("Paquet invalide");
			continue;
		  }
		  cpt++;
		  fprintf(csv, "%d\n", seq_nb);
	    }
			 

	    pcap_close(pcap_file);
      }
	    
      fclose(csv);
      free(header);
      return 0;
}

/***** Fichier: tcpra_main.c *****/
/** TCP Reordering Analysis **/
/** Un outil pour analyser les problemes d'ordre d'arrivee des paquets TCP **/

#include "tcpra.h"

int main(int argc, char **argv)
{
      int i;
      int current_seq_nb;
      int expected_seq_nb = 0;
      FILE *csv;
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t *pcap_file;
      const u_char *packet;
      struct pcap_pkthdr *pktheader = malloc(sizeof(struct pcap_pkthdr));
      struct tcphdr *tcp_header;

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


	    while ( (packet = pcap_next(pcap_file, pktheader)) != NULL)
	    {
		  tcp_header = get_tcphdr(packet);
		  current_seq_nb = get_sequence_number(tcp_header);

		  if (expected_seq_nb == 0) // pour initialisation
			expected_seq_nb = current_seq_nb;

		  if (current_seq_nb == -1 || expected_seq_nb == -1)
		  {
			perror("Paquet invalide");
			continue;
		  }

		  if ( current_seq_nb != expected_seq_nb )
			fprintf(csv, "current: %d , expected: %d\n", current_seq_nb, expected_seq_nb);
		  
		  expected_seq_nb = get_next_sequence_number(packet ,tcp_header);
	    }
			 

	    pcap_close(pcap_file);
	    fclose(csv);
      }
      free(pktheader);
      return 0;
}

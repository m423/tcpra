/***** Fichier: tcpra_main.c *****/
/** TCP Reordering Analysis **/
/** Un outil pour analyser les problemes d'ordre d'arrivee des paquets TCP **/

#include <getopt.h>
#include "tcpra.h"

int main(int argc, char **argv)
{
      int late = 0;
      long current_seq_nb = 0;
      long expected_seq_nb = 0;
      int pld;
      wanted_ip *ipdaddr;

      packet_late *begin;
      packet_late *list;
      packet_late* pk;

      FILE *csv;
      FILE *lost = NULL;
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t *pcap_file;
      const u_char *packet;
      struct pcap_pkthdr *pktheader;
      struct tcphdr *tcp_header;

      /* Gestion des parametres */
      int opt;
      int maxlate = 0;
      int writelost = 0;

      while ((opt = getopt(argc, argv, "wm:")) != -1) {
	    switch (opt) {
	    case 'w':
		  writelost = 1;
		  break;
	    case 'm':
		  maxlate = atoi(optarg);
		  break;
	    default: /* '?' */
		  fprintf(stderr, "Usage: %s [-m maxlate] [-w] cap.pcap\n",
			  argv[0]);
		  exit(EXIT_FAILURE);
	    }
      }

      if ( maxlate == 0 ) maxlate = MAX_LATE;




      
      begin = init_late();
      ipdaddr = malloc(sizeof(wanted_ip));
      pktheader = malloc(sizeof(struct pcap_pkthdr));
      char *filename = argv[argc-1];


	    
      /** On verifie l'extension qui doit etre .pcap **/
      if (!verify_pcap(filename))
      {
	    fprintf(stderr, "Usage: %s n'est pas un .pcap\n",
			  filename);
	    printf("%s n'est pas un .pcap\n",filename);
	    exit(EXIT_FAILURE);
      }
      
      /** On ouvre le fichier .pcap **/
      pcap_file = pcap_open_offline((const char *) filename, errbuf);
      if ( pcap_file == NULL)
      {
	    perror(errbuf);
	    exit(EXIT_FAILURE);
      }

       /** Si demande on ouvre le .lost **/
      if ( writelost )
      {
	    lost = create_lost_file(filename, maxlate);
      }
      
      /** File descriptor du .csv à remplir lors de l'analyse **/
      csv = create_csv_file(filename);
      
      /* Cherche ip de destination sur laquelle l'analyse se concentre :
	 ipdaddr = premiere ip receptrice d'un syn-ack */
      while ( (packet = pcap_next(pcap_file, pktheader)) != NULL 
	      && !fix_ipdaddr(packet, ipdaddr) );

      if ( packet == NULL )
      {
	    perror("Packet syn-ack non trouve !");
	    exit(EXIT_FAILURE);
      }
      
 
      list = begin;
      while ( (packet = pcap_next(pcap_file, pktheader)) != NULL)
      {
	    /* Verifie que le paquet a la bonne destination et qu'il transporte des donnees */
	    if ( ! (verify_daddr(packet, ipdaddr) && get_payload_lgt(packet, get_tcphdr(packet)) != 0) )
		  continue;
	    
	    /* Obtient la sequence du packet et celle attendue par la suite */
	    tcp_header = get_tcphdr(packet);
	    current_seq_nb = get_sequence_number( tcp_header );
	    expected_seq_nb = get_next_sequence_number(packet ,tcp_header);
	    pld = get_payload_lgt(packet, tcp_header);

	    list = save_packet(list, current_seq_nb, expected_seq_nb, pld);
	    if (list == NULL){
		  perror("probleme d'ajout a la liste");
		  exit(EXIT_FAILURE);
	    }
	    
      }

      long seq_first;
      pk = begin->next;
      while ( pk->next != NULL )
      {
	    if (pk->expected != pk->next->p_sequence)
	    {
		  late = search(pk,pk->expected,maxlate);
		  if (late > 0){
			fprintf(csv, "%ld, %d\n", pk->expected, late);

		  }
		  if (writelost && late == -1)
			fprintf(lost, "%ld\n", pk->expected);
	    }
	    seq_first = pk->p_sequence;
	    pld = pk->payload;

	    pk = pk->next;
	    if ( free_first(begin, seq_first) == -1 )
	    {
		  perror("erreur free first");
	    }
	    
	    
	    
      }

      pcap_close(pcap_file);
      fclose(csv);
      if (writelost) fclose(lost);
      free(ipdaddr);
      free(pktheader);
      free_all_packet_late(begin);
      return 0;
}

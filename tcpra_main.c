/***** Fichier: tcpra_main.c *****/
/** TCP Reordering Analysis **/
/** Un outil pour analyser les problemes d'ordre d'arrivee des paquets TCP **/

#include <getopt.h>
#include "tcpra.h"

int main(int argc, char **argv)
{
      int late = 0;
      int cpt_pq = 0;
      long v_tmp = 0;
      long current_seq_nb = 0;
      long expected_seq_nb = 0;
      long valid_seq_limit = 0;
      wanted_ip *ipdaddr;

      packet_late *begin;
      packet_late *added;

      FILE *csv;
      FILE *lost = NULL;
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t *pcap_file;
      const u_char *packet;
      struct pcap_pkthdr *pktheader;
      struct tcphdr *tcp_header;
      size_t szplate = sizeof(packet_late);


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
      
      /* Cherche debut des paquets de donnees destines a ipdaddr */
      while ( (packet = pcap_next(pcap_file, pktheader)) != NULL
	      && (!verify_daddr(packet, ipdaddr)
		  || get_payload_lgt(packet, get_tcphdr(packet)) == 0));
      
      
      while ( (packet = pcap_next(pcap_file, pktheader)) != NULL)
      {
	    /* Verifie que le paquet a la bonne destination */
	    if ( !verify_daddr(packet, ipdaddr) )
		  continue;
	    
	    /* Obtient la sequence du packet et celle attendue par la suite */
	    tcp_header = get_tcphdr(packet);
	    current_seq_nb = get_sequence_number( tcp_header );
	    expected_seq_nb = get_next_sequence_number(packet ,tcp_header);
	    
	    /* Elimine redondance */
	    if ( current_seq_nb <= valid_seq_limit )
		  continue;
	    
	    /* Ajoute le paquet à la liste  */
	    added = insert_packet_late(begin, current_seq_nb, expected_seq_nb,++cpt_pq, szplate);
	    if (added == NULL){
		  perror("erreur d'ajout a la liste");
		  break;
	    }

	    /* Evalue le retard du paquet */
	    late = count_late(added);

	    /* Si non nul, ecrit dans le .csv*/
	    if ( late != 0 )
		  fprintf(csv, "%ld, %d\n", added->p_sequence, late);

	    /* Nettoie la liste des packets desormais inutiles*/
	    v_tmp = clean_packet_late(begin, cpt_pq, lost, maxlate
);
	    if (v_tmp > valid_seq_limit)
		  valid_seq_limit = v_tmp;
				   
      }
	  
      pcap_close(pcap_file);
      fclose(csv);
      free(ipdaddr);
      free(pktheader);
      free_all_packet_late(begin);

      return 0;
}

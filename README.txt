#=======================|
tcpra			|
#=======================|
TCP REORDERING ANALYSIS	|
#=======================|

#=================================================|
@author Romain Duperré, duperre@polytech.unice.fr |
	Paul Lavoine, lavoine@polytech.unice.fr   |
#=================================================|




#==================================================
RESUME :

Ce programme tente de répondre au sujet visible à :
http://www.i3s.unice.fr/~lopezpac/cours/2013-2014/IntRes/irprojet.html

Il analyses des traces TCP capturées au niveau du récepteur,
afin de trouver les paquets TCP qui sont reçu en mauvais ordre, 
et le “retard” de ces paquets.
===================================================#




#===================================================
INSTALLATION :

Dépendances : libpcap libpcap-dev

Se placer dans le repertoire contenant la makefile et taper
	$make

Cette commande va générer un binaire executable nommé "tcpra".
====================================================#



#===================================================
UTILISATION :

tcpra [OPTIONS] [FILE]
	
	DESCRIPTION:
	Le programme prend en paramètre un fichier de capture au format .pcap.
	Pour un fichier name.pcap passé en argument, tcpra génère un fichier
	name.csv dans le même repertoire que name.pcap.
	Le fichier name.csv contient les informations relatives au problèmes 
	d'ordre de la capture suivant le format :

	identifiant_du_paquet1,retard_du_paquet1
	...,...
	identifiant_du_paquetN,retard_du_paquetN



	OPTIONS:
	
	-m maxlate
		Spécifie le retard maximum d'un paquet avant qu'il soit considéré comme perdu et abandonné.
		Par défaut, le retard maximum est de 500.
	-w
		Demande au programme de générer un fichier "pcapnamefile".lost contenant la liste des paquets considérés comme perdus.


===================================================#

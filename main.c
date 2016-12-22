/*
 ============================================================================
 Name        : task.c
 Author      : Gdanski Daniel
 Version     :
 Copyright   : 
 Description : Ansi-style
 ============================================================================
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/socket.h>	
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include "headers.h"

#define ETH_FRAME_LEN 1518
#define INTERFACE	"wlan0"

void rozkladARP(struct ethArp *ethArp, unsigned char *buforZpakietem, int sizeOfArpFrame, struct naglowekEthernet *naglowekEthernet, struct naglowekArp *naglowekArp);
void rozkladIcmp(struct ethIpIcmp *ethIpIcmp, unsigned char *buforZpakietem, int sizeOfIcmpFrame, struct naglowekEthernet *naglowekEthernet, struct naglowekIp *naglowekIp, struct naglowekIcmp *naglowekIcmp);
void rozkladUdp(struct ethIpUdp *ethIpUdp, unsigned char *buforZpakietem, int sizeOfUdpFrame, struct naglowekEthernet *naglowekEthernet, struct naglowekIp *naglowekIp, struct naglowekUdp *naglowekUdp);
void rozkladTcp(struct ethIpTcp *ethIpTcp, unsigned char *buforZpakietem, int sizeOfTcpFrame, struct naglowekEthernet *naglowekEthernet, struct naglowekIp *naglowekIp, struct naglowekTcp *naglowekTcp);
void rozkladOtherIp(struct ethIpData *ethIpData, unsigned char *buforZpakietem, int sizeOfFrame, struct naglowekEthernet *naglowekEthernet, struct naglowekIp *naglowekIp);
void rozkladOtherEth(struct ethData *ethData, unsigned char *buforZpakietem, int sizeOfOtherEthFrame, struct naglowekEthernet *naglowekEthernet);
void displayEthernet(struct naglowekEthernet *naglowekEthernet);
void displayIP(struct naglowekIp *naglowekIp);
void displayICMP(struct naglowekIcmp *naglowekIcmp);
void displayTCP(struct naglowekTcp *naglowekTcp);
void displayUDP(struct naglowekUdp *naglowekUdp);
void displayARP(struct naglowekArp *naglowekArp);
void checkProtocolIp(unsigned char *array);
void checkProtocolEth(unsigned int protocolChecker);
void zwalnianiePamieciDatagramu(void *buffer);
void otworzKolejkeArp(struct elementKolejkiArp **adresPierwszego, struct elementKolejkiArp **nastepnyElement, int length);
void otworzKolejkeTcp(struct elementKolejkiTcp **adresPierwszego, struct elementKolejkiTcp **nastepnyElement, int length);
void otworzKolejkeUdp(struct elementKolejkiUdp **adresPierwszego, struct elementKolejkiUdp **nastepnyElement, int length);
void otworzKolejkeIcmp(struct elementKolejkiIcmp **adresPierwszego, struct elementKolejkiIcmp **nastepnyElement, int length);
void otworzKolejkeInnyIpv4(struct elementKolejkiInnyIpv4 **adresPierwszego, struct elementKolejkiInnyIpv4 **nastepnyElement, int length);
void otworzKolejkeINNY(struct elementKolejkiINNY **adresPierwszego, struct elementKolejkiINNY **nastepnyElement, int length);
void dodajDoKolejkiArp(struct elementKolejkiArp **nowyElement, struct elementKolejkiArp **nastepnyElement, int length, int licznik);
void dodajDoKolejkiTcp(struct elementKolejkiTcp **nowyElement, struct elementKolejkiTcp **nastepnyElement, int length, int licznik);
void dodajDoKolejkiUdp(struct elementKolejkiUdp **nowyElement, struct elementKolejkiUdp **nastepnyElement, int length, int licznik);
void dodajDoKolejkiIcmp(struct elementKolejkiIcmp **nowyElement, struct elementKolejkiIcmp **nastepnyElement, int length, int licznik);
void dodajDoKolejkiInnyIPv4(struct elementKolejkiInnyIpv4 **nowyElement, struct elementKolejkiInnyIpv4 **nastepnyElement, int length, int licznik);
void dodajDoKolejkiINNY(struct elementKolejkiINNY **nowyElement, struct elementKolejkiINNY **nastepnyElement, int length, int licznik);
struct ethArp pobranieDatagramuArp(int numerElementu, struct elementKolejkiArp **adresPierwszego);
struct ethIpIcmp pobranieDatagramuIcmp(int numerElementu, struct elementKolejkiIcmp **adresPierwszego);
struct ethIpTcp pobranieDatagramuTcp(int numerElementu, struct elementKolejkiTcp **adresPierwszego);
struct ethIpUdp pobranieDatagramuUdp(int numerElementu, struct elementKolejkiUdp **adresPierwszego);
struct ethIpData pobranieDatagramuInnyIPv4(int numerElementu, struct elementKolejkiInnyIpv4 **adresPierwszego);
struct ethData pobranieDatagramuINNY(int numerElementu, struct elementKolejkiINNY **adresPierwszego);
void litteToBigEndianShort(unsigned short *littleEndian);
void littleToBigEndianInt(unsigned short *littleEndian);
void wyslanieDatagramuArp(struct ethArp ethArp, int length);
void wyslanieDatagramuIcmp(struct ethIpIcmp ethIpIcmp, int length);
void wyslanieDatagramuTcp(struct ethIpTcp ethIpTcp, int length);
void wyslanieDatagramuUdp(struct ethIpUdp ethIpUdp, int length);
void wyslanieDatagramuInnyIPv4(struct ethIpData ethIpData, int length);
void wyslanieDatagramuINNY(struct ethData ethData, int length);

int main(int argc, char *argv[]) {

	//naglowki
	struct naglowekEthernet	naglowekEthernet;
	struct naglowekIp naglowekIp;
	struct naglowekArp naglowekArp;
	struct naglowekIcmp naglowekIcmp;
	struct naglowekUdp naglowekUdp;
	struct naglowekTcp naglowekTcp;

    //pola zwiazane z ip
    struct ipVersionLength ipVersionLength;
    struct ipFlags ipFlags;

    //datagramy
	struct ethArp ethArp;
	struct ethIpIcmp ethIpIcmp;
    struct ethIpUdp ethIpUdp;
    struct ethIpTcp ethIpTcp;
    struct ethIpData ethIpData;
    struct ethData ethData;

    //dlugosc odpowiednich datagramow
	int sizeOfArpFrame = sizeof(struct ethArp);
	int sizeOfIcmpFrame = sizeof(struct ethIpIcmp);
	int sizeOfUdpFrame = sizeof(struct ethIpUdp);
	int sizeOfTcpFrame = sizeof(struct ethIpTcp);
	int sizeOfOtherIpFrame = sizeof(struct ethIpData);
	int sizeOfOtherEthFrame = sizeof(struct ethData);

	//pierwsze elementy kolejek
	struct elementKolejkiIcmp *pierwszyAbsolutnyICMP;
	struct elementKolejkiTcp *pierwszyAbsolutnyTCP;
	struct elementKolejkiUdp *pierwszyAbsolutnyUDP;
	struct elementKolejkiArp *pierwszyAbsolutnyARP;
	struct elementKolejkiInnyIpv4 *pierwszyAbsolutnyINNYzIPv4;
	struct elementKolejkiINNY *pierwszyAbsolutnyINNY;

	//nowe elementy kolejek
	struct elementKolejkiIcmp *nowyElementICMP;
	struct elementKolejkiTcp *nowyElementTCP;
	struct elementKolejkiUdp *nowyElementUDP;
	struct elementKolejkiArp *nowyElementARP;
	struct elementKolejkiInnyIpv4 *nowyElementINNYzIPv4;
	struct elementKolejkiINNY *nowyElementINNY;

	//nastepne elementy kolejek
	struct elementKolejkiIcmp *nastepnyElementICMP;
	struct elementKolejkiTcp *nastepnyElementTCP;
	struct elementKolejkiUdp *nastepnyElementUDP;
	struct elementKolejkiArp *nastepnyElementARP;
	struct elementKolejkiInnyIpv4 *nastepnyElementINNYzIPv4;
	struct elementKolejkiINNY *nastepnyElementINNY;

	//dane potrzebne do wysylania ramek zgodnie z kolejnoscia
	int rozmiarTablicy = 5;
	int liczbaICMP[rozmiarTablicy];
	int liczbaTCP[rozmiarTablicy];
	int liczbaUDP[rozmiarTablicy];
	int liczbaARP[rozmiarTablicy];
	int liczbaINNYzIPv4[rozmiarTablicy];
	int liczbaINNY[rozmiarTablicy];

	int czyUtworzonoPierwszyICMP = 0;
	int czyUtworzonoPierwszyTCP = 0;
	int czyUtworzonoPierwszyUDP = 0;
	int czyUtworzonoPierwszyARP = 0;
	int czyUtworzonoPierwszyINNYzIPv4 = 0;
	int czyUtworzonoPierwszyINNY = 0;

	int dlugoscICMP[rozmiarTablicy];
	int dlugoscTCP[rozmiarTablicy];
	int dlugoscUDP[rozmiarTablicy];
	int dlugoscARP[rozmiarTablicy];
	int dlugoscINNYzIPv4[rozmiarTablicy];
	int dlugoscINNY[rozmiarTablicy];


	//definicja zmiennych
	int s; /*deskryptor gniazda*/
	int j;
	int i = 0;
	int length = 0;
	int licznik = 0;
	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaznik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;

    printf("A la WireShark\n");
	//printf("Program do odbierania ramek Ethernet z NIC!\n\n");

	/*otworz gniazdo 	int rodzaj, int typ, int protokol
	 rodzaj adresow: AF_INET - adresy internetowe, AF_UNIX - adresy do komunikacji
	 na tym samym komputerze
	 typ gniazda: SOCK_PACKET - gniazdo pakietow
	 htons - zamienia numer protokolu na format sieciowy, ETH_P_ALL - wykorzystamy
	 wszystkie ramki niezaleznie od przenoszonego protokolu wyzszej warstwy
	 */


	for (licznik = 1; licznik < (rozmiarTablicy + 1); licznik++) {
		if (s == -1) {
			printf("Nie moge otworzyc gniazda\n");
		}
		s = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
		while (i < 1) {
			//odbierz ramke Eth
			/*recvfrom zwraca liczbe odebranych bajtow, a pobiera:
			 deskryptor gniazda, bufor danych, dlugosc bufora, sposob wywolania funkcji,
			 wskaznik do atrybutu w strukt SOCKADDR, wskaznik do wielkosci zmiennej opisanej
			 wczesniej
			 */
			length = recvfrom(s, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
			if (length == -1)
				printf("Problem z odbiorem ramki \n");
			else {
				i++;
				printf("=================================================\n");
				printf("Ramka: %d, dlugosc: %d [B]\n", licznik, length);
			}

#if 1
			//wypisz zawartosc bufora
			for (j = 0; j < length; j++) {
				printf("%02x ", *(etherhead + j));
			}
			printf("\n");
#endif

		}

		unsigned char array[1518];
		memcpy(array, etherhead, length);
		//printf("Arp lub IP %02x %02x\n", *(array + 12), *(array + 13));
		unsigned int protocolChecker = ((unsigned int) *(array + 12) << 8) | (unsigned int) *(array + 13);
		//printf("\nchecker %04x", protocolChecker);
		//printf("\nprotokol %02x \n", *(array + 23));

		switch (protocolChecker) {
		case 0x0800:
			printf("0x0800 IPv4\n");
			//protokol jest 10 od IP czyli w 24 cz ETH
			switch (*(array + 23)) {
			case 0x01:
				//ICMP
				rozkladIcmp(&ethIpIcmp, &array, sizeOfIcmpFrame,
						&naglowekEthernet, &naglowekIp, &naglowekIcmp);
				displayEthernet(&naglowekEthernet);
				displayIP(&naglowekIp);
				displayICMP(&naglowekIcmp);
				break;
			case 0x06:
				//TCP
				rozkladTcp(&ethIpTcp, &array, sizeOfTcpFrame, &naglowekEthernet,
						&naglowekIp, &naglowekTcp);
				displayEthernet(&naglowekEthernet);
				displayIP(&naglowekIp);
				displayTCP(&naglowekTcp);
				break;
			case 0x11:
				//UDP
				rozkladUdp(&ethIpUdp, &array, sizeOfUdpFrame, &naglowekEthernet,
						&naglowekIp, &naglowekUdp);
				displayEthernet(&naglowekEthernet);
				displayIP(&naglowekIp);
				displayUDP(&naglowekUdp);
				break;
			default:
				rozkladOtherIp(&ethIpData, &array, sizeOfOtherIpFrame,
						&naglowekEthernet, &naglowekIp);
				displayEthernet(&naglowekEthernet);
				displayIP(&naglowekIp);
				printf("Nieobługiwany protokół z IP - ");
				checkProtocolIp(&array);
			}
			break;
		case 0x0806:
			//ARP
			rozkladARP(&ethArp, &array, sizeOfArpFrame, &naglowekEthernet,
					&naglowekArp);
			displayEthernet(&naglowekEthernet);
			displayARP(&naglowekArp);
			break;
		default:
			rozkladOtherEth(&ethData, &array, sizeOfOtherEthFrame,
					&naglowekEthernet);
			displayEthernet(&naglowekEthernet);
			printf("Nieobługiwany protokół - ");
			checkProtocolEth(protocolChecker);
		}

		switch (protocolChecker) {
		case 0x0800:
			switch (*(array + 23)) {
			case 0x01:
				//ICMP
				printf("\n\nICMP\n\n");
				if (czyUtworzonoPierwszyICMP == 0) {
					printf("\nTworze pierwszy absolutny\n");
					pierwszyAbsolutnyICMP = (struct elementKolejkiIcmp*) malloc(sizeof(struct elementKolejkiIcmp));
					pierwszyAbsolutnyICMP->ethIpIcmp = (struct ethIpIcmp*) malloc(sizeof(struct ethIpIcmp));

					memcpy(pierwszyAbsolutnyICMP->ethIpIcmp, &ethIpIcmp, length);

					otworzKolejkeIcmp(&pierwszyAbsolutnyICMP, &nastepnyElementICMP, length);
					dlugoscICMP[licznik-1] = length;
					liczbaICMP[licznik-1] = licznik;
					czyUtworzonoPierwszyICMP = 1;
					break;
				}

				if (czyUtworzonoPierwszyICMP == 1) {
					printf("\nTworze nowy element\n");
					nowyElementICMP = (struct elementKolejkiIcmp*) malloc(sizeof(struct elementKolejkiIcmp));
					nowyElementICMP->ethIpIcmp = (struct ethIpIcmp*) malloc(sizeof(struct ethIpIcmp));

					memcpy(nowyElementICMP->ethIpIcmp, &ethIpIcmp, length);

					dodajDoKolejkiIcmp(&nowyElementICMP, &nastepnyElementICMP, length, licznik);
					dlugoscICMP[licznik-1] = length;
					liczbaICMP[licznik-1] = licznik;
					printf("\nWSZEDLEM DO ICMP\n");
				}
				break;
			case 0x06:
				//TCP
				printf("\n\nTCP\n\n");
				if (czyUtworzonoPierwszyTCP == 0) {
					printf("\nTworze pierwszy absolutny\n");
					pierwszyAbsolutnyTCP = (struct elementKolejkiTcp*) malloc(sizeof(struct elementKolejkiTcp));
					pierwszyAbsolutnyTCP->ethIpTcp = (struct ethIpTcp*) malloc(sizeof(struct ethIpTcp));

					memcpy(pierwszyAbsolutnyTCP->ethIpTcp, &ethIpTcp, length);

					otworzKolejkeTcp(&pierwszyAbsolutnyTCP, &nastepnyElementTCP, length);
					dlugoscTCP[licznik-1] = length;
					liczbaTCP[licznik-1] = licznik;
					czyUtworzonoPierwszyTCP = 1;
					break;
				}

				if (czyUtworzonoPierwszyTCP == 1) {
					printf("\nTworze nowy element\n");
					nowyElementTCP = (struct elementKolejkiTcp*) malloc(sizeof(struct elementKolejkiTcp));
					nowyElementTCP->ethIpTcp = (struct ethIpTcp*) malloc(sizeof(struct ethIpTcp));

					memcpy(nowyElementTCP->ethIpTcp, &ethIpTcp, length);

					dodajDoKolejkiTcp(&nowyElementTCP, &nastepnyElementTCP, length, licznik);
					dlugoscTCP[licznik-1] = length;
					liczbaTCP[licznik-1] = licznik;
					printf("\nWSZEDLEM DO TCP\n");
				}
				break;
			case 0x11:
				//UDP
				printf("\n\nUDP\n\n");
				if (czyUtworzonoPierwszyUDP == 0) {
					printf("\nTworze pierwszy absolutny\n");
					pierwszyAbsolutnyUDP = (struct elementKolejkiUdp*) malloc(sizeof(struct elementKolejkiUdp));
					pierwszyAbsolutnyUDP->ethIpUdp = (struct ethIpUdp*) malloc(sizeof(struct ethIpUdp));

					memcpy(pierwszyAbsolutnyUDP->ethIpUdp, &ethIpUdp, length);

					otworzKolejkeUdp(&pierwszyAbsolutnyUDP, &nastepnyElementUDP, length);
					dlugoscUDP[licznik-1] = length;
					liczbaUDP[licznik-1] = licznik;
					czyUtworzonoPierwszyUDP = 1;
					break;
				}

				if (czyUtworzonoPierwszyUDP == 1) {
					printf("\nTworze nowy element\n");
					nowyElementUDP = (struct elementKolejkiUdp*) malloc(sizeof(struct elementKolejkiUdp));
					nowyElementUDP->ethIpUdp = (struct ethIpUdp*) malloc(sizeof(struct ethIpUdp));

					memcpy(nowyElementUDP->ethIpUdp, &ethIpUdp, length);

					dodajDoKolejkiUdp(&nowyElementUDP, &nastepnyElementUDP, length, licznik);
					dlugoscUDP[licznik-1] = length;
					liczbaUDP[licznik-1] = licznik;
					printf("\nWSZEDLEM DO UDP\n");
				}
				break;
			default:
				printf("\nNieobługiwane protokoły z IP\n");
				if (czyUtworzonoPierwszyINNYzIPv4 == 0) {
					printf("\nTworze pierwszy absolutny\n");
					pierwszyAbsolutnyINNYzIPv4 = (struct elementKolejkiInnyIpv4*) malloc(sizeof(struct elementKolejkiInnyIpv4));
					pierwszyAbsolutnyINNYzIPv4->ethIpData = (struct ethIpData*) malloc(sizeof(struct ethIpData));

					memcpy(pierwszyAbsolutnyINNYzIPv4->ethIpData, &ethIpData, length);

					otworzKolejkeInnyIpv4(&pierwszyAbsolutnyINNYzIPv4, &nastepnyElementINNYzIPv4, length);
					dlugoscINNYzIPv4[licznik-1] = length;
					liczbaINNYzIPv4[licznik-1] = licznik;
					czyUtworzonoPierwszyINNYzIPv4 = 1;
					break;
				}

				if (czyUtworzonoPierwszyINNYzIPv4 == 1) {
					printf("\nTworze nowy element\n");
					nowyElementINNYzIPv4 = (struct elementKolejkiInnyIpv4*) malloc(sizeof(struct elementKolejkiInnyIpv4));
					nowyElementINNYzIPv4->ethIpData = (struct ethIpData*) malloc(sizeof(struct ethIpData));

					memcpy(nowyElementINNYzIPv4->ethIpData, &ethIpData, length);

					dodajDoKolejkiInnyIPv4(&nowyElementINNYzIPv4, &nastepnyElementINNYzIPv4, length, licznik);
					dlugoscINNYzIPv4[licznik-1] = length;
					liczbaINNYzIPv4[licznik-1] = licznik;
					printf("\nWSZEDLEM DO INNYzIPv4\n");
				}
			}
			break;
		case 0x0806:
			//ARP
			printf("\n\nARP\n\n");
			if (czyUtworzonoPierwszyARP == 0) {
				printf("\nTworze pierwszy absolutny\n");
				pierwszyAbsolutnyARP = (struct elementKolejkiArp*) malloc(sizeof(struct elementKolejkiArp));
				pierwszyAbsolutnyARP->ethArp = (struct ethArp*) malloc(sizeof(struct ethArp));

				memcpy(pierwszyAbsolutnyARP->ethArp, &ethArp, length);

				otworzKolejkeArp(&pierwszyAbsolutnyARP, &nastepnyElementARP, length);
				dlugoscARP[licznik-1] = length;
				liczbaARP[licznik-1] = licznik;
				czyUtworzonoPierwszyARP = 1;
				break;
			}

			if (czyUtworzonoPierwszyARP == 1) {
				printf("\nTworze nowy element\n");
				nowyElementARP = (struct elementKolejkiArp*) malloc(sizeof(struct elementKolejkiArp));
				nowyElementARP->ethArp = (struct ethArp*) malloc(sizeof(struct ethArp));

				memcpy(nowyElementARP->ethArp, &ethArp, length);

				dodajDoKolejkiArp(&nowyElementARP, &nastepnyElementARP, length, licznik);
				dlugoscARP[licznik-1] = length;
				liczbaARP[licznik-1] = licznik;
				printf("\nWSZEDLEM DO ARP\n");
			}
			break;
		default:
			printf("\nNieobługiwane protokoły bez IP\n");
			if (czyUtworzonoPierwszyINNY == 0) {
				printf("\nTworze pierwszy absolutny\n");
				pierwszyAbsolutnyINNY = (struct elementKolejkiINNY*) malloc(sizeof(struct elementKolejkiINNY));
				pierwszyAbsolutnyINNY->ethData = (struct ethData*) malloc(sizeof(struct ethData));

				memcpy(pierwszyAbsolutnyINNY->ethData, &ethData, length);

				otworzKolejkeINNY(&pierwszyAbsolutnyINNY, &nastepnyElementINNY, length);
				dlugoscINNY[licznik-1] = length;
				liczbaINNY[licznik-1] = licznik;
				czyUtworzonoPierwszyINNY = 1;
				break;
			}

			if (czyUtworzonoPierwszyINNY == 1) {
				printf("\nTworze nowy element\n");
				nowyElementINNY = (struct elementKolejkiINNY*) malloc(sizeof(struct elementKolejkiINNY));
				nowyElementINNY->ethData = (struct ethData*) malloc(sizeof(struct ethData));

				memcpy(nowyElementINNY->ethData, &ethData, length);

				dodajDoKolejkiINNY(&nowyElementINNY, &nastepnyElementINNY, length, licznik);
				dlugoscINNY[licznik-1] = length;
				liczbaINNY[licznik-1] = licznik;
				printf("\nWSZEDLEM DO INNY\n");
			}
		}


		s = NULL;
		j = 0;
		i = 0;
		length = 0;
	}




	printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
	printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
	for(i = 1; i<(rozmiarTablicy + 1); i++){
		if (liczbaICMP[i-1] == i) {
			printf("\n%d ICMP\n", i);
			ethIpIcmp = pobranieDatagramuIcmp(0, &pierwszyAbsolutnyICMP);
			printf("\n%d ICMP\n", i);
			wyslanieDatagramuIcmp(ethIpIcmp, dlugoscICMP[i-1]);
			continue;
		}
		if (liczbaTCP[i-1] == i) {
			ethIpTcp = pobranieDatagramuTcp(0, &pierwszyAbsolutnyTCP);
			printf("\n%d TCP\n", i);
			wyslanieDatagramuTcp(ethIpTcp, dlugoscTCP[i-1]);
			continue;
		}
		if (liczbaUDP[i - 1] == i) {
			ethIpUdp = pobranieDatagramuUdp(0, &pierwszyAbsolutnyUDP);
			printf("\n%d UDP\n", i);
			wyslanieDatagramuUdp(ethIpUdp, dlugoscUDP[i-1]);
			continue;
		}
		if (liczbaINNYzIPv4[i - 1] == i) {
			ethIpData = pobranieDatagramuInnyIPv4(0, &pierwszyAbsolutnyINNYzIPv4);
			printf("\n%d INNYzIPv4\n", i);
			wyslanieDatagramuInnyIPv4(ethIpData, dlugoscINNYzIPv4[i-1]);
			continue;
		}
		if (liczbaARP[i - 1] == i) {
			ethArp = pobranieDatagramuArp(0, &pierwszyAbsolutnyARP);
			printf("\n%d ARP\n", i);
			wyslanieDatagramuArp(ethArp, dlugoscARP[i-1]);
			continue;
		}
		if (liczbaINNY[i - 1] == i) {
			ethData = pobranieDatagramuINNY(0, &pierwszyAbsolutnyINNY);
			printf("\n%d INNY\n", i);
			wyslanieDatagramuINNY(ethData, dlugoscINNY[i-1]);
			continue;
		}
	}


	if (czyUtworzonoPierwszyICMP == 1) {
		zwalnianiePamieciDatagramu(pierwszyAbsolutnyICMP->ethIpIcmp);
		zwalnianiePamieciDatagramu(pierwszyAbsolutnyICMP);
	}
	if (czyUtworzonoPierwszyTCP == 1) {
		zwalnianiePamieciDatagramu(pierwszyAbsolutnyTCP->ethIpTcp);
		zwalnianiePamieciDatagramu(pierwszyAbsolutnyTCP);
	}
	if (czyUtworzonoPierwszyUDP == 1) {
		zwalnianiePamieciDatagramu(pierwszyAbsolutnyUDP->ethIpUdp);
		zwalnianiePamieciDatagramu(pierwszyAbsolutnyUDP);
	}
	if (czyUtworzonoPierwszyARP == 1) {
		zwalnianiePamieciDatagramu(pierwszyAbsolutnyARP->ethArp);
		zwalnianiePamieciDatagramu(pierwszyAbsolutnyARP);
	}
	if (czyUtworzonoPierwszyINNYzIPv4 == 1) {
		zwalnianiePamieciDatagramu(pierwszyAbsolutnyINNYzIPv4->ethIpData);
		zwalnianiePamieciDatagramu(pierwszyAbsolutnyINNYzIPv4);
	}
	if (czyUtworzonoPierwszyINNY == 1) {
		zwalnianiePamieciDatagramu(pierwszyAbsolutnyINNY->ethData);
		zwalnianiePamieciDatagramu(pierwszyAbsolutnyINNY);
	}

	zwalnianiePamieciDatagramu(buffer);

	return EXIT_SUCCESS;


}

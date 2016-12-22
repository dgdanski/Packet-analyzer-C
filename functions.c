#include <stdio.h>
#include <stdlib.h>
#include "naglowki.h"
#include <string.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>

#define ETH_FRAME_LEN 1518
#define INTERFACE	"wlan0"

/*
eth - 14B
ip - 20B
arp - 18B
icmp - 4B
udp - 8B
tcp - 24B
*/

void rozkladARP(struct ethArp *ethArp, unsigned char *buforZpakietem, int sizeOfArpFrame,
		struct naglowekEthernet *naglowekEthernet,
		struct naglowekArp *naglowekArp) {

	memcpy(ethArp, buforZpakietem, sizeOfArpFrame);
	memcpy(naglowekEthernet, &buforZpakietem[0], 14);
	memcpy(naglowekArp, &buforZpakietem[14], 28);

}

void rozkladIcmp(struct ethIpIcmp *ethIpIcmp, unsigned char *buforZpakietem,
		int sizeOfIcmpFrame, struct naglowekEthernet *naglowekEthernet,
		struct naglowekIp *naglowekIp, struct naglowekIcmp *naglowekIcmp) {

	memcpy(ethIpIcmp, buforZpakietem, sizeOfIcmpFrame);
	memcpy(naglowekEthernet, &buforZpakietem[0], 14);
	memcpy(naglowekIp, &buforZpakietem[14], 20);
	memcpy(naglowekIcmp, &buforZpakietem[34], 8);
}

void rozkladUdp(struct ethIpUdp *ethIpUdp, unsigned char *buforZpakietem,
		int sizeOfUdpFrame, struct naglowekEthernet *naglowekEthernet,
		struct naglowekIp *naglowekIp, struct naglowekUdp *naglowekUdp) {

	memcpy(ethIpUdp, buforZpakietem, sizeOfUdpFrame);
	memcpy(naglowekEthernet, &buforZpakietem[0], 14);
	memcpy(naglowekIp, &buforZpakietem[14], 20);
	memcpy(naglowekUdp, &buforZpakietem[34], 8);
}

void rozkladTcp(struct ethIpTcp *ethIpTcp, unsigned char *buforZpakietem,
		int sizeOfTcpFrame, struct naglowekEthernet *naglowekEthernet,
		struct naglowekIp *naglowekIp, struct naglowekTcp *naglowekTcp) {

	memcpy(ethIpTcp, buforZpakietem, sizeOfTcpFrame);
	memcpy(naglowekEthernet, &buforZpakietem[0], 14);
	memcpy(naglowekIp, &buforZpakietem[14], 20);
	memcpy(naglowekTcp, &buforZpakietem[34], 24);
}


void displayEthernet(struct naglowekEthernet *naglowekEthernet) {
	printf("\n--Naglowek Ethernet II\n");
	printf("Adres docelowy MAC: 0x %02x %02x %02x %02x %02x %02x\n",
				naglowekEthernet->destinationAddress[0], naglowekEthernet->destinationAddress[1],
				naglowekEthernet->destinationAddress[2], naglowekEthernet->destinationAddress[3],
				naglowekEthernet->destinationAddress[4], naglowekEthernet->destinationAddress[5]);
		printf("Adres zrodlowy MAC: 0x %02x %02x %02x %02x %02x %02x\n",
				naglowekEthernet->sourceAddress[0], naglowekEthernet->sourceAddress[1],
				naglowekEthernet->sourceAddress[2],	naglowekEthernet->sourceAddress[3],
				naglowekEthernet->sourceAddress[4],	naglowekEthernet->sourceAddress[5]);
	litteToBigEndianShort(&(naglowekEthernet->frameType));
	printf("Typ: 0x %04x\n\n", naglowekEthernet->frameType);

}

void litteToBigEndianShort(unsigned short int *littleEndian) {
	*littleEndian = (*littleEndian >> 8 & 0x00FF) | (*littleEndian << 8 & 0xFF00);
}

void littleToBigEndianInt(unsigned int *littleEndian) {
	*littleEndian = (*littleEndian >> 24 & 0x000000FF)
			| ((*littleEndian >> 8) &      0x0000FF00)
			| ((*littleEndian << 8) &      0x00FF0000)
			| ((*littleEndian << 24) &     0xFF000000);
}

//void littleToBigEndianLong(unsigned long long int *littleEndian) {
//	*littleEndian = (*littleEndian >> 56 & 0x00000000000000FF)
//			| ((*littleEndian >> 40) &     0x000000000000FF00)
//			| ((*littleEndian >> 24) &     0x0000000000FF0000)
//			| ((*littleEndian >> 8) &      0x00000000FF000000)
//			| ((*littleEndian << 8) &      0x000000FF00000000)
//			| ((*littleEndian << 24) &     0x0000FF0000000000)
//			| ((*littleEndian << 40) & 	   0x00FF000000000000)
//			| ((*littleEndian << 56) &     0xFF00000000000000);
//}

//void littleToBigEndianLong(unsigned long long int *littleEndian) {
//	*littleEndian =
//			  ((*littleEndian >> 40) &     0x00000000000000FF)
//			| ((*littleEndian >> 24) &     0x000000000000FF00)
//			| ((*littleEndian >> 8) &      0x0000000000FF0000)
//			| ((*littleEndian << 8) &      0x00000000FF000000)
//			| ((*littleEndian << 24) &     0x000000FF00000000)
//			| ((*littleEndian << 40) & 	   0x0000FF0000000000);
//}

//void displayMacAddress(unsigned long long int bigEndian){
//	unsigned long long int bigEndianCopy = bigEndian;
//	printf("%02x ", ((bigEndianCopy >> 40) & 0x0000000000FF));
//	bigEndianCopy = bigEndian;
//	printf("%02x ", ((bigEndianCopy >> 32) & 0x0000000000FF));
//	bigEndianCopy = bigEndian;
//	printf("%02x ", ((bigEndianCopy >> 24) & 0x0000000000FF));
//	bigEndianCopy = bigEndian;
//	printf("%02x ", ((bigEndianCopy >> 16) & 0x0000000000FF));
//	bigEndianCopy = bigEndian;
//	printf("%02x ", ((bigEndianCopy >> 8)  & 0x0000000000FF));
//	bigEndianCopy = bigEndian;
//	printf("%02x\n", (bigEndianCopy        & 0x0000000000FF));
//}

void displayIpAddress(unsigned int bigEndian){
	unsigned int bigEndianCopy = bigEndian;
	printf("%d.", ((bigEndianCopy >> 24) & 0x000000FF));
	bigEndianCopy = bigEndian;
	printf("%d.", ((bigEndianCopy >> 16) & 0x000000FF));
	bigEndianCopy = bigEndian;
	printf("%d.", ((bigEndianCopy >> 8) & 0x000000FF));
	bigEndianCopy = bigEndian;
	printf("%d\n", (bigEndianCopy & 0x000000FF));
}

void displayIP(struct naglowekIp *naglowekIp) {
	printf("--Naglowek IP\n");
	printf("Wersja: %d\n", naglowekIp->ipVersionLength.version);
	printf("Dlugosc naglowka: %d B\n", ((unsigned int)naglowekIp->ipVersionLength.length)*4 );
	printf("ECN: 0x %02x\n", naglowekIp->ecn);
	litteToBigEndianShort(&(naglowekIp->totalLength));
	printf("Dlugosc calkowita: %d\n", naglowekIp->totalLength);
	litteToBigEndianShort(&(naglowekIp->identificationNumber));
	printf("Numer identyfikacyjny: 0x %04x (%d)\n", naglowekIp->identificationNumber, naglowekIp->identificationNumber);
	switch ((int)naglowekIp->ipFlags.flags) {
	case 1:
		printf("Flagi: 0x %02d (Reserved bit: Not set)\n", naglowekIp->ipFlags.flags);
		break;
	case 2:
		printf("Flagi: 0x %02d (Don't fragment: Set)\n", naglowekIp->ipFlags.flags);
		break;
	case 4:
		printf("Flagi: 0x %02d (More fragments: Not set)\n", naglowekIp->ipFlags.flags);
		break;
	default:
		printf("Flagi: 0x %02x \n", (naglowekIp->ipFlags.flags));
	}
	printf("Przesuniecie: %d\n", naglowekIp->ipFlags.fragmentOffset);
	printf("Czas zycia: %d\n", naglowekIp->timeOfLife);
	switch (naglowekIp->protocol) {
	case 0x01:
		printf("Protokol warstwy wyzszej (typ): ICMP (1)\n");
		break;
	case 0x06:
		printf("Protokol warstwy wyzszej (typ): TCP (6)\n");
		break;
	case 0x11:
		printf("Protokol warstwy wyzszej (typ): UDP (11)\n");
		break;
	default:
		printf("Protokol warstwy wyzszej (typ): 0x %02x\n",
				naglowekIp->protocol);
	}
	litteToBigEndianShort(&(naglowekIp->headerChecksum));
	printf("Suma kontrolna naglowka: 0x %04x\n", naglowekIp->headerChecksum);
	littleToBigEndianInt(&(naglowekIp->sourceAddress));
	printf("Adres zrodlowy IP: ");
	displayIpAddress(naglowekIp->sourceAddress);
	littleToBigEndianInt(&(naglowekIp->destinationAddress));
	printf("Adres docelowy IP: ");
	displayIpAddress(naglowekIp->destinationAddress);
	printf("\n");
}

void displayICMP(struct naglowekIcmp *naglowekIcmp){
	//ICMP
	//>>>>>>>>>>>>>>>>>>>>>>>>>ICMP
	printf("--Naglowek ICMP\n");
	printf("Typ: 0x %02x\n", naglowekIcmp->type);
	printf("Kod: 0x %02x\n", naglowekIcmp->code);
	litteToBigEndianShort(&(naglowekIcmp->checkSum));
	printf("Suma kontrolna: 0x %04x\n", naglowekIcmp->checkSum);
}

void displayTCP(struct naglowekTcp *naglowekTcp) {
	printf("--Naglowek TCP\n");
	litteToBigEndianShort(&(naglowekTcp->sourcePort));
	printf("Port nadawcy: %d\n", naglowekTcp->sourcePort);
	litteToBigEndianShort(&(naglowekTcp->destinationPort));
	printf("Port odbiorcy: %d\n", naglowekTcp->destinationPort);
	littleToBigEndianInt(&(naglowekTcp->sequenceNumber));
	printf("Numer sekwencyjny: 0x %08x\n", naglowekTcp->sequenceNumber);
	littleToBigEndianInt(&(naglowekTcp->acknowledgementNumber));
	printf("Numer potwierdzenia: 0x %08x\n", naglowekTcp->acknowledgementNumber);

	printf("Przesuniecie danych: 0x %x\n", naglowekTcp->group1.dataOffset);
	printf("Zarezerwowane: %d\n", naglowekTcp->group1.reserved);
	printf("Nonce sum: %d\n", naglowekTcp->group1.ns);
	printf("Congestion window reduced: %d\n", naglowekTcp->group2.cwr);
	printf("ECN-echo: %d\n", naglowekTcp->group2.ece);
	printf("Priorytet: %d\n", naglowekTcp->group2.urg);
	printf("Istotnosc pola 'numer potwierdzenia': %d\n", naglowekTcp->group2.ack);
	printf("Wymuszenie przeslania pakietu: %d\n", naglowekTcp->group2.psh);
	printf("Reset polaczenia: %d\n", naglowekTcp->group2.rst);
	printf("Synchro kolejnych nr sekwencyjnych: %d\n", naglowekTcp->group2.syn);
	printf("Zakonczenie przekazu danych: %d\n", naglowekTcp->group2.fin);

	litteToBigEndianShort(&(naglowekTcp->window));
	printf("Szerokosc okna: 0x %d\n", naglowekTcp->window);
	litteToBigEndianShort(&(naglowekTcp->checkSum));
	printf("Suma kontrolna: 0x %04x\n", naglowekTcp->checkSum);
	litteToBigEndianShort(&(naglowekTcp->urgentPointer));
	printf("Wskaznik priorytetu: 0x %04x\n", naglowekTcp->urgentPointer);
	littleToBigEndianInt(&(naglowekTcp->options));
	printf("Opcje: 0x %08x\n", naglowekTcp->options);
}

void displayUDP(struct naglowekUdp *naglowekUdp){
	printf("--Naglowek UDP\n");
	litteToBigEndianShort(&(naglowekUdp->sourcePort));
	printf("Port nadawcy: 0x %04x\n", naglowekUdp->sourcePort);
	litteToBigEndianShort(&(naglowekUdp->destinationPort));
	printf("Port odbiorcy: 0x %04x\n", naglowekUdp->destinationPort);
	litteToBigEndianShort(&(naglowekUdp->length));
	printf("Dlugosc komunikatu: %d B\n", naglowekUdp->length);
	litteToBigEndianShort(&(naglowekUdp->checkSum));
	printf("Suma kontrolna: 0x %04x\n", naglowekUdp->checkSum);
}

void displayARP(struct naglowekArp *naglowekArp) {
	printf("--Naglowek ARP\n");
	litteToBigEndianShort(&(naglowekArp->hType));
	if(naglowekArp->hType == 0x01){
		printf("Typ wartwy fizycznej: Ethernet (1)\n");
	}else{
		printf("Typ wartwy fizycznej: 0x %04x\n", naglowekArp->hType);
	}
	litteToBigEndianShort(&(naglowekArp->pType));
	if(naglowekArp->pType == 0x0800){
		printf("Typ protokolu wyzszej warstwy: IP (0x0800)\n");
	}else{
		printf("Typ protokolu wyzszej warstwy: 0x %04x\n", naglowekArp->pType);
	}
	printf("Dlugosc adresu sprzetowego: %d\n", naglowekArp->hLen);
	printf("Dlugosc protokolu wyzszej warstwy: %d\n", naglowekArp->pLen);
	litteToBigEndianShort(&(naglowekArp->oper));
	if(naglowekArp->oper == 0x0001){
		printf("Operacja: request (%x)\n", naglowekArp->oper);
	}else{
		printf("Operacja: reply (%x)\n", naglowekArp->oper);
	}
	printf("Adres sprzetowy MAC zrodla: 0x %02x %02x %02x %02x %02x %02x\n",
			naglowekArp->sourceMacAddress[0], naglowekArp->sourceMacAddress[1],
			naglowekArp->sourceMacAddress[2], naglowekArp->sourceMacAddress[3],
			naglowekArp->sourceMacAddress[4], naglowekArp->sourceMacAddress[5]);
	littleToBigEndianInt(&(naglowekArp->sourceIpAddress));

	//printf("Adres protokolu IP wyzszej warstwy zrodla: 0x %02x\n", ((naglowekArp->sourceIpAddress >> 40) & 0x00000000000000FF));
	printf("Adres protokolu IP wyzszej warstwy zrodla: ");
	displayIpAddress(naglowekArp->sourceIpAddress);
	printf("Adres sprzetowy MAC przeznaczenia: 0x %02x %02x %02x %02x %02x %02x\n",
			naglowekArp->destinationMacAddress[0], naglowekArp->destinationMacAddress[1],
			naglowekArp->destinationMacAddress[2], naglowekArp->destinationMacAddress[3],
			naglowekArp->destinationMacAddress[4], naglowekArp->destinationMacAddress[5]);
	littleToBigEndianInt(&(naglowekArp->destinationIpAddress));
	printf("Adres protokolu IP wyzszej warstwy przeznaczenia: ");
	displayIpAddress(naglowekArp->destinationIpAddress);
}


void rozkladOtherIp(struct ethIpData *ethIpData, unsigned char *buforZpakietem,
		int sizeOfOtherIpFrame, struct naglowekEthernet *naglowekEthernet,
		struct naglowekIp *naglowekIp) {

	memcpy(ethIpData, buforZpakietem, sizeOfOtherIpFrame);
	memcpy(naglowekEthernet, &buforZpakietem[0], 14);
	memcpy(naglowekIp, &buforZpakietem[14], 20);

}

void checkProtocolIp(unsigned char *array) {
	switch (*(array + 23)) {
	case 0x00:
		printf("HOPOPT");
		break;
	case 0x02:
		printf("IGMP");
		break;
	case 0x03:
		printf("GGP");
		break;
	case 0x04:
		printf("IP-in-IP");
		break;
	case 0x05:
		printf("ST");
		break;
	case 0x07:
		printf("CBT");
		break;
	case 0x08:
		printf("EGP");
		break;
	case 0x09:
		printf("IGP");
		break;
	case 0x0A:
		printf("BBN-RCC-MON");
		break;
	case 0x0B:
		printf("NVP-II");
		break;
	case 0x0C:
		printf("PUP");
		break;
	case 0x0D:
		printf("ARGUS");
		break;
	case 0x0E:
		printf("EMCON");
		break;
	case 0x0F:
		printf("XNET");
		break;
	case 0x10:
		printf("CHAOS");
		break;
	case 0x12:
		printf("MUX");
		break;
	case 0x13:
		printf("DCN-MEAS");
		break;
	case 0x14:
		printf("HMP");
		break;
	case 0x15:
		printf("PRM");
		break;
	case 0x16:
		printf("XNS-IDP");
		break;
	case 0x17:
		printf("TRUNK-1");
		break;
	case 0x18:
		printf("TRUNK-2");
		break;
	case 0x19:
		printf("LEAF-1");
		break;
	case 0x1A:
		printf("LEAF-2");
		break;
	case 0x1B:
		printf("RDP");
		break;
	case 0x1C:
		printf("IRTP");
		break;
	case 0x1D:
		printf("ISO-TP4");
		break;
	case 0x1E:
		printf("NETBLT");
		break;
	case 0x1F:
		printf("MFE-NSP");
		break;
	case 0x20:
		printf("MERIT-INP");
		break;
	case 0x21:
		printf("DCCP");
		break;
	case 0x22:
		printf("3PC");
		break;
	case 0x23:
		printf("IDPR");
		break;
	case 0x24:
		printf("XTP");
		break;
	case 0x25:
		printf("DDP");
		break;
	case 0x26:
		printf("IDPR-CMTP");
		break;
	case 0x27:
		printf("TP++");
		break;
	case 0x28:
		printf("IL");
		break;
	case 0x29:
		printf("IPv6");
		break;
	case 0x2A:
		printf("SDRP");
		break;
	case 0x2B:
		printf("IPv6-Route");
		break;
	case 0x2C:
		printf("IPv6-Frag");
		break;
	case 0x2D:
		printf("IDRP");
		break;
	case 0x2E:
		printf("RSVP");
		break;
	case 0x2F:
		printf("GRE");
		break;
	case 0x30:
		printf("MHRP");
		break;
	case 0x31:
		printf("BN");
		break;
	case 0x32:
		printf("ESP");
		break;
	case 0x33:
		printf("AH");
		break;
	case 0x34:
		printf("I-NLSP");
		break;
	case 0x35:
		printf("SWIPE");
		break;
	case 0x36:
		printf("NARP");
		break;
	case 0x37:
		printf("MOBILE");
		break;
	case 0x38:
		printf("TLSP");
		break;
	case 0x39:
		printf("SKIP");
		break;
	case 0x3A:
		printf("IPv6-ICMP");
		break;
	case 0x3B:
		printf("IPv6-NoNxt");
		break;
	case 0x3C:
		printf("IPv6-Opts");
		break;
	case 0x3E:
		printf("CFTP");
		break;
	case 0x40:
		printf("SAT-EXPAK");
		break;
	case 0x41:
		printf("KRYPTOLAN");
		break;
	case 0x42:
		printf("RVD");
		break;
	case 0x43:
		printf("IPPC");
		break;
	case 0x45:
		printf("SAT-MON");
		break;
	case 0x46:
		printf("VISA");
		break;
	case 0x47:
		printf("IPCU");
		break;
	case 0x48:
		printf("CPNX");
		break;
	case 0x49:
		printf("CPHB");
		break;
	case 0x4A:
		printf("WSN");
		break;
	case 0x4B:
		printf("PVP");
		break;
	case 0x4C:
		printf("BR-SAT-MON");
		break;
	case 0x4D:
		printf("SUN-ND");
		break;
	case 0x4E:
		printf("WB-MON");
		break;
	case 0x4F:
		printf("WB-EXPAK");
		break;
	case 0x50:
		printf("ISO-IP");
		break;
	case 0x51:
		printf("VMTP");
		break;
	case 0x52:
		printf("SECURE-VMTP");
		break;
	case 0x53:
		printf("VINES");
		break;
	case 0x54:
		printf("TTP");
		break;
	case 0x55:
		printf("NSFNET-IGP");
		break;
	case 0x56:
		printf("DGP");
		break;
	case 0x57:
		printf("TCF");
		break;
	case 0x58:
		printf("EIGRP");
		break;
	case 0x59:
		printf("OSPF");
		break;
	case 0x5A:
		printf("Sprite-RPC");
		break;
	case 0x5B:
		printf("LARP");
		break;
	case 0x5C:
		printf("MTP");
		break;
	case 0x5D:
		printf("AX.25");
		break;
	case 0x5E:
		printf("IPIP");
		break;
	case 0x5F:
		printf("MICP");
		break;
	case 0x60:
		printf("SCC-SP");
		break;
	case 0x61:
		printf("ETHERIP");
		break;
	case 0x62:
		printf("ENCAP");
		break;
	case 0x64:
		printf("GMTP");
		break;
	case 0x65:
		printf("IFMP");
		break;
	case 0x66:
		printf("PNNI");
		break;
	case 0x67:
		printf("PIM");
		break;
	case 0x68:
		printf("ARIS");
		break;
	case 0x69:
		printf("SCPS");
		break;
	case 0x6A:
		printf("QNX");
		break;
	case 0x6B:
		printf("A/N");
		break;
	case 0x6C:
		printf("IPComp");
		break;
	case 0x6D:
		printf("SNP");
		break;
	case 0x6E:
		printf("Compaq-Peer");
		break;
	case 0x6F:
		printf("IPX-in-IP");
		break;
	case 0x70:
		printf("VRRP");
		break;
	case 0x71:
		printf("PGM");
		break;
	case 0x73:
		printf("L2TP");
		break;
	case 0x74:
		printf("DDX");
		break;
	case 0x75:
		printf("IATP");
		break;
	case 0x76:
		printf("STP");
		break;
	case 0x77:
		printf("SRP");
		break;
	case 0x78:
		printf("UTI");
		break;
	case 0x79:
		printf("SMP");
		break;
	case 0x7A:
		printf("SM");
		break;
	case 0x7B:
		printf("PTP");
		break;
	case 0x7C:
		printf("IS-IS over IPv4");
		break;
	case 0x7D:
		printf("FIRE");
		break;
	case 0x7E:
		printf("CRTP");
		break;
	case 0x7F:
		printf("CRUDP");
		break;
	case 0x80:
		printf("SSCOPMCE");
		break;
	case 0x81:
		printf("IPLT");
		break;
	case 0x82:
		printf("SPS");
		break;
	case 0x83:
		printf("PIPE");
		break;
	case 0x84:
		printf("SCTP");
		break;
	case 0x85:
		printf("FC");
		break;
	case 0x86:
		printf("RSVP-E2E-IGNORE");
		break;
	case 0x87:
		printf("Mobility Header");
		break;
	case 0x88:
		printf("UDPLite");
		break;
	case 0x89:
		printf("MPLS-in-IP");
		break;
	case 0x8A:
		printf("manet");
		break;
	case 0x8B:
		printf("HIP");
		break;
	case 0x8C:
		printf("Shim6");
		break;
	case 0x8D:
		printf("WESP");
		break;
	case 0x8E:
		printf("ROHC");
		break;
	}
	printf("\n\n");
}

void rozkladOtherEth(struct ethData *ethData, unsigned char *buforZpakietem,
		int sizeOfOtherEthFrame, struct naglowekEthernet *naglowekEthernet) {

	memcpy(ethData, buforZpakietem, sizeOfOtherEthFrame);
	memcpy(naglowekEthernet, &buforZpakietem[0], 14);
}

void checkProtocolEth(unsigned int protocolChecker){
	switch(protocolChecker){
	case 0x0842:
		printf("Wake-on-LAN");
		break;
	case 0x22F0:
		printf("Audio Video Transport Protocol");
		break;
	case 0x22F3:
		printf("IETF TRILL Protocol");
		break;
	case 0x6003:
		printf("DECnet Phase IV");
		break;
	case 0x8035:
		printf("Reverse Address Resolution Protocol");
		break;
	case 0x809B:
		printf("AppleTalk");
		break;
	case 0x80F3:
		printf("AppleTalk Address Resolution Protocol");
		break;
	case 0x8100:
		printf("VLAN-tagged frame & Shortest Path Bridging");
		break;
	case 0x8137:
		printf("IPX");
		break;
	case 0x8138:
		printf("IPX");
		break;
	case 0x8204:
		printf("QNX Qnet");
		break;
	case 0x86DD:
		printf("IPv6");
		break;
	case 0x8808:
		printf("Ethernet flow control");
		break;
	case 0x8809:
		printf("Slow Protocols (IEEE 802.3)");
		break;
	case 0x8819:
		printf("CobraNet");
		break;
	case 0x8847:
		printf("MPLS unicast");
		break;
	case 0x8848:
		printf("MPLS multicast");
		break;
	case 0x8863:
		printf("PPPoE Discovery Stage");
		break;
	case 0x8864:
		printf("PPPoE Session Stage");
		break;
	case 0x8870:
		printf("Jumbo Frames");
		break;
	case 0x887B:
		printf("HomePlug 1.0 MME");
		break;
	case 0x888E:
		printf("EAP over LAN");
		break;
	case 0x8892:
		printf("PROFINET Protocol");
		break;
	case 0x889A:
		printf("HyperSCSI");
		break;
	case 0x88A2:
		printf("ATA over Ethernet");
		break;
	case 0x88A4:
		printf("EtherCAT Protocol");
		break;
	case 0x88A8:
		printf("Provider Bridging & Shortest Path Bridging");
		break;
	case 0x88AB:
		printf("Ethernet Powerlink");
		break;
	case 0x88CC:
		printf("Link Layer Discovery Protocol");
		break;
	case 0x88CD:
		printf("SERCOS III");
		break;
	case 0x88E1:
		printf("HomePlug AV MME");
		break;
	case 0x88E3:
		printf("Media Redundancy Protocol");
		break;
	case 0x88E5:
		printf("MAC security");
		break;
	case 0x88E7:
		printf("Provider Backbone Bridges");
		break;
	case 0x88F7:
		printf("Precision Time Protocol");
		break;
	case 0x8902:
		printf("Connectivity Fault Management Protocol");
		break;
	case 0x8906:
		printf("Fibre Channel over Ethernet");
		break;
	case 0x8914:
		printf("FCoE Initialization Protocol");
		break;
	case 0x8915:
		printf("RDMA over Converged Ethernet");
		break;
	case 0x892F:
		printf("High-availability Seamless Redundancy");
		break;
	case 0x9000:
		printf("Ethernet Configuration Testing Protocol");
		break;
	case 0xCAFE:
		printf("Veritas Low Latency Transport for Veritas Cluster Server");
		break;
	}
	printf("\n\n");
}


struct ethArp pobranieDatagramuArp(int numerElementu, struct elementKolejkiArp **adresPierwszego) {
	struct elementKolejkiArp *pomocniczy = (*adresPierwszego); //tworze pomocniczy wskaznik na strukture
	printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
	printf("\nAdres pierwszego elementu %x\n", pomocniczy);
	int licznik = 0, z;
	struct ethArp ethArp;
	while (pomocniczy->poprzedni != NULL) { //przechodze w petli while przez cala liste
		licznik++;
		printf("[%d] ", licznik);

		printf("\n");
		pomocniczy = pomocniczy->poprzedni;
		if (pomocniczy->poprzedni == NULL) {
			licznik++;
			printf("[%d] ", licznik);
		}
	}
	if (licznik == 0) {
		printf("licznik wynosi %d czyli jestesmy w absolutnym\n", licznik);

	}

	while (pomocniczy->nastepny != NULL){	//wracamy do absolutnego
		pomocniczy = pomocniczy->nastepny;
		if (pomocniczy->nastepny == NULL) {
			//znajdujemy sie w pierwszym
			memcpy(&ethArp, pomocniczy->ethArp, pomocniczy->length);
			printf("\nAdres pomocniczego przed przypisaniem %x\n", pomocniczy);

			pomocniczy = pomocniczy->poprzedni;
			printf("\nAdres pomocniczego %x\n", pomocniczy);
			printf("\nAdres do usuniecia %x\n", (*adresPierwszego));

			zwalnianiePamieciDatagramu((*adresPierwszego)->ethArp);
			zwalnianiePamieciDatagramu((*adresPierwszego));

			(*adresPierwszego) = pomocniczy;
			printf("\nAdres przejety %x\n", (*adresPierwszego));
			pomocniczy = NULL;
			(*adresPierwszego)->nastepny = NULL;
			printf("\n");

			break;
		}
	}
	if (licznik == 0){
		printf("licznik wynosi %d", licznik);
		memcpy(&ethArp, (*adresPierwszego)->ethArp, (*adresPierwszego)->length);
	}

	return ethArp;
}

struct ethIpIcmp pobranieDatagramuIcmp(int numerElementu, struct elementKolejkiIcmp **adresPierwszego) {
	struct elementKolejkiIcmp *pomocniczy = (*adresPierwszego); //Tworzę pomocniczy wskaźnik na strukturę
	printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
	printf("\nAdres pierwszego elementu %x\n", pomocniczy);
	int licznik = 0, z;
	//for (z = 0; z < 30; z++) {
	//	adresPierwszego->pakiet[z] = 0;
	//}
	struct ethIpIcmp ethIpIcmp;
	while (pomocniczy->poprzedni != NULL) { //Przechodzę w pętli while przez całą listę
		licznik++;
		printf("[%d] ", licznik);

		printf("\n");
		if (licznik == numerElementu) {
			break;
		}
		pomocniczy = pomocniczy->poprzedni; //Przestawiam wskaźnik help na kolejny element listy
		if (pomocniczy->poprzedni == NULL) {
			licznik++;
			printf("[%d] ", licznik);

			if (licznik == numerElementu) {
				printf("\n");
				//return pomocniczy;
			}
		}
	}
	if (licznik == 0) {
		printf("licznik wynosi %d i abs\n", licznik);
	}

	while (pomocniczy->nastepny != NULL){	//wracamy do absolutnego
		pomocniczy = pomocniczy->nastepny;
		if (pomocniczy->nastepny == NULL) {
			//znajdujemy sie w pierwszym
			memcpy(&ethIpIcmp, pomocniczy->ethIpIcmp, pomocniczy->length);
			//pomocniczy = (struct elementKolejki*) malloc(sizeof(struct elementKolejki));
			//pomocniczy = (*adresPierwszego)->poprzedni;
			//(*adresPierwszego) = (*adresPierwszego)->poprzedni;
			printf("\nAdres pomocniczego przed przypisaniem %x\n", pomocniczy);

			pomocniczy = pomocniczy->poprzedni;
			printf("\nAdres pomocniczego %x\n", pomocniczy);
			printf("\nAdres do usuniecia %x\n", (*adresPierwszego));
			//free((*adresPierwszego));

			zwalnianiePamieciDatagramu((*adresPierwszego)->ethIpIcmp);
			zwalnianiePamieciDatagramu((*adresPierwszego));

			(*adresPierwszego) = pomocniczy;
			//(*adresPierwszego) = (*adresPierwszego)->poprzedni;
			//free(pomocniczy);
			printf("\nAdres przejety %x\n", (*adresPierwszego));
			pomocniczy = NULL;
			//free((*adresPierwszego)->nastepny);
			(*adresPierwszego)->nastepny = NULL;
			printf("\n");

			break;
		}
	}
	if (licznik == 0){
		printf("licznik wynosi %d", licznik);
		memcpy(&ethIpIcmp, (*adresPierwszego)->ethIpIcmp, (*adresPierwszego)->length);
	}

	return ethIpIcmp;
}

struct ethIpTcp pobranieDatagramuTcp(int numerElementu, struct elementKolejkiTcp **adresPierwszego) {
	struct elementKolejkiTcp *pomocniczy = (*adresPierwszego); //Tworzę pomocniczy wskaźnik na strukturę
	printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
	printf("\nAdres pierwszego elementu %x\n", pomocniczy);
	int licznik = 0, z;

	struct ethIpTcp ethIpTcp;
	while (pomocniczy->poprzedni != NULL) { //Przechodzę w pętli while przez całą listę
		licznik++;
		printf("[%d] ", licznik);
		printf("\n");
		if (licznik == numerElementu) {
			break;
		}
		pomocniczy = pomocniczy->poprzedni; //Przestawiam wskaźnik help na kolejny element listy
		if (pomocniczy->poprzedni == NULL) {
			licznik++;
			printf("[%d] ", licznik);
			if (licznik == numerElementu) {
				printf("\n");
				//return pomocniczy;
			}
		}
	}
	if (licznik == 0) {
		printf("licznik wynosi %d i abs\n", licznik);
	}

	while (pomocniczy->nastepny != NULL){	//wracamy do absolutnego
		pomocniczy = pomocniczy->nastepny;
		if (pomocniczy->nastepny == NULL) {
			//znajdujemy sie w pierwszym
			memcpy(&ethIpTcp, pomocniczy->ethIpTcp, pomocniczy->length);
			//pomocniczy = (struct elementKolejki*) malloc(sizeof(struct elementKolejki));
			//pomocniczy = (*adresPierwszego)->poprzedni;
			//(*adresPierwszego) = (*adresPierwszego)->poprzedni;
			printf("\nAdres pomocniczego przed przypisaniem %x\n", pomocniczy);

			pomocniczy = pomocniczy->poprzedni;
			printf("\nAdres pomocniczego %x\n", pomocniczy);
			printf("\nAdres do usuniecia %x\n", (*adresPierwszego));
			//free((*adresPierwszego));

			zwalnianiePamieciDatagramu((*adresPierwszego)->ethIpTcp);
			zwalnianiePamieciDatagramu((*adresPierwszego));

			(*adresPierwszego) = pomocniczy;
			//(*adresPierwszego) = (*adresPierwszego)->poprzedni;
			//free(pomocniczy);
			printf("\nAdres przejety %x\n", (*adresPierwszego));
			pomocniczy = NULL;
			//free((*adresPierwszego)->nastepny);
			(*adresPierwszego)->nastepny = NULL;
			printf("\n");

			break;
		}
	}
	if (licznik == 0){
		printf("licznik wynosi %d", licznik);
		memcpy(&ethIpTcp, (*adresPierwszego)->ethIpTcp, (*adresPierwszego)->length);
	}

	return ethIpTcp;
}

struct ethIpUdp pobranieDatagramuUdp(int numerElementu, struct elementKolejkiUdp **adresPierwszego) {
	struct elementKolejkiUdp *pomocniczy = (*adresPierwszego); //Tworzę pomocniczy wskaźnik na strukturę
	printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
	printf("\nAdres pierwszego elementu %x\n", pomocniczy);
	int licznik = 0, z;

	struct ethIpUdp ethIpUdp;
	while (pomocniczy->poprzedni != NULL) { //Przechodzę w pętli while przez całą listę
		licznik++;
		printf("[%d] ", licznik);

		printf("\n");
		if (licznik == numerElementu) {
			break;
		}
		pomocniczy = pomocniczy->poprzedni; //Przestawiam wskaźnik help na kolejny element listy
		if (pomocniczy->poprzedni == NULL) {
			licznik++;
			printf("[%d] ", licznik);

			if (licznik == numerElementu) {
				printf("\n");
				//return pomocniczy;
			}
		}
	}
	if (licznik == 0) {
		printf("licznik wynosi %d i abs\n", licznik);
	}

	while (pomocniczy->nastepny != NULL){	//wracamy do absolutnego
		pomocniczy = pomocniczy->nastepny;
		if (pomocniczy->nastepny == NULL) {
			//znajdujemy sie w pierwszym
			memcpy(&ethIpUdp, pomocniczy->ethIpUdp, pomocniczy->length);
			//pomocniczy = (struct elementKolejki*) malloc(sizeof(struct elementKolejki));
			//pomocniczy = (*adresPierwszego)->poprzedni;
			//(*adresPierwszego) = (*adresPierwszego)->poprzedni;
			printf("\nAdres pomocniczego przed przypisaniem %x\n", pomocniczy);

			pomocniczy = pomocniczy->poprzedni;
			printf("\nAdres pomocniczego %x\n", pomocniczy);
			printf("\nAdres do usuniecia %x\n", (*adresPierwszego));
			//free((*adresPierwszego));

			zwalnianiePamieciDatagramu((*adresPierwszego)->ethIpUdp);
			zwalnianiePamieciDatagramu((*adresPierwszego));

			(*adresPierwszego) = pomocniczy;
			//(*adresPierwszego) = (*adresPierwszego)->poprzedni;
			//free(pomocniczy);
			printf("\nAdres przejety %x\n", (*adresPierwszego));
			pomocniczy = NULL;
			//free((*adresPierwszego)->nastepny);
			(*adresPierwszego)->nastepny = NULL;
			printf("\n");

			break;
		}
	}
	if (licznik == 0){
		printf("licznik wynosi %d", licznik);
		memcpy(&ethIpUdp, (*adresPierwszego)->ethIpUdp, (*adresPierwszego)->length);
	}

	return ethIpUdp;
}

struct ethIpData pobranieDatagramuInnyIPv4(int numerElementu, struct elementKolejkiInnyIpv4 **adresPierwszego) {
	struct elementKolejkiInnyIpv4 *pomocniczy = (*adresPierwszego); //Tworzę pomocniczy wskaźnik na strukturę
	printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
	printf("\nAdres pierwszego elementu %x\n", pomocniczy);
	int licznik = 0, z;

	struct ethIpData ethIpData;
	while (pomocniczy->poprzedni != NULL) { //Przechodzę w pętli while przez całą listę
		licznik++;
		printf("[%d] ", licznik);

		printf("\n");
		if (licznik == numerElementu) {
			break;
		}
		pomocniczy = pomocniczy->poprzedni; //Przestawiam wskaźnik help na kolejny element listy
		if (pomocniczy->poprzedni == NULL) {
			licznik++;
			printf("[%d] ", licznik);

			if (licznik == numerElementu) {
				printf("\n");
				//return pomocniczy;
			}
		}
	}
	if (licznik == 0) {
		printf("licznik wynosi %d i abs\n", licznik);
	}

	while (pomocniczy->nastepny != NULL){	//wracamy do absolutnego
		pomocniczy = pomocniczy->nastepny;
		if (pomocniczy->nastepny == NULL) {
			//znajdujemy sie w pierwszym
			memcpy(&ethIpData, pomocniczy->ethIpData, pomocniczy->length);
			//pomocniczy = (struct elementKolejki*) malloc(sizeof(struct elementKolejki));
			//pomocniczy = (*adresPierwszego)->poprzedni;
			//(*adresPierwszego) = (*adresPierwszego)->poprzedni;
			printf("\nAdres pomocniczego przed przypisaniem %x\n", pomocniczy);

			pomocniczy = pomocniczy->poprzedni;
			printf("\nAdres pomocniczego %x\n", pomocniczy);
			printf("\nAdres do usuniecia %x\n", (*adresPierwszego));
			//free((*adresPierwszego));

			zwalnianiePamieciDatagramu((*adresPierwszego)->ethIpData);
			zwalnianiePamieciDatagramu((*adresPierwszego));

			(*adresPierwszego) = pomocniczy;
			//(*adresPierwszego) = (*adresPierwszego)->poprzedni;
			//free(pomocniczy);
			printf("\nAdres przejety %x\n", (*adresPierwszego));
			pomocniczy = NULL;
			//free((*adresPierwszego)->nastepny);
			(*adresPierwszego)->nastepny = NULL;
			printf("\n");

			break;
		}
	}
	if (licznik == 0){
		printf("licznik wynosi %d", licznik);
		memcpy(&ethIpData, (*adresPierwszego)->ethIpData, (*adresPierwszego)->length);
	}

	return ethIpData;
}

struct ethData pobranieDatagramuINNY(int numerElementu, struct elementKolejkiINNY **adresPierwszego) {
	struct elementKolejkiINNY *pomocniczy = (*adresPierwszego); //Tworzę pomocniczy wskaźnik na strukturę
	printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
	printf("\nAdres pierwszego elementu %x\n", pomocniczy);
	int licznik = 0, z;

	struct ethData ethData;
	while (pomocniczy->poprzedni != NULL) { //Przechodzę w pętli while przez całą listę
		licznik++;
		printf("[%d] ", licznik);

		printf("\n");
		if (licznik == numerElementu) {
			break;
		}
		pomocniczy = pomocniczy->poprzedni; //Przestawiam wskaźnik help na kolejny element listy
		if (pomocniczy->poprzedni == NULL) {
			licznik++;
			printf("[%d] ", licznik);

			if (licznik == numerElementu) {
				printf("\n");
				//return pomocniczy;
			}
		}
	}
	if (licznik == 0) {
		printf("licznik wynosi %d i abs\n", licznik);
	}

	while (pomocniczy->nastepny != NULL){	//wracamy do absolutnego
		pomocniczy = pomocniczy->nastepny;
		if (pomocniczy->nastepny == NULL) {
			//znajdujemy sie w pierwszym
			memcpy(&ethData, pomocniczy->ethData, pomocniczy->length);
			//pomocniczy = (struct elementKolejki*) malloc(sizeof(struct elementKolejki));
			//pomocniczy = (*adresPierwszego)->poprzedni;
			//(*adresPierwszego) = (*adresPierwszego)->poprzedni;
			printf("\nAdres pomocniczego przed przypisaniem %x\n", pomocniczy);

			pomocniczy = pomocniczy->poprzedni;
			printf("\nAdres pomocniczego %x\n", pomocniczy);
			printf("\nAdres do usuniecia %x\n", (*adresPierwszego));
			//free((*adresPierwszego));

			zwalnianiePamieciDatagramu((*adresPierwszego)->ethData);
			zwalnianiePamieciDatagramu((*adresPierwszego));

			(*adresPierwszego) = pomocniczy;
			//(*adresPierwszego) = (*adresPierwszego)->poprzedni;
			//free(pomocniczy);
			printf("\nAdres przejety %x\n", (*adresPierwszego));
			pomocniczy = NULL;
			//free((*adresPierwszego)->nastepny);
			(*adresPierwszego)->nastepny = NULL;
			printf("\n");

			break;
		}
	}
	if (licznik == 0){
		printf("licznik wynosi %d", licznik);
		memcpy(&ethData, (*adresPierwszego)->ethData, (*adresPierwszego)->length);
	}

	return ethData;
}


void otworzKolejkeArp(struct elementKolejkiArp **adresPierwszego, struct elementKolejkiArp **nastepnyElement,
		int length) {

	(*adresPierwszego)->nastepny = NULL;
	(*adresPierwszego)->poprzedni = NULL;
	printf("Adres pierwszego: %x\n", (*adresPierwszego));

	(*adresPierwszego)->length = length;
	(*nastepnyElement) = (*adresPierwszego);
	printf("Adres nastepnego po przypisaniu: %x\n\n", *nastepnyElement);
}

void otworzKolejkeTcp(struct elementKolejkiTcp **adresPierwszego, struct elementKolejkiTcp **nastepnyElement,
		int length) {

	(*adresPierwszego)->nastepny = NULL;
	(*adresPierwszego)->poprzedni = NULL;
	printf("Adres pierwszego: %x\n", (*adresPierwszego));

	(*adresPierwszego)->length = length;
	(*nastepnyElement) = (*adresPierwszego);
	printf("Adres nastepnego po przypisaniu: %x\n\n", *nastepnyElement);
}

void otworzKolejkeUdp(struct elementKolejkiUdp **adresPierwszego, struct elementKolejkiUdp **nastepnyElement,
		int length) {

	(*adresPierwszego)->nastepny = NULL;
	(*adresPierwszego)->poprzedni = NULL;
	printf("Adres pierwszego: %x\n", (*adresPierwszego));

	(*adresPierwszego)->length = length;
	(*nastepnyElement) = (*adresPierwszego);
	printf("Adres nastepnego po przypisaniu: %x\n\n", *nastepnyElement);
}

void otworzKolejkeIcmp(struct elementKolejkiIcmp **adresPierwszego, struct elementKolejkiIcmp **nastepnyElement,
		int length) {

	(*adresPierwszego)->nastepny = NULL;
	(*adresPierwszego)->poprzedni = NULL;
	printf("Adres pierwszego: %x\n", (*adresPierwszego));

	(*adresPierwszego)->length = length;
	(*nastepnyElement) = (*adresPierwszego);
	printf("Adres nastepnego po przypisaniu: %x\n\n", *nastepnyElement);
}

void otworzKolejkeInnyIpv4(struct elementKolejkiInnyIpv4 **adresPierwszego, struct elementKolejkiInnyIpv4 **nastepnyElement,
		int length) {

	(*adresPierwszego)->nastepny = NULL;
	(*adresPierwszego)->poprzedni = NULL;
	printf("Adres pierwszego: %x\n", (*adresPierwszego));

	(*adresPierwszego)->length = length;
	(*nastepnyElement) = (*adresPierwszego);
	printf("Adres nastepnego po przypisaniu: %x\n\n", *nastepnyElement);
}

void otworzKolejkeINNY(struct elementKolejkiINNY **adresPierwszego, struct elementKolejkiINNY **nastepnyElement,
		int length) {

	(*adresPierwszego)->nastepny = NULL;
	(*adresPierwszego)->poprzedni = NULL;
	printf("Adres pierwszego: %x\n", (*adresPierwszego));

	(*adresPierwszego)->length = length;
	(*nastepnyElement) = (*adresPierwszego);
	printf("Adres nastepnego po przypisaniu: %x\n\n", *nastepnyElement);
}


void dodajDoKolejkiArp(struct elementKolejkiArp **nowyElement,
		struct elementKolejkiArp **nastepnyElement, int length, int licznik) {

	printf("Adres nowego nr %d: %x\n", licznik, (*nowyElement));
	(*nowyElement)->nastepny = (*nastepnyElement);
	(*nowyElement)->poprzedni = NULL;
	(*nowyElement)->length = length;

	(*nastepnyElement)->poprzedni = (*nowyElement);
	printf("Adres w poprzedniego wzgl nastepnego: %x\n\n", (*nastepnyElement)->poprzedni);
	(*nastepnyElement) = (*nowyElement);
}

void dodajDoKolejkiTcp(struct elementKolejkiTcp **nowyElement,
		struct elementKolejkiTcp **nastepnyElement, int length, int licznik) {

	printf("Adres nowego nr %d: %x\n", licznik, (*nowyElement));
	(*nowyElement)->nastepny = (*nastepnyElement);
	(*nowyElement)->poprzedni = NULL;
	(*nowyElement)->length = length;

	(*nastepnyElement)->poprzedni = (*nowyElement);
	printf("Adres w poprzedniego wzgl nastepnego: %x\n\n", (*nastepnyElement)->poprzedni);
	(*nastepnyElement) = (*nowyElement);
}

void dodajDoKolejkiUdp(struct elementKolejkiUdp **nowyElement,
		struct elementKolejkiUdp **nastepnyElement, int length, int licznik) {

	printf("Adres nowego nr %d: %x\n", licznik, (*nowyElement));
	(*nowyElement)->nastepny = (*nastepnyElement);
	(*nowyElement)->poprzedni = NULL;
	(*nowyElement)->length = length;

	(*nastepnyElement)->poprzedni = (*nowyElement);
	printf("Adres w poprzedniego wzgl nastepnego: %x\n\n", (*nastepnyElement)->poprzedni);
	(*nastepnyElement) = (*nowyElement);
}

void dodajDoKolejkiIcmp(struct elementKolejkiIcmp **nowyElement,
		struct elementKolejkiIcmp **nastepnyElement, int length, int licznik) {

	printf("Adres nowego nr %d: %x\n", licznik, (*nowyElement));
	(*nowyElement)->nastepny = (*nastepnyElement);
	(*nowyElement)->poprzedni = NULL;
	(*nowyElement)->length = length;

	(*nastepnyElement)->poprzedni = (*nowyElement);
	printf("Adres w poprzedniego wzgl nastepnego: %x\n\n", (*nastepnyElement)->poprzedni);
	(*nastepnyElement) = (*nowyElement);
}

void dodajDoKolejkiInnyIPv4(struct elementKolejkiInnyIpv4 **nowyElement,
		struct elementKolejkiInnyIpv4 **nastepnyElement, int length, int licznik) {

	printf("Adres nowego nr %d: %x\n", licznik, (*nowyElement));
	(*nowyElement)->nastepny = (*nastepnyElement);
	(*nowyElement)->poprzedni = NULL;
	(*nowyElement)->length = length;

	(*nastepnyElement)->poprzedni = (*nowyElement);
	printf("Adres w poprzedniego wzgl nastepnego: %x\n\n", (*nastepnyElement)->poprzedni);
	(*nastepnyElement) = (*nowyElement);
}

void dodajDoKolejkiINNY(struct elementKolejkiINNY **nowyElement,
		struct elementKolejkiINNY **nastepnyElement, int length, int licznik) {

	printf("Adres nowego nr %d: %x\n", licznik, (*nowyElement));
	(*nowyElement)->nastepny = (*nastepnyElement);
	(*nowyElement)->poprzedni = NULL;
	(*nowyElement)->length = length;

	(*nastepnyElement)->poprzedni = (*nowyElement);
	printf("Adres w poprzedniego wzgl nastepnego: %x\n\n", (*nastepnyElement)->poprzedni);
	(*nastepnyElement) = (*nowyElement);
}


void wyslanieDatagramuArp(struct ethArp ethArp, int length) {

	//definicja zmiennych
	int s_out; /*deskryptor gniazda*/
	int j;

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;



	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;


	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
	//Adres docelowy Eth
	unsigned char dest_mac[6] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb };
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);

	//eh->h_proto = htons (0x0800); //Protokol warstwy wyzszej: 0x0800 - pakiet IPv4
	//////////////////////////////////////////////////////////////////////////////

	/////////////////wylosuj lub ustaw dane dane do pola danych///////////////////////////////
	//UWAGA! BUFOR DANYCH RAMKI JEST NASTEPUJACY: data[]
//	for (j = 0; j < 1500; j++) {
//		//data[j] = (unsigned char)((int) (255.0*rand()/(RAND_MAX+1.0)));
//		data[j] = 0xaa;
//	}
	////////////////////////////////////////////////////////////////////////////

	//**************************wyslij ramke***********************************
#if 1 //tu mozna zablokowac wysylanie
	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	//usatwiono index urzadzenia siecowego
	socket_address.sll_ifindex = ifindex;
	//memcpy((void*)(buffer + 14), (ethArp + 14), (length - 14));
	memcpy(buffer, &ethArp, length);
	send_result = sendto(s_out, buffer, length, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}

	//=======wypisz zawartosc bufora do wyslania===========
#if 1
	printf("Dane do wyslania: \n");
	for (j = 0; j < send_result; j++) {
		printf("%02x ", *(etherhead + j));
	}
	printf("\n");
#endif
	//========koniec wypisywania===========================

#endif //konic blokady wysylania
	//*******************************************************************************
	zwalnianiePamieciDatagramu(buffer);
}

void wyslanieDatagramuIcmp(struct ethIpIcmp ethIpIcmp, int length) {

	//definicja zmiennych
	int s_out; /*deskryptor gniazda*/
	int j;

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;



	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;


	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
	//Adres docelowy Eth
	unsigned char dest_mac[6] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb };
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	//eh->h_proto = htons (0x0800); //Protokol warstwy wyzszej: 0x0800 - pakiet IPv4
	//////////////////////////////////////////////////////////////////////////////

	/////////////////wylosuj lub ustaw dane dane do pola danych///////////////////////////////
	//UWAGA! BUFOR DANYCH RAMKI JEST NASTEPUJACY: data[]
//	for (j = 0; j < 1500; j++) {
//		//data[j] = (unsigned char)((int) (255.0*rand()/(RAND_MAX+1.0)));
//		data[j] = 0xaa;
//	}
	////////////////////////////////////////////////////////////////////////////

	//**************************wyslij ramke***********************************
#if 1 //tu mozna zablokowac wysylanie
	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	//usatwiono index urzadzenia siecowego
	socket_address.sll_ifindex = ifindex;

	//memcpy((void*)(buffer + 14), (ethIpIcmp + 14), (length - 14));
	memcpy(buffer, &ethIpIcmp, length);
	send_result = sendto(s_out, buffer, length, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}

	//=======wypisz zawartosc bufora do wyslania===========
#if 1
	printf("Dane do wyslania: \n");
	for (j = 0; j < send_result; j++) {
		printf("%02x ", *(etherhead + j));
	}
	printf("\n");
#endif
	//========koniec wypisywania===========================

#endif //konic blokady wysylania
	//*******************************************************************************
	zwalnianiePamieciDatagramu(buffer);
}

void wyslanieDatagramuTcp(struct ethIpTcp ethIpTcp, int length) {

	//definicja zmiennych
	int s_out; /*deskryptor gniazda*/
	int j;

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;


	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;


	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
	//Adres docelowy Eth
	unsigned char dest_mac[6] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb };
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	//eh->h_proto = htons (0x0800); //Protokol warstwy wyzszej: 0x0800 - pakiet IPv4
	//////////////////////////////////////////////////////////////////////////////

	/////////////////wylosuj lub ustaw dane dane do pola danych///////////////////////////////
	//UWAGA! BUFOR DANYCH RAMKI JEST NASTEPUJACY: data[]
//	for (j = 0; j < 1500; j++) {
//		//data[j] = (unsigned char)((int) (255.0*rand()/(RAND_MAX+1.0)));
//		data[j] = 0xaa;
//	}
	////////////////////////////////////////////////////////////////////////////

	//**************************wyslij ramke***********************************
#if 1 //tu mozna zablokowac wysylanie
	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	//usatwiono index urzadzenia siecowego
	socket_address.sll_ifindex = ifindex;
	//memcpy((void*)(buffer + 14), (ethIpTcp + 14), (length - 14));
	memcpy(buffer, &ethIpTcp, length);
	send_result = sendto(s_out, buffer, length, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}

	//=======wypisz zawartosc bufora do wyslania===========
#if 1
	printf("Dane do wyslania: \n");
	for (j = 0; j < send_result; j++) {
		printf("%02x ", *(etherhead + j));
	}
	printf("\n");
#endif
	//========koniec wypisywania===========================

#endif //konic blokady wysylania
	//*******************************************************************************
	zwalnianiePamieciDatagramu(buffer);
}

void wyslanieDatagramuUdp(struct ethIpUdp ethIpUdp, int length) {

	//definicja zmiennych
	int s_out; /*deskryptor gniazda*/
	int j;

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;



	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;


	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
	//Adres docelowy Eth
	unsigned char dest_mac[6] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb };
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	//eh->h_proto = htons (0x0800); //Protokol warstwy wyzszej: 0x0800 - pakiet IPv4
	//////////////////////////////////////////////////////////////////////////////

	/////////////////wylosuj lub ustaw dane dane do pola danych///////////////////////////////
	//UWAGA! BUFOR DANYCH RAMKI JEST NASTEPUJACY: data[]
//	for (j = 0; j < 1500; j++) {
//		//data[j] = (unsigned char)((int) (255.0*rand()/(RAND_MAX+1.0)));
//		data[j] = 0xaa;
//	}
	////////////////////////////////////////////////////////////////////////////

	//**************************wyslij ramke***********************************
#if 1 //tu mozna zablokowac wysylanie
	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	//usatwiono index urzadzenia siecowego
	socket_address.sll_ifindex = ifindex;
	//memcpy((void*)(buffer + 14), (ethIpUdp + 14), (length - 14));
	memcpy(buffer, &ethIpUdp, length);
	send_result = sendto(s_out, buffer, length, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}

	//=======wypisz zawartosc bufora do wyslania===========
#if 1
	printf("Dane do wyslania: \n");
	for (j = 0; j < send_result; j++) {
		printf("%02x ", *(etherhead + j));
	}
	printf("\n");
#endif
	//========koniec wypisywania===========================

#endif //konic blokady wysylania
	//*******************************************************************************
	zwalnianiePamieciDatagramu(buffer);
}

void wyslanieDatagramuInnyIPv4(struct ethIpData ethIpData, int length) {

	//definicja zmiennych
	int s_out; /*deskryptor gniazda*/
	int j;

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;


	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;


	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
	//Adres docelowy Eth
	unsigned char dest_mac[6] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb };
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	//eh->h_proto = htons (0x0800); //Protokol warstwy wyzszej: 0x0800 - pakiet IPv4
	//////////////////////////////////////////////////////////////////////////////

	/////////////////wylosuj lub ustaw dane dane do pola danych///////////////////////////////
	//UWAGA! BUFOR DANYCH RAMKI JEST NASTEPUJACY: data[]
//	for (j = 0; j < 1500; j++) {
//		//data[j] = (unsigned char)((int) (255.0*rand()/(RAND_MAX+1.0)));
//		data[j] = 0xaa;
//	}
	////////////////////////////////////////////////////////////////////////////

	//**************************wyslij ramke***********************************
#if 1 //tu mozna zablokowac wysylanie
	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	//usatwiono index urzadzenia siecowego
	socket_address.sll_ifindex = ifindex;
	//memcpy((void*)(buffer + 14), (ethIpData + 14), (length - 14));
	memcpy(buffer, &ethIpData, length);
	send_result = sendto(s_out, buffer, length, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}

	//=======wypisz zawartosc bufora do wyslania===========
#if 1
	printf("Dane do wyslania: \n");
	for (j = 0; j < send_result; j++) {
		printf("%02x ", *(etherhead + j));
	}
	printf("\n");
#endif
	//========koniec wypisywania===========================

#endif //konic blokady wysylania
	//*******************************************************************************
	zwalnianiePamieciDatagramu(buffer);
}

void wyslanieDatagramuINNY(struct ethData ethData, int length) {

	//definicja zmiennych
	int s_out; /*deskryptor gniazda*/
	int j;

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;


	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;


	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
	//Adres docelowy Eth
	unsigned char dest_mac[6] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb };
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	//eh->h_proto = htons (0x0800); //Protokol warstwy wyzszej: 0x0800 - pakiet IPv4
	//////////////////////////////////////////////////////////////////////////////

	/////////////////wylosuj lub ustaw dane dane do pola danych///////////////////////////////
	//UWAGA! BUFOR DANYCH RAMKI JEST NASTEPUJACY: data[]
//	for (j = 0; j < 1500; j++) {
//		//data[j] = (unsigned char)((int) (255.0*rand()/(RAND_MAX+1.0)));
//		data[j] = 0xaa;
//	}
	////////////////////////////////////////////////////////////////////////////

	//**************************wyslij ramke***********************************
#if 1 //tu mozna zablokowac wysylanie
	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	//usatwiono index urzadzenia siecowego
	socket_address.sll_ifindex = ifindex;

	//memcpy((void*)(buffer + 14), (ethData + 14), (length - 14));
	memcpy(buffer, &ethData, length);
	send_result = sendto(s_out, buffer, length, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}

	//=======wypisz zawartosc bufora do wyslania===========
#if 1
	printf("Dane do wyslania: \n");
	for (j = 0; j < send_result; j++) {
		printf("%02x ", *(etherhead + j));
	}
	printf("\n");
#endif
	//========koniec wypisywania===========================

#endif //konic blokady wysylania
	//*******************************************************************************
	zwalnianiePamieciDatagramu(buffer);
}


void zwalnianiePamieciDatagramu(void *buffer){
    free (buffer);
    printf("\nUsunalem\n");
};

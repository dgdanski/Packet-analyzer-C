struct naglowekEthernet{
    unsigned char destinationAddress[6]; //unsigned char zapobiega wyrzucaniu calego bajta np 0xffffffff
    unsigned char sourceAddress[6];
    unsigned short int frameType;
};
struct ipFlags {
	unsigned short int fragmentOffset:13;
	unsigned char flags:3;
};
struct ipVersionLength {
    unsigned char	length:4;
	unsigned char	version:4;
};
struct naglowekIp {
	struct ipVersionLength ipVersionLength;
    unsigned char ecn;
    unsigned short int totalLength;
    unsigned short int identificationNumber;
    struct ipFlags ipFlags;
    unsigned char timeOfLife;
    unsigned char protocol;
    unsigned short int headerChecksum;
    unsigned int sourceAddress;
    unsigned int destinationAddress;
};

struct naglowekArp{
    unsigned short int hType;
    unsigned short int pType;
    unsigned char hLen;
    unsigned char pLen;
    unsigned short int oper;
    unsigned char sourceMacAddress[6];
    unsigned int sourceIpAddress;
    unsigned char destinationMacAddress[6];
    unsigned int destinationIpAddress;
};
struct ethArp{
    struct naglowekEthernet naglowekEthernet;
    struct naglowekArp naglowekArp;
    unsigned char buforDanych[1486];

};

struct naglowekIcmp{
    unsigned char type;
    unsigned char code;
    unsigned short int checkSum;
};
struct ethIpIcmp{
    struct naglowekEthernet naglowekEthernet;
    struct naglowekIp naglowekIp;
    struct naglowekIcmp naglowekIcmp;
    unsigned char buforDanych[1480];
};

struct naglowekUdp{
    unsigned short int sourcePort;
    unsigned short int destinationPort;
    unsigned short int length;
    unsigned short int checkSum;
};
struct ethIpUdp{
    struct naglowekEthernet naglowekEthernet;
    struct naglowekIp naglowekIp;
    struct naglowekUdp naglowekUdp;
    unsigned char buforDanych[1476];
};

struct group1{
    unsigned char ns:1;
    unsigned char reserved:3;
    unsigned char dataOffset:4;
};
struct group2{
    unsigned char fin:1;
    unsigned char syn:1;
    unsigned char rst:1;
    unsigned char psh:1;
    unsigned char ack:1;
    unsigned char urg:1;
    unsigned char ece:1;
    unsigned char cwr:1;
};
struct naglowekTcp{
    unsigned short int sourcePort;
    unsigned short int destinationPort;
    unsigned int sequenceNumber;
    unsigned int acknowledgementNumber;
    struct group1 group1;
    struct group2 group2;
    unsigned short int window;
    unsigned short int checkSum;
    unsigned short int urgentPointer;
    unsigned int options;
};
struct ethIpTcp{
    struct naglowekEthernet naglowekEthernet;
    struct naglowekIp naglowekIp;
    struct naglowekTcp naglowekTcp;
    unsigned char buforDanych[1460];
};

struct ethIpData{
	struct naglowekEthernet naglowekEthernet;
	struct naglowekIp naglowekIp;
	unsigned char buforDanych[1484];
};

struct ethData{
	struct naglowekEthernet naglowekEthernet;
	unsigned char buforDanych[1504];
};


struct elementKolejkiArp {
	struct elementKolejki *nastepny;
	struct elementKolejki *poprzedni;
	struct elementKolejki *pierwszy;
	unsigned int protocolChecker;
	unsigned int length;
	struct ethArp *ethArp;
};

struct elementKolejkiIcmp {
	struct elementKolejki *nastepny;
	struct elementKolejki *poprzedni;
	struct elementKolejki *pierwszy;
	unsigned int protocolChecker;
	unsigned int length;
	struct ethIpIcmp *ethIpIcmp;
};

struct elementKolejkiTcp {
	struct elementKolejki *nastepny;
	struct elementKolejki *poprzedni;
	struct elementKolejki *pierwszy;
	unsigned int protocolChecker;
	unsigned int length;
	struct ethIpTcp *ethIpTcp;
};

struct elementKolejkiUdp {
	struct elementKolejki *nastepny;
	struct elementKolejki *poprzedni;
	struct elementKolejki *pierwszy;
	unsigned int protocolChecker;
	unsigned int length;
	struct ethIpUdp *ethIpUdp;
};

struct elementKolejkiInnyIpv4 {
	struct elementKolejki *nastepny;
	struct elementKolejki *poprzedni;
	struct elementKolejki *pierwszy;
	unsigned int protocolChecker;
	unsigned int length;
	struct ethIpData *ethIpData;
};

struct elementKolejkiINNY {
	struct elementKolejki *nastepny;
	struct elementKolejki *poprzedni;
	struct elementKolejki *pierwszy;
	unsigned int protocolChecker;
	unsigned int length;
	struct ethData *ethData;
};


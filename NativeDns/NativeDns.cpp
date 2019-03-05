/* main function, input check, socket generating and error check*/
/*
 * CPSC 612 Spring 2019
 * HW2
 * by Chengyi Min
 */

#include "pch.h"


int main(int argc, char **argv)
{
	if (argc != 3)
	{
		printf("Usage: executable query_url DNS_addr");
		return 0;
	}
	Utilities ut;

	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_real_distribution<> dis(1, 65535);

	USHORT txID = dis(gen);

	char *urlCopy = argv[1];
	char *dnsAddr = argv[2];
	char url[MAX_DNS_SIZE];
	memcpy(url, urlCopy, strlen(urlCopy) + 1);
	DWORD IP = inet_addr(url);
	if (IP != INADDR_NONE)
	{
		ut.ptrQuestion(urlCopy, url);
	}
	int pkt_size = strlen(url) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);

	
	char * query = url;

	char *buf = new char[pkt_size];

	FixedDNSheader *fdh = (FixedDNSheader *)buf;
	QueryHeader *qh = (QueryHeader *)(buf + pkt_size - sizeof(QueryHeader));
	fdh->ID = htons(txID);
	fdh->flags = htons(DNS_QUERY | DNS_RD);
	fdh->nAnswers = htons(0);
	fdh->nQuestions = htons(1);
	fdh->nAdditional = htons(0);
	fdh->nAuthority = htons(0);

	ut.TXID = txID;

	qh->qClass = htons(DNS_INET);
	qh->qType = htons(DNS_A);
	if (IP != INADDR_NONE)
	{
		qh->qType = htons(DNS_PTR);
		//Reverse query
		//Type A
	}
	printf("Lookup\t: %s\n", url);
	printf("Query\t: %s, type %d, TXID 0x%.4X\n", url, htons(qh->qType), htons(fdh->ID));
	printf("Server\t: %s\n", dnsAddr);
	printf("********************************\n");
	// ##############
	
	ut.makeDNSquestion(buf, url);

	for (int i = 0; i < MAX_ATTEMPTS; i++)
	{
		printf("Attempt %d with %d bytes... ", i, pkt_size);
		int sendSize = 0;

		// ############## Forming Header


		WSADATA wsaData;

		//Initialize WinSock; once per program run
		WORD wVersionRequested = MAKEWORD(2, 2);
		if (WSAStartup(wVersionRequested, &wsaData) != 0) {
			printf("WSAStartup error %d\n", WSAGetLastError());
			WSACleanup();
			exit(0);
		}

		//UDP socket connection
		SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock == INVALID_SOCKET)
		{
			printf("socket generate error %d", WSAGetLastError());
		}
		struct sockaddr_in local;
		memset(&local, 0, sizeof(local));
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = INADDR_ANY;
		local.sin_port = htons(0);
		if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR)
		{
			printf("socket error %d", WSAGetLastError());
			delete buf;
			closesocket(sock);
			return 0;
		}

		struct sockaddr_in remote;
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(dnsAddr);
		remote.sin_port = htons(53);
		if (sendto(sock, buf, pkt_size, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR)
		{
			printf("socket error %d", WSAGetLastError());
			delete buf;
			closesocket(sock);
			return 0;
		}
		

		char *recvBuf = new char[MAX_DNS_SIZE];
		int Rcode = ut.dnsRead(sock, recvBuf, remote);
		// close the socket to this server; open again for the next one
		closesocket(sock);

		if (!(Rcode==TIMEOUT_CODE))
			break;	
	}
	delete buf;
	WSACleanup();
}


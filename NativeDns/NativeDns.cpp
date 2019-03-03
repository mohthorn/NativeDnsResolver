// NativeDns.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"


int main(int argc, char **argv)
{
	if (argc != 3)
	{
		printf("Usage: executable query_url DNS_addr");
		return 0;
	}

	char *url = argv[1];
	char *dnsAddr = argv[2];

	int pkt_size = strlen(url) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);

	char *buf =new char[pkt_size];
	int sendSize = 0;

	Utilities ut;

	WSADATA wsaData;

	//Initialize WinSock; once per program run
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		exit(0);
	}





	// ############## Forming Header
	FixedDNSheader *fdh =(FixedDNSheader *) buf;
	QueryHeader *qh = (QueryHeader *)(buf + pkt_size - sizeof(QueryHeader));
	fdh->ID = htons(1);
	fdh->flags = htons(DNS_QUERY | DNS_RD );
	fdh->nAnswers = htons(0);
	fdh->nQuestions = htons(1);
	fdh->nAdditional = htons(0);
	fdh->nAuthority = htons(0);

	qh->qClass = htons(DNS_INET);
	qh->qType = htons(DNS_A);
	DWORD IP = inet_addr(url);
	if (IP != INADDR_NONE)
	{
		qh->qType = htons(DNS_PTR);
		//Reverse query
		//Type A
	}
	ut.makeDNSquestion(buf, url);
	// ##############

	
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
		printf("socket bind error %d", WSAGetLastError());
		return 0;
	}

	struct sockaddr_in remote;
	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(dnsAddr);
	remote.sin_port = htons(53);
	if (sendto(sock, buf, pkt_size, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR)
	{
		printf("socket send error %d", WSAGetLastError());
		delete buf;
		return 0;
	}
	delete buf;

	char *recvBuf = new char[MAX_DNS_SIZE];
	ut.dnsRead(sock, recvBuf, remote);
	// close the socket to this server; open again for the next one
	closesocket(sock);

	// call cleanup when done with everything and ready to exit program
	WSACleanup();
	//type-PTR
}


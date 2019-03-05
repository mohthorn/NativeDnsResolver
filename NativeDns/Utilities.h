#pragma once
#include<unordered_set>
using namespace std;
class Utilities
{
public:
	int recvSize;
	USHORT TXID;

	void makeDNSquestion(char* buf, char *host);
	int dnsRead(SOCKET  sock, char* buf, struct sockaddr_in &remote);
	int jumpRead(int curPos, u_char * buf, u_char *name, unordered_set<int> seenOffsets);
	int recordRead(char * buf, u_char * &off);
	void ptrQuestion(char * ip, char * buf);
};


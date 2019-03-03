#pragma once
class Utilities
{
public:
	void outputPrint(char* url, int size);
	void makeDNSquestion(char* buf, char *host);
	int dnsRead(SOCKET  sock, char* buf, struct sockaddr_in &remote);
};


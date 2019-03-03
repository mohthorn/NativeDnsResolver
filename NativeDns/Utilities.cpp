#include "pch.h"
#include "Utilities.h"



void Utilities::outputPrint(char* url, int size)
{
	printf("********************************");
}

void Utilities::makeDNSquestion(char * original_buf , char * host)
{
	char * buf = original_buf + sizeof(FixedDNSheader);
	int i = 0;
	//int j = 0;
	char * ptr_s = host;
	char *	ptr_e = host;
	while (strlen(ptr_s) > 0 && (*ptr_s!=NULL))
	{
		if (*ptr_s == '.')
			ptr_s++;
		ptr_e = strchr(ptr_s, '.');
		if (!ptr_e)
			ptr_e = strlen(ptr_s) + ptr_s;
		int size_of_word = ptr_e-ptr_s;
		buf[i++] = size_of_word;
		memcpy(buf + i, ptr_s, size_of_word);
		i += size_of_word;
		ptr_s = ptr_e ;
	}
	buf[i] = 0;
}

//u_char * printUncompressed(u_char * buf, char *host)
//{
//	char *host_start = host;
//	//print host name
//	while (*buf != 0)
//	{
//		int wLength = *buf;
//		buf++;
//		for (int j = 0; j < wLength; j++)
//		{
//			sprintf(host_start, "%c", *buf);
//			host_start++;
//			buf++;
//		}
//		if (*buf != 0)
//		{
//			sprintf(host_start, ".");
//			host_start++;
//		}
//	}
//	*host_start = 0;
//	printf("%s", host);
//	printf(" ");
//	return buf;
//}

int jumpRead(int curPos, u_char * buf, u_char *name)
{
	int retPos=curPos;
	int level = 0;
	int jump_flag = 0;
	if (buf[curPos] >= 0xc0)
	{
		int jumpTo = ((buf[curPos] & 0x3f) << 8) + buf[curPos + 1];
		jumpRead(jumpTo, buf, name);
		retPos += 2;
		jump_flag = 1;
	}
	else
	{
		while (buf[curPos] != 0 && buf[curPos]<0xc0)
		{
			int wLength = buf[curPos];
			curPos++;
			for (int j = 0; j < wLength; j++)
			{
				*name = buf[curPos];
				name++;
				curPos++;
			}
			if (buf[curPos] != 0)
			{
				*name = '.';
				name++;
			}
			else
			{
				*name = 0;
			}
			retPos += (wLength + 1);
		}

	}

	//if no jump, a jump is possible
	if (!jump_flag && buf[curPos]!=0)
	{
		jumpRead(retPos, buf, name);
		retPos += 2;
	}

	return retPos;
}

int Utilities::dnsRead(SOCKET  sock, char * buf, struct sockaddr_in &remote)
{
	//##########receiving
	fd_set fd;
	FD_ZERO(&fd); // clear the set 
	FD_SET(sock, &fd); // add your socket to the set
	TIMEVAL *timeout = new TIMEVAL;
	timeout->tv_sec = 10;
	timeout->tv_usec = 0;
	int available = select(0, &fd, NULL, NULL, timeout);
	
	if (available > 0)
	{
		struct sockaddr_in response;
		int responseSize = sizeof(response);
		if (recvfrom(sock, buf, MAX_DNS_SIZE, 0, (struct sockaddr*) &response, &responseSize) == 0)
		{
			printf("response error %d\n", WSAGetLastError());
			return 0;
		}

		//check sender
		if (response.sin_addr.s_addr != remote.sin_addr.s_addr || response.sin_port != remote.sin_port)
		{
			printf("Response Not from target DNS server\n");
			return 0;
		}

		FixedDNSheader *fdh = (FixedDNSheader*)buf;
		
		printf("response ID: %d, flags: 0x%x\n", ntohs(fdh->ID), ntohs(fdh->flags));
		int nQuestions = ntohs(fdh->nQuestions);
		int nAnswers = ntohs(fdh->nAnswers);
		int nAuthorities = ntohs(fdh->nAuthority);
		int nAdditional = ntohs(fdh->nAdditional);
		//print Questions

		u_char * off = (u_char*)buf;
		if (nQuestions > 0)
		{
			printf("------------ [questions] ----------\n");
			off = (u_char*)buf + sizeof(FixedDNSheader);

			for (int i = 0; i < nQuestions; i++)
			{
				char host[MAX_DNS_SIZE];
				jumpRead(0, off, (u_char*)host);
				printf("%s ", host);
				//print query header
				QueryHeader *qh = (QueryHeader *)(off + 2 +strlen(host) );
				printf("type %d class %d\n", ntohs(qh->qType),ntohs(qh->qClass));
				off = (u_char*)qh + sizeof(QueryHeader);
			}
			
		}
		//print Answers
		if (nAnswers > 0)
		{
			printf("------------ [answers] ----------\n");
			
			for (int i = 0; i < nAnswers; i++)
			{
				int curPos = off - (u_char*)buf;

				u_char name[MAX_DNS_SIZE];

				int newPos = jumpRead(curPos, (u_char*)buf, name);

				printf("%s ", name);
				DNSanswerHdr *frr = (DNSanswerHdr*)(buf + newPos);
				printf("%d %d %d length: %d ", ntohs(frr->qType), ntohs(frr->qClass), ntohl(frr->ttl), ntohs(frr->len));
				u_char* ip = (u_char*)buf + newPos + sizeof(DNSanswerHdr);
				printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
				off = ip + ntohs(frr->len);
			}

		}

		if (nAuthorities > 0)
		{
			printf("------------ [authority] ----------\n");

			for (int i = 0; i < nAuthorities; i++)
			{
				int curPos = off - (u_char*)buf;

				u_char name[MAX_DNS_SIZE];

				curPos = jumpRead(curPos, (u_char*)buf, name);

				printf("%s ", name);
				DNSanswerHdr *frr = (DNSanswerHdr*)(buf + curPos);
				printf("%d %d %d %d ", ntohs(frr->qType), ntohs(frr->qClass), ntohl(frr->ttl), ntohs(frr->len));	

				curPos = curPos + sizeof(DNSanswerHdr);
				u_char authName[MAX_DNS_SIZE];
				curPos = jumpRead(curPos, (u_char*)buf, authName);
				printf("%s\n", authName);
				off = (u_char*)buf + curPos;
			}
			if (nAdditional > 0)
			{
				printf("------------ [additional] ----------\n");

				for (int i = 0; i < nAdditional; i++)
				{
					int curPos = off - (u_char*)buf;

					u_char name[MAX_DNS_SIZE];

					curPos = jumpRead(curPos, (u_char*)buf, name);

					u_char* ip = (u_char*)buf + curPos + sizeof(DNSanswerHdr);
					DNSanswerHdr *frr = (DNSanswerHdr*)(buf + curPos);
					if (ntohs(frr->len) == 4)
					{
						printf("%s ", name);
						printf("%d %d %d %d ", ntohs(frr->qType), ntohs(frr->qClass), ntohl(frr->ttl), ntohs(frr->len));
						
						printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
						
					}
					off = ip + ntohs(frr->len);
				}
			}
		}

	}
	return 0;
}

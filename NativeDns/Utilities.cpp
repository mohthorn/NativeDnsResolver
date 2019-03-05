/* functions: makeDNSquestion, make PTR type question, jump read function, recv packets
	reading single record
/*
 * CPSC 612 Spring 2019
 * HW2
 * by Chengyi Min
 */

#include "pch.h"
#include "Utilities.h"

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


int Utilities::jumpRead(int curPos, u_char * buf, u_char * name, unordered_set<int> seenOffsets)
{
	if (curPos < sizeof(FixedDNSheader))
	{
		printf("++\tinvalid record: jump into fixed header\n");
		return FAIL_CODE;
	}

	if (curPos >= recvSize)
	{
		printf("++\tinvalid record: jump beyond packet boundary\n");
		return FAIL_CODE;
	}
	int retPos=curPos;
	int level = 0;
	int jump_flag = 0;
	if (buf[curPos] >= 0xc0)
	{
		if (curPos+1 >= recvSize)
		{
			printf("\n++\tinvalid record : truncated jump offset\n");
			return TRUNCATED_OFFSET;
		}
		int jumpTo = ((buf[curPos] & 0x3f) << 8) + buf[curPos + 1];
		int prevIPSize = seenOffsets.size();
		seenOffsets.insert(jumpTo);
		if (seenOffsets.size() <= prevIPSize)
		{
			printf("\n++\tinvalid record: jump loop\n");
			return JUMP_LOOP;
		}
		if (jumpRead(jumpTo, buf, name,seenOffsets) <0)
		{
			return FAIL_CODE;
		}
		retPos += 2;
		jump_flag = 1;
	}
	else
	{
		while (buf[curPos] != 0 && buf[curPos]<0xc0)
		{
			if (curPos  >= recvSize)
			{
				printf("\n++\tinvalid record : truncated name\n");
				return TRUNCATED_NAME;
			}
			int wLength = buf[curPos];
			if (wLength + curPos >= recvSize)
			{
				printf("\n++\tinvalid record : truncated name\n");
				return TRUNCATED_NAME;
			}
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
				retPos += 1;
			}
			retPos += (wLength + 1);
		}

	}

	//if no jump, a jump is possible
	if (!jump_flag && buf[curPos]!=0)
	{
		if (curPos  >= recvSize)
		{
			printf("\n++\tinvalid record : truncated name\n");
			return TRUNCATED_NAME;
		}
		if (curPos + 1 >= recvSize)
		{
			printf("\n++\tinvalid record : truncated jump offset\n");
			return TRUNCATED_OFFSET;
		}
		int jumpTo = ((buf[curPos] & 0x3f) << 8) + buf[curPos + 1];
		int jumpCode;
		if ((jumpCode = jumpRead(retPos, buf, name, seenOffsets))<0 )
		{
			return FAIL_CODE;
		}
		retPos += 2;
	}

	return retPos;
}

void Utilities::ptrQuestion(char * ip, char * buf)
{
	char * ptr_s = ip;
	USHORT nIp[4] = {0,0,0,0};
	for (int i = 0; i < 4; i++)
	{
		char *ptr_e = strchr(ptr_s,'.');
		if (ptr_e == NULL)
		{
			ptr_e = ptr_s;
			while (*ptr_e != 0)
			{
				ptr_e++;
			}
		}
		for (int j = 0; j < ptr_e - ptr_s; j++)
		{
			nIp[i] = (ptr_s[j]-'0') + nIp[i] * 10;
		}
		ptr_s = ptr_e + 1;
	}
	sprintf(buf, "%d.%d.%d.%d.in-addr.arpa", nIp[3], nIp[2], nIp[1], nIp[0]);

}

int Utilities::recordRead(char * buf, u_char * &off)
{
	int curPos = off - (u_char*)buf;

	u_char name[MAX_DNS_SIZE];

	unordered_set<int> seenOffsets;
	seenOffsets.empty();
	curPos = jumpRead(curPos, (u_char*)buf, name, seenOffsets);

	if (curPos <0)
	{
		return FAIL_CODE;
	}

	u_char* ip = (u_char*)buf + curPos + sizeof(DNSanswerHdr);
	DNSanswerHdr *frr = (DNSanswerHdr*)(buf + curPos);

	if ((ip - (u_char*)buf) > recvSize)
	{
		printf("++\tinvalid record : truncated fixed RR header\n");
		return FAIL_CODE;
	}
	if ((ip + ntohs(frr->len) -(u_char*)buf) > recvSize)
	{
		printf("++\tinvalid record : RR value length beyond packet");
		return FAIL_CODE;
	}

	if (ntohs(frr->qType) == DNS_A || ntohs(frr->qType) == DNS_CNAME || ntohs(frr->qType) == DNS_NS || ntohs(frr->qType) == DNS_PTR)
	{
		printf("\t%s ", name);

		switch (ntohs(frr->qType)) {
		case 1: printf("A"); break;
		case 2: printf("NS"); break;
		case 5: printf("CNAME"); break;
		case 12: printf("PTR"); break;
		default: printf("Wrong Type %d", ntohs(frr->qType)); break;
		}
		printf(" ");
		//printf("%d %d %d %d ", ntohs(frr->qType), ntohs(frr->qClass), ntohl(frr->ttl), ntohs(frr->len));

		u_char* ip = (u_char*)buf + curPos + sizeof(DNSanswerHdr);
		if (ntohs(frr->qType) == DNS_A)
		{
			printf("%d.%d.%d.%d ", ip[0], ip[1], ip[2], ip[3]);

		}
		if (ntohs(frr->qType) == DNS_CNAME || ntohs(frr->qType) == DNS_NS || ntohs(frr->qType) == DNS_PTR)
		{
			curPos = ip - (u_char*)buf;
			u_char aHost[MAX_DNS_SIZE];
			seenOffsets.empty();
			curPos = jumpRead(curPos, (u_char*)buf, aHost,seenOffsets);
			if (curPos <0)
				return FAIL_CODE;
			printf("%s ", aHost);

		}
		printf("TTL = %d\n", ntohl(frr->ttl));

	}
	off = ip + ntohs(frr->len);
	return 0;
}

int Utilities::dnsRead(SOCKET  sock, char * buf, struct sockaddr_in &remote)
{
	//##########receiving
	clock_t start;
	clock_t end;
	clock_t duration;
	start = clock();
	fd_set fd;
	FD_ZERO(&fd); // clear the set 
	FD_SET(sock, &fd); // add your socket to the set
	TIMEVAL *timeout = new TIMEVAL;
	timeout->tv_sec = 10;
	timeout->tv_usec = 0;
	int available = select(0, &fd, NULL, NULL, timeout);
	end = clock();
	duration = 1000.0*(end - start) / (double)(CLOCKS_PER_SEC);
	int Rcode = 5;

	if (available > 0)
	{
		struct sockaddr_in response;
		int responseSize = sizeof(response);
		if ((recvSize = recvfrom(sock, buf, MAX_DNS_SIZE, 0, (struct sockaddr*) &response, &responseSize)) < 0)
		{
			printf("socket error on receive %d\n", WSAGetLastError());
			return FAIL_CODE;
		}
		end = clock();
		duration = 1000.0*(end - start) / (double)(CLOCKS_PER_SEC);
		printf("response in %dms with %d bytes\n", duration, recvSize);
		if (recvSize < sizeof(FixedDNSheader))
		{
			printf("++\tinvalid reply: smaller than fixed header\n");
			return FAIL_CODE;
		}


		//check sender
		if (response.sin_addr.s_addr != remote.sin_addr.s_addr || response.sin_port != remote.sin_port)
		{
			printf("Response Not from target DNS server\n");
			return FAIL_CODE;
		}

		
		FixedDNSheader *fdh = (FixedDNSheader*)buf;
		
		int nQuestions = ntohs(fdh->nQuestions);
		int nAnswers = ntohs(fdh->nAnswers);
		int nAuthorities = ntohs(fdh->nAuthority);
		int nAdditional = ntohs(fdh->nAdditional);

		printf("\tTXID: 0x%.4X flags 0x%.4X questions %d answers %d authority %d additional %d\n", 
				ntohs(fdh->ID), 
				ntohs(fdh->flags),
				nQuestions,
				nAnswers,
				nAuthorities,
				nAdditional
				);

		Rcode = ntohs(fdh->flags) & 0x000f;

		if (TXID != ntohs(fdh->ID))
		{
			printf("++\tinvalid reply: TXID mismatch, sent 0x%.4X, received 0x%.4X\n", TXID, ntohs(fdh->ID));
			return FAIL_CODE;
		}

		if (Rcode)
		{
			printf("\tfailed with Rcode = %d\n", Rcode);
			return Rcode;
		}

		printf("\tsucceeded with Rcode = %d\n", Rcode);

		//print Questions

		u_char * off = (u_char*)buf;
		off = (u_char*)buf + sizeof(FixedDNSheader);
		if (nQuestions > 0)
		{
			printf("------------ [questions] ----------\n");
			

			for (int i = 0; i < nQuestions; i++)
			{
				if ((off - (u_char*)buf) >= recvSize)
				{
					printf("++\tinvalid section: not enough records\n");
					return FAIL_CODE;
				}
				char host[MAX_DNS_SIZE];
				int curPos = off - (u_char*)buf;
				unordered_set<int> seenOffsets;
				seenOffsets.empty();
				if (jumpRead(curPos, (u_char*)buf, (u_char*)host,seenOffsets) <0)
					return FAIL_CODE;
				printf("\t%s ", host);
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
				if ((off - (u_char*)buf) >= recvSize)
				{
					printf("++\tinvalid section: not enough records\n");
					return FAIL_CODE;
				}
				if (recordRead(buf, off) <0)
					return FAIL_CODE;
			}
		}

		if (nAuthorities > 0)
		{
			printf("------------ [authority] ----------\n");

			for (int i = 0; i < nAuthorities; i++)
			{
				if ((off - (u_char*)buf) >= recvSize)
				{
					printf("++\tinvalid section: not enough records\n");
					return FAIL_CODE;
				}
				if (recordRead(buf, off) <0)
					return FAIL_CODE;
			}
			
			
		}
		if (nAdditional > 0)
		{
			printf("------------ [additional] ----------\n");

			for (int i = 0; i < nAdditional; i++)
			{
				if ((off - (u_char*)buf) >= recvSize)
				{
					printf("++\tinvalid section: not enough records\n");
					return FAIL_CODE;
				}
				if (recordRead(buf, off) <0)
					return FAIL_CODE;
			}
		}

	}
	else
	{
		if (available == 0)
		{
			printf("timeout in %d ms\n", duration);
			Rcode = TIMEOUT_CODE;
		}
		if (available < 0)
		{
			printf("failed with %d on recv\n", WSAGetLastError());
			Rcode = FAIL_CODE;
		}
	}
	return Rcode;
}


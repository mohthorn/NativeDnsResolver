#pragma once
#include <Windows.h>

#pragma pack(push,1) 
class QueryHeader {
public:
	USHORT qType;
	USHORT qClass;
};

class FixedDNSheader {
public:
	USHORT ID;
	USHORT flags;
	USHORT nQuestions;
	USHORT nAnswers;
	USHORT nAuthority;
	USHORT nAdditional;
};

class DNSanswerHdr {
public:
	USHORT qType;
	USHORT qClass;
	UINT ttl;
	USHORT len;
};
#pragma pack(pop)

/*
 * CPSC 612 Spring 2019
 * HW2
 * by Chengyi Min
 */
#pragma once

#define DNS_A		1 /* name -> IP */ 
#define DNS_NS		2
#define DNS_CNAME	5
#define DNS_PTR		12
#define DNS_HINFO	13
#define DNS_MX		15
#define DNS_AXFR	252
#define	DNS_ANY		255

#define	DNS_INET	1

#define DNS_QUERY		(0<<15)
#define DNS_RESPONSE	(1<<15)
#define DNS_STDQUERY	(0<<11)
#define DNS_AA		(1<<10)
#define DNS_TC		(1<<9)
#define DNS_RD		(1<<8)
#define DNS_RA		(1<<7)

#define DNS_OK			0
#define DNS_FORMAT		1
#define DNS_SERVERFAIL	2
#define DNS_ERROR		3
#define DNS_NOTIMPL		4
#define DNS_REFUSSED	5

#define MAX_ATTEMPTS	3
#define MAX_DNS_SIZE	512
#define FAIL_CODE		-1
#define TIMEOUT_CODE	-2
#define TRUNCATED_OFFSET	-3
#define TRUNCATED_NAME	-4
#define JUMP_LOOP		-5
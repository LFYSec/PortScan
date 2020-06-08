#ifndef MYSOCK_H_H
#define MYSOCK_H_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>/*recvfrom() & sendto()*/
#include <signal.h>/*信号处理*/
#include <netinet/in.h>/*protocol参数形如IPPROTO_XXX的常值*/
#include <netinet/ip.h>/*ip帧头定义*/
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>/*icmp帧头定义*/
#include <sys/time.h>/*gettimeofday()*/
#include <time.h>/**/
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include "ping.h"


// #define u8 unsigned char
// #define u16 unsigned short

typedef unsigned char     u8;
//typedef uint8_t           u8;
typedef unsigned short    u16;
typedef unsigned long     u32;

#define MAXLINE 2048


struct ScanSock
{
    unsigned short portStart;
    unsigned short portEnd;
    char destIP[16];
    char sourIP[16];

};

struct Queue
{
    int data;
    struct Queue *next;
};

struct Queue *existPort;

struct ScanParam
{
    unsigned short sourPort;
    unsigned short destPort;
    char destIP[16];
    char sourIP[16];

};

struct PseudoHdr
{
    unsigned int        sIP;
    unsigned int        dIP;
    char                useless;
    char                protocol;
    unsigned short      length;
};



u8 flag_port[65535];
u8 flag_err;




#endif
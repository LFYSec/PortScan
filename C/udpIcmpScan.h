#ifndef UDPICMPSCAN_H_H
#define UDPICMPSCAN_H_H

#include "mysock.h"


int udpCnt;
static pthread_mutex_t udp_printf_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t udp_num_mutex = PTHREAD_MUTEX_INITIALIZER;
//extern pthread_mutex_t udp_printf_mutex;
//extern pthread_mutex_t udp_num_mutex;

void* udpIcmpScanPort(void *arg);
void* udpIcmpScanEach(void *arg);
void* udpIcmpScanRecv(void *arg);
void alarm_udp(int signo);

#endif
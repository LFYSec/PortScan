#ifndef TCPSYNSCAN_H_H
#define TCPSYNSCAN_H_H

#include "mysock.h"


int synCnt;
static pthread_mutex_t syn_printf_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t syn_num_mutex = PTHREAD_MUTEX_INITIALIZER;
//extern pthread_mutex_t syn_printf_mutex;
//extern pthread_mutex_t syn_num_mutex;

void* tcpSynScanPort(void *arg);
void* tcpSynScanEach(void *arg);
void* tcpSynScanRecv(void *arg);

#endif
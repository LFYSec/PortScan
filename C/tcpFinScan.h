#ifndef TCPFINSCAN_H_H
#define TCPFINSCAN_H_H

#include "mysock.h"


int finCnt;
static pthread_mutex_t fin_printf_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fin_num_mutex = PTHREAD_MUTEX_INITIALIZER;
//extern pthread_mutex_t fin_printf_mutex;
//extern pthread_mutex_t fin_num_mutex;

void* tcpFinScanPort(void *arg);
void* tcpFinScanEach(void *arg);
void* tcpFinScanRecv(void *arg);

#endif
#ifndef TCPCONSCAN_H_H
#define TCPCONSCAN_H_H

#include "mysock.h"

int connectCnt;
static pthread_mutex_t connect_printf_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t connect_num_mutex = PTHREAD_MUTEX_INITIALIZER;
//extern pthread_mutex_t connect_printf_mutex;
//extern pthread_mutex_t connect_num_mutex;

void* tcpConScanPort(void *arg);//端口扫描主线程
void* tcpConScanEach(void *arg);//端口扫描子线程

#endif
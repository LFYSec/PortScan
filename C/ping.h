//ping.h
#ifndef PING_H_H
#define PING_H_H

#include "mysock.h"
#include <pthread.h>
#include <unistd.h>

int ping(char *strIp);
unsigned short checksum(unsigned char*buf, unsigned int len);
void getMyIp(char *sourIP);
void alarm_timer(int signo);

int pingFlag;
#define PINGDATA 56

#endif
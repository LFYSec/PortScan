#include "mysock.h"
#include "ping.h"
#include "tcpConScan.h"
#include "tcpSynScan.h"
#include "tcpFinScan.h"
#include "udpIcmpScan.h"
int main(int argc, char *argv[])
{
    //printf("*******************************\n");
    if(argc<2 || argc>5){
        printf("please type correct parameters!\n");
        return 0;
    }
    
    char *destIPStr = argv[1]; //目标主机ip
    char *port1Str = argv[2]; //扫描的初始端口
    char *port2Str = argv[3]; //扫描的结束端口

    int cmd;
    if(argc ==5)
    {
        if(strcmp(argv[4],"SYN")==0)
            cmd = 2;
        else if(strcmp(argv[4],"FIN")==0)
            cmd = 3;
        else if(strcmp(argv[4],"UDP")==0)
            cmd = 4;
    }
    else
        cmd = 1;
    struct ScanSock s;
    //cmd = 4;//扫描方式
    
    s.portStart = atoi(port1Str);
    s.portEnd = atoi(port2Str);
    //s.destIP = malloc(sizeof(destIPStr));
    //s.sourIP = malloc(sizeof(destIPStr));
    strncpy(s.destIP, destIPStr, 16);
    //printf("*******************************\n");
    if(ping(s.destIP) == -1)//在扫描端口前先确定主机是否可达
    {
        printf("destination host does not exist!\n");
        return 0;
    }
    getMyIp(s.sourIP);//获取本机ip
    printf("my IP is %s\n", s.sourIP);
    pthread_t pidTh;
    int err;
    void* (*scanFunc[4])(void *arg);//函数数组
    scanFunc[0] = tcpConScanPort;
    scanFunc[1] = tcpSynScanPort;
    scanFunc[2] = tcpFinScanPort;
    scanFunc[3] = udpIcmpScanPort;
    //printf("*******************************\n");
    err = pthread_create(&pidTh, NULL, scanFunc[cmd-1], (void*)&s);
    if(err != 0)
    {
        printf("pthread_create:%s\n", strerror(err));
        exit(1);
    }
    //printf("*******************************\n");
    float costtime;
    struct timeval start;
    struct timeval end;
    float diff = 0;
    gettimeofday(&start, NULL);
    printf("*******************************\n");
    err = pthread_join(pidTh, NULL);//挂起等待扫面线程结束(duan cuo wu)
    printf("*******************************\n");
    if(err != 0)
    {
        printf("pthread_join:%s\n", strerror(err));
        exit(1);
    }
    printf("---exist port:\n");//打印开放的端口
    //printf("*******************************\n");
    struct Queue *tempQ;
    //printf("*******************************\n");
    while(existPort != NULL)
    {
        printf("%d\n",existPort->data);
        tempQ = existPort;
        existPort = existPort->next;
        free(tempQ);
    }
    printf("scan finish!\n");
    gettimeofday(&end, NULL);

    diff = 1000000*(end.tv_sec - start.tv_sec)+(end.tv_usec-start.tv_usec);
    printf("Total time: %.2f seconds\n", diff/1000000);
}
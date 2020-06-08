#include "udpIcmpScan.h"

//u8 flag_port[65535];
//u8 flag_err;
u8 flag_alarm;
void* udpIcmpScanEach(void *arg)
{
    int udpfd;
    uint ip_len, udp_len, pseu_len, len;
    struct ScanParam *ss = (struct ScanParam*)arg;

    u8 sendBuf[200];

    struct sockaddr_in destAddr;
    struct PseudoHdr *pPseuH;
    struct udphdr *pUdp;
    pPseuH = (struct PseudoHdr*)sendBuf;
    pUdp = (struct udphdr*)(sendBuf + sizeof(struct PseudoHdr));
//  memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    inet_pton(AF_INET, ss->destIP, &destAddr.sin_addr);
    destAddr.sin_port = htons(ss->destPort);
    udpfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if(udpfd < 0)
    {
        pthread_mutex_lock(&udp_printf_mutex);
        perror("udp socket");
        pthread_mutex_unlock(&udp_printf_mutex);
    }

    inet_pton(AF_INET, ss->destIP, &pPseuH->dIP);
    inet_pton(AF_INET, ss->sourIP, &pPseuH->sIP);
    pPseuH->protocol = IPPROTO_UDP;
    pPseuH->useless = 0;
    pPseuH->length = htons(sizeof(struct udphdr));//!!!
//  pPseuH->length = htons(40);//!!!
    memset(pUdp, 0, sizeof(struct udphdr));
//  memset(pUdp, 0, 60-20);
    pUdp->source = htons(ss->sourPort);
    pUdp->dest = htons(ss->destPort);
    pUdp->len = htons(sizeof(struct udphdr));
    pUdp->check = 0;
    pUdp->check = checksum((u8*)sendBuf, sizeof(struct PseudoHdr)+sizeof(struct udphdr));
//  pUdp->check = checksum((u8*)sendBuf, sizeof(struct PseudoHdr)+40);

    len = sendto(udpfd, (void *)pUdp, sizeof(struct udphdr), 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
    if(len <= 0)
    {
        pthread_mutex_lock(&udp_printf_mutex);
        perror("sendto");
        pthread_mutex_unlock(&udp_printf_mutex);
    }
    free(ss);
    close(udpfd);//!!!
}

void* udpIcmpScanRecv(void *arg)
{
    u8 recvBuf[MAXLINE];
    char recvIP[INET_ADDRSTRLEN];
    int len;
//  struct icmp *pIcmp;//28字节
    struct icmphdr *pIcmp;//8字节
    struct ip *pIp;
    struct udphdr *pUdp;
    struct ScanSock *ss = (struct ScanSock*)arg;
    int udpfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int num_port = ss->portEnd - ss->portStart + 1;
    u16 port_now;
    while(1)
    {
        memset(recvBuf, 0, MAXLINE);
        len = recvfrom(udpfd, recvBuf, MAXLINE, 0, NULL, NULL);
        if(len <= 0)
        {
            if(errno == EINTR)
                    continue;
            pthread_mutex_lock(&udp_printf_mutex);
            perror("recvfrom\n");
            pthread_mutex_unlock(&udp_printf_mutex);
        }
        else
        {
            int i;

            if(len >= sizeof(struct iphdr) + sizeof(struct icmphdr))
            {
                pIcmp = (struct icmphdr*)(recvBuf + sizeof(struct ip));
                if( (pIcmp->type == ICMP_DEST_UNREACH) && (pIcmp->code == ICMP_PORT_UNREACH) )
                {
                    pUdp =  (struct udphdr*)(recvBuf + sizeof(struct ip) + sizeof(struct icmphdr) + sizeof(struct ip));
                    port_now = ntohs(pUdp->dest);
                    if( (ss->portStart <= port_now) && (port_now <= ss->portEnd) )//!!
                    {
                        pthread_mutex_lock(&udp_printf_mutex);
                        printf("port now = %d\t", port_now);
                        if(flag_err >= 1)
                        {
                            for(i = 0 ; i < len ; i++)
                            {
                                printf("%02x ", recvBuf[i]);
                                if( (i+1)%12 == 0)
                                    printf("\n");
                            }
                            printf("\n");
                        }
                        pthread_mutex_unlock(&udp_printf_mutex);

                        pthread_mutex_lock(&udp_printf_mutex);
                        printf("close\n");
                        pthread_mutex_unlock(&udp_printf_mutex);

                        pthread_mutex_lock(&udp_num_mutex);
                        udpCnt--;
                        flag_port[port_now] = 2;
                        pthread_mutex_unlock(&udp_num_mutex);


                    }
                    else
                    {
                        pthread_mutex_lock(&udp_printf_mutex);
                        printf("else \n");
                        pthread_mutex_unlock(&udp_printf_mutex);

                        pthread_mutex_lock(&udp_printf_mutex);
                        for(i = 0 ; i < len ; i++)
                        {
                            printf("%02x ", recvBuf[i]);
                            if( (i+1)%12 == 0)
                                printf("\n");
                        }
                        printf("\n");
                        pthread_mutex_unlock(&udp_printf_mutex);
                    }
                }
            }
        }
    }
}
void* udpIcmpScanPort(void *arg)
{
    int cnt_delay = 0;
    flag_err = 0;
    struct ScanSock *ss = (struct ScanSock*)arg;
    int i;
    struct ScanParam *scanAddr;
    pthread_t pidTh;
    int err;
    pthread_attr_t attr;
    struct sigaction newact, oldact;
    /*pthread_attr_init(&attr);
    err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if(err != 0)
    {
    printf("pthread_attr_setdetachstate:%s\n", strerror(err));
    exit(1);
    }*/
    int recv_th;
    recv_th = pthread_create(&pidTh, NULL, udpIcmpScanRecv, arg);
    if(recv_th != 0)
    {
        printf("pthread_create:%s\n", strerror(recv_th));
        exit(1);
    }
    //  pthread_attr_destroy(&attr);
    memset(flag_port, 0, 65535);
    udpCnt = 0;
resend:
    for(i = ss->portStart ; i <= ss->portEnd ; i++)
    {
        //printf("port:%d\n", i);
        if(flag_port[i] == 0)
        {
//          printf("i = %d\n", i);
            scanAddr = malloc(sizeof(struct ScanSock));
            strncpy(scanAddr->destIP, ss->destIP, INET_ADDRSTRLEN);
            strncpy(scanAddr->sourIP, ss->sourIP, INET_ADDRSTRLEN);
            scanAddr->destPort = i;//!!!
            scanAddr->sourPort = 1024+i;

            pthread_attr_init(&attr);
            err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            if(err != 0)
            {
                printf("pthread_attr_setdetachstate:%s\n", strerror(err));
                exit(1);
            }
            err = pthread_create(&pidTh, &attr, udpIcmpScanEach, (void*)scanAddr);
            if(err != 0)
            {
                printf("pthread_create:%s\n", strerror(err));
                exit(1);
            }
            pthread_attr_destroy(&attr);
            if(flag_err == 0)
            {
                pthread_mutex_lock(&udp_num_mutex);
                udpCnt++;
                flag_port[i] = 0;
                pthread_mutex_unlock(&udp_num_mutex);

            }
            sleep(1);

            newact.sa_handler = alarm_udp;
            sigemptyset(&newact.sa_mask);
            newact.sa_flags = 0;
            sigaction(SIGALRM, &newact, &oldact);
            alarm(30);//在规定30秒内卡死在下面while循环的话，就重新发送UDP包
            flag_alarm = 0;
            while(udpCnt > 50)
            {
                if(flag_alarm != 0)
                    goto resend;
                sleep(3);
            }

            alarm(0);//正常出循环的话，就将定时器关掉。
        }
    }
    alarm(0);
    sigaction(SIGALRM, &oldact, NULL);//恢复alarm原来的行为

    while(udpCnt > 0)//!!!
    {
        sleep(3);
        cnt_delay++;
        if(cnt_delay == 10)
        {
            cnt_delay = 0;
            flag_err++;
            if(flag_err > 3)
            {
                for(i = ss->portStart ; i <= ss->portEnd ; i++)
                {
                    if(flag_port[i] == 0)
                    {
                        struct Queue *p = malloc(sizeof(struct Queue));
                        p->data = i;
                        p->next = NULL;
                        pthread_mutex_lock(&udp_num_mutex);
                        p->next = existPort;
                        existPort = p;
                        pthread_mutex_unlock(&udp_num_mutex);
                    }
                }
                break;
            }

            goto resend;
        }
        pthread_mutex_lock(&udp_printf_mutex);
        printf("cnt_delay = %d\tflag_err = %d\n", cnt_delay, flag_err);
        pthread_mutex_unlock(&udp_printf_mutex);
    }
    pthread_cancel(recv_th);

}
void alarm_udp(int signo)
{
    alarm(0);
    flag_err ++;
    flag_alarm = 1;//设置重发标志
}
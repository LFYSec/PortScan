#include "tcpSynScan.h"
//防火墙不关的话只有open的返回，close的不回应！
//u8 flag_port[65535];
//u8 flag_err;
void* tcpSynScanEach(void *arg)
{
    //printf("tcpSynScanEach\n");
    int synfd;
    uint ip_len, tcp_len, pseu_len, len;
    struct ScanParam *ss = (struct ScanParam*)arg;

    u8 sendBuf[200];

    struct sockaddr_in destAddr;
    struct PseudoHdr *pPseuH;
    struct tcphdr *pTcp;
    pPseuH = (struct PseudoHdr*)sendBuf;
    pTcp = (struct tcphdr*)(sendBuf + sizeof(struct PseudoHdr));
//  memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    inet_pton(AF_INET, ss->destIP, &destAddr.sin_addr);
    destAddr.sin_port = htons(ss->destPort);
    synfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);//原始套接字 tcp协议，这样 接收的都是tcp包
    if(synfd < 0)
    {
        pthread_mutex_lock(&syn_printf_mutex);
        perror("syn socket");
        pthread_mutex_unlock(&syn_printf_mutex);
    }

    inet_pton(AF_INET, ss->destIP, &pPseuH->dIP);
    inet_pton(AF_INET, ss->sourIP, &pPseuH->sIP);
    pPseuH->protocol = IPPROTO_TCP;
    pPseuH->useless = 0;
//  pPseuH->length = htons(sizeof(struct tcphdr));//!!!
    pPseuH->length = htons(40);//!!!
//  memset(pTcp, 0, sizeof(struct tcphdr));
    memset(pTcp, 0, 60-20);
    pTcp->source = htons(ss->sourPort);
    pTcp->dest = htons(ss->destPort);
    pTcp->seq = htonl(123456+ss->destPort);//??
    pTcp->ack_seq = 0;
    pTcp->doff = 10;//!!!长度 windows下不用设置啊，linux不设置不搭理我啊～
//  pTcp->doff = 0;//!!!长度 windows下不用设置啊，linux不设置不搭理我啊～
    pTcp->syn = 1;
    pTcp->ack = 0;
    pTcp->window = htons(65535);//!!!
    pTcp->check = 0;
//  pTcp->check = checksum((u8*)sendBuf, sizeof(struct PseudoHdr)+sizeof(struct tcphdr));
    pTcp->check = checksum((u8*)sendBuf, sizeof(struct PseudoHdr)+40);

    len = sendto(synfd, (void *)pTcp, 40, 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
    if(len <= 0)
    {
        pthread_mutex_lock(&syn_printf_mutex);
        perror("sendto");
        pthread_mutex_unlock(&syn_printf_mutex);
    }
    free(ss);
    close(synfd);//!!!
}

void* tcpSynScanRecv(void *arg)
{
    //printf("tcpSynScanRecv\n");
    u8 recvBuf[MAXLINE];
    char recvIP[INET_ADDRSTRLEN];
    int len;
    struct tcphdr *pTcp;
    struct ip *pIp;
    struct ScanSock *ss = (struct ScanSock*)arg;

    int synfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    int num_port = ss->portEnd - ss->portStart + 1;

    u16 port_now;
    
//  u8 flag_port[65535];
//  memset(flag_port, 0, 65535);
    while(1)//线程自己一直处在不断接收的状态，知道别的线程杀掉它
    {
        
        memset(recvBuf, 0, MAXLINE);
        len = recvfrom(synfd, recvBuf, MAXLINE, 0, NULL, NULL);
        if(len <= 0)
        {
            pthread_mutex_lock(&syn_printf_mutex);
            perror("recvfrom\n");
            pthread_mutex_unlock(&syn_printf_mutex);
        }
        else
        {
            int i;
            if(len >= sizeof(struct iphdr) + sizeof(struct tcphdr))
            {
                pTcp = (struct tcphdr*)(recvBuf + sizeof(struct ip));

                port_now = ntohs(pTcp->source);

                if( (ss->portStart <= port_now) && (port_now <= ss->portEnd) )//!!
                {
                    pthread_mutex_lock(&syn_printf_mutex);
                    printf("port now = %d\t", port_now);
                    // if(flag_err == 1)
                    // {
                    //     for(i = 0 ; i < len ; i++)
                    //     {
                    //         printf("%02x ", recvBuf[i]);
                    //         if( (i+1)%12 == 0)
                    //             printf("\n");
                    //     }
                    //     printf("\n");
                    // }
                    pthread_mutex_unlock(&syn_printf_mutex);

                    if( (pTcp->syn == 1)&&( ntohl(pTcp->ack_seq) == 123456+port_now+1) )//收到ack
                    {
                        pthread_mutex_lock(&syn_printf_mutex);
                        printf("open\n");
                        pthread_mutex_unlock(&syn_printf_mutex);

                        if(flag_port[port_now] == 0)//防止重复记录，所以只对没收到过ack的记录
                        {
                            struct Queue *p = malloc(sizeof(struct Queue));
                            p->data = port_now;
                            p->next = NULL;

                            flag_port[port_now] = 1;
                            pthread_mutex_lock(&syn_num_mutex);
                            synCnt--;
                            p->next = existPort ;
                            existPort = p;
                            pthread_mutex_unlock(&syn_num_mutex);
                        }

                    }
                    else if( pTcp->syn == 0)//收到rst
                    {
                        pthread_mutex_lock(&syn_printf_mutex);
                        printf("close\n");
                        pthread_mutex_unlock(&syn_printf_mutex);


                            pthread_mutex_lock(&syn_num_mutex);
                            synCnt--;
                            flag_port[port_now] = 2;
                            pthread_mutex_unlock(&syn_num_mutex);

                    }
                    else
                    {
                        pthread_mutex_lock(&syn_printf_mutex);
                        printf("!!!3\n");
                        pthread_mutex_unlock(&syn_printf_mutex);


                        pthread_mutex_lock(&syn_printf_mutex);
                        for(i = 0 ; i < len ; i++)
                        {
                            printf("%02x ", recvBuf[i]);
                            if( (i+1)%12 == 0)
                                printf("\n");
                        }
                        printf("\n");
                        pthread_mutex_unlock(&syn_printf_mutex);
                    }
                }
            }
        }
    }
    //printf("tcpSynScanRecv\n");
}
void* tcpSynScanPort(void *arg)
{
    //printf("tcpSynScanPort\n");
    int cnt_delay = 0;
    flag_err = 0;
    struct ScanSock *ss = (struct ScanSock*)arg;
    int i;
    struct ScanParam *scanAddr;
    pthread_t pidTh;
    int err;
    pthread_attr_t attr;

    /*pthread_attr_init(&attr);
    err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if(err != 0)
    {
    printf("pthread_attr_setdetachstate:%s\n", strerror(err));
    exit(1);
    }*/
    int recv_th;
    //printf("tcpSynScanPort\n");
    recv_th = pthread_create(&pidTh, NULL, tcpSynScanRecv, arg);
    //printf("tcpSynScanPort\n");
    if(recv_th != 0)
    {
        printf("pthread_create:%s\n", strerror(recv_th));
        exit(1);
    }
    //printf("tcpSynScanPort\n");
    //  pthread_attr_destroy(&attr);
    memset(flag_port, 0, 65535);
    synCnt = 0;
resend:
    for(i = ss->portStart ; i <= ss->portEnd ; i++)
    {
        //printf("tcpSynScanPort\n");
        if(flag_port[i] == 0)//只对还没收到应答的包发送SYN帧
        {
            //printf("tcpSynScanPort6\n");
            scanAddr = malloc(sizeof(struct ScanParam));
            //printf("tcpSynScanPort7\n");
            strncpy(scanAddr->destIP, ss->destIP, INET_ADDRSTRLEN);
            //printf("tcpSynScanPort8\n");
            strncpy(scanAddr->sourIP, ss->sourIP, INET_ADDRSTRLEN);
            //printf("tcpSynScanPort9\n");
            scanAddr->destPort = i;//!!!
            scanAddr->sourPort = 1024+i;

            pthread_attr_init(&attr);
            err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            if(err != 0)
            {
                printf("pthread_attr_setdetachstate:%s\n", strerror(err));
                exit(1);
            }
            err = pthread_create(&pidTh, &attr, tcpSynScanEach, (void*)scanAddr);
            if(err != 0)
            {
                printf("pthread_create:%s\n", strerror(err));
                exit(1);
            }
            pthread_attr_destroy(&attr);
            if(flag_err == 0)
            {
                pthread_mutex_lock(&syn_num_mutex);
                synCnt++;
                flag_port[i] = 0;
                pthread_mutex_unlock(&syn_num_mutex);

            }
            while(synCnt > 100)
                sleep(3);
        }
    }
    while(synCnt > 0)//!!!
    {
        sleep(1);
        cnt_delay++;
        if(cnt_delay == 10)//很久没归零，则判断丢包的可能性较大
        {
            cnt_delay == 0;
            flag_err = 1;
            goto resend;//回到发送那一步，对丢包的再次发送SYN包
        }
        // pthread_mutex_lock(&syn_printf_mutex);
        // printf("\tsynCnt = %d\n", synCnt);
        // printf("---now exist port:\n");
        // struct Queue *tempQ = existPort;
        // while(tempQ != NULL)
        // {
        //     printf("%d\t",tempQ->data);
        //     tempQ = tempQ->next;
        // }
        // printf("\n");

        // pthread_mutex_unlock(&syn_printf_mutex);

    }//出循环说明已对每个端口状态做了判断
    pthread_cancel(recv_th);//杀掉接收线程
    //printf("tcpSynScanPort\n");

}
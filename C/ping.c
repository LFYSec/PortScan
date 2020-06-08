#include "ping.h"


int ping(char *strIp)
{
    u8 sendBuf[MAXLINE];
    u8 recvBuf[MAXLINE];
    struct sockaddr_in destAddr;
    int sockfd;
    if( (sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("socket");
        exit(1);
    }
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    if( inet_pton( AF_INET, strIp, &(destAddr.sin_addr)) != 1)
    {
        perror("inet_pton:");
        exit(1);
    }

    struct sigaction newact, oldact;
    newact.sa_handler = alarm_timer;
    sigemptyset(&newact.sa_mask);
    newact.sa_flags = 0;
    sigaction(SIGALRM, &newact, &oldact);
    alarm(30);

    struct icmp *pIcmp;
    struct ip *pIp;
    int seq = 0;
    struct timeval *tvStart, *tvEnd;
    pid_t pid = getpid();
    pingFlag = 0;
    while(pingFlag == 0)
    {
        memset(sendBuf, 0, MAXLINE);
        pIcmp = (struct icmp*)sendBuf;
        pIcmp->icmp_type = ICMP_ECHO;
        pIcmp->icmp_code = 0;
        pIcmp->icmp_cksum = 0;
        pIcmp->icmp_id = pid;
        pIcmp->icmp_seq = seq++;
        tvStart = (struct timeval* )pIcmp->icmp_data;
        gettimeofday(tvStart, NULL);
        pIcmp->icmp_cksum = checksum( (u8 *)pIcmp, PINGDATA+8);

        sendto(sockfd, sendBuf, PINGDATA+8, 0, (struct sockaddr* )&destAddr, sizeof(destAddr));

        uint lenIphd, lenIcmp;
        u16 sumRecv, sumCal;
        double deltSec;
        char ipSource[INET_ADDRSTRLEN];
        int n;
        memset(recvBuf, 0, MAXLINE);
        n = recvfrom(sockfd, recvBuf, MAXLINE, 0, NULL, NULL);
        if(n < 0)
        {
            if(errno == EINTR)
                continue;
            else
            {
                perror("recvfrom");
                exit(1);
            }
        }
        if( (tvEnd = malloc(sizeof(struct timeval))) < 0)
        {
            perror("malloc tvEnd:");
            exit(1);
        }
        gettimeofday(tvEnd, NULL);
        pIp = (struct ip*)recvBuf;
        lenIphd = (pIp->ip_hl)*4;
        lenIcmp = ntohs(pIp->ip_len)-lenIphd;//icmp字段长度
        pIcmp = (struct icmp*)( (u8*)pIp + lenIphd);//必须强制转换！
        sumRecv = pIcmp->icmp_cksum;
        pIcmp->icmp_cksum = 0;
        sumCal = checksum( (u8*)pIcmp, lenIcmp);
        if(sumCal != sumRecv)
        {
            printf("checksum error\tsum_recv = %d\tsum_cal = %d\n",sumRecv, sumCal);
        }
        else
        {
            switch(pIcmp->icmp_type)
            {
                case ICMP_ECHOREPLY:
                    {
                        pid_t pidNow, pidRev;
                        pidRev = (pIcmp->icmp_id);
                        pidNow = getpid();
                        if(pidRev != pidNow )
                        {
                            printf("pid not match!pin_now = %d, pin_rev = %d\n", pidNow, pidRev);
                        }
                        else
                        {
                            pingFlag = 1;
                        }
                        inet_ntop(AF_INET, (void*)&(pIp->ip_src), ipSource, INET_ADDRSTRLEN);
                        tvStart = (struct timeval*)pIcmp->icmp_data;
                        deltSec = (tvEnd->tv_sec - tvStart->tv_sec) + (tvEnd->tv_usec - tvStart->tv_usec)/1000000.0;
                        printf("%d bytes from %s: icmp_req=%d ttl=%d time=%4.2f ms\n", lenIcmp, ipSource, pIcmp->icmp_seq, pIp->ip_ttl, deltSec*1000);//想用整型打印的话必须强制转换！
                        break;
                    }
                case ICMP_TIME_EXCEEDED:
                    {
                        printf("time out!\n");
                        pingFlag = -1;
                        break;
                    }
                case ICMP_DEST_UNREACH:
                    {
                        inet_ntop(AF_INET, (void*)&(pIp->ip_src), ipSource, INET_ADDRSTRLEN);
                        printf("From %s icmp_seq=%d Destination Host Unreachable\n", ipSource, pIcmp->icmp_seq);
                        pingFlag = -1;
                        break;
                    }
                default:
                    {
                        printf("recv error!\n");
                        pingFlag = -1;
                        break;
                    }
            }
        }

    }
    alarm(0);
    sigaction(SIGALRM, &oldact, NULL);
    return pingFlag;
}
unsigned short checksum(unsigned char*buf, unsigned int len)//对每16位进行反码求和（高位溢出位会加到低位），即先对每16位求和，在将得到的和转为反码
{
    unsigned long sum = 0;
    unsigned short *pbuf;
    pbuf = (unsigned short*)buf;//转化成指向16位的指针
    while(len > 1)//求和
    {
        sum+=*pbuf++;
        len-=2;
    }
    if(len)//如果len为奇数，则最后剩一位要求和
        sum += *(unsigned char*)pbuf;
    sum = (sum>>16)+(sum & 0xffff);//
    sum += (sum>>16);//上一步可能产生溢出
    return (unsigned short)(~sum);
}
void getMyIp(char *sourIP)
{
    FILE *ipFd;
    ipFd = popen("/sbin/ifconfig|grep 'inet '|grep -v 127|awk -F ':' '{print $2}'|cut -d ' ' -f1", "r");
    if(ipFd == NULL)
    {
        perror("popen");
        exit(0);
    }
    fscanf(ipFd, "%20s", sourIP);
//  fscanf(ipFd, "%INET_ADDRSTRLENs", sourIP);
}
void alarm_timer(int signo)
{
    pingFlag = -1;
    alarm(0);
}
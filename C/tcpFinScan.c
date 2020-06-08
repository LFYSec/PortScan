#include "tcpFinScan.h"

void* tcpFinScanEach(void *arg)
{
	int finfd;
	uint ip_len, tcp_len, pseu_len, len;
	struct ScanParam *ss = (struct ScanParam*)arg;
 
	u8 sendBuf[200];
 
	struct sockaddr_in destAddr;
	struct PseudoHdr *pPseuH;
	struct tcphdr *pTcp;
	pPseuH = (struct PseudoHdr*)sendBuf;
	pTcp = (struct tcphdr*)(sendBuf + sizeof(struct PseudoHdr));
	destAddr.sin_family = AF_INET;
	inet_pton(AF_INET, ss->destIP, &destAddr.sin_addr);
	destAddr.sin_port = htons(ss->destPort);
	finfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(finfd < 0)
	{
		pthread_mutex_lock(&fin_printf_mutex);
		perror("fin socket");
		pthread_mutex_unlock(&fin_printf_mutex);
	}

	inet_pton(AF_INET, ss->destIP, &pPseuH->dIP);
	inet_pton(AF_INET, ss->sourIP, &pPseuH->sIP);
	pPseuH->protocol = IPPROTO_TCP;
	pPseuH->useless = 0;
	pPseuH->length = htons(40);//!!!
	memset(pTcp, 0, 60-20);
	pTcp->source = htons(ss->sourPort);
	pTcp->dest = htons(ss->destPort);
	pTcp->seq = htonl(123456+ss->destPort);//??
	pTcp->ack_seq = 0;
	pTcp->doff = 10;
	pTcp->syn = 1;
	pTcp->ack = 0;
	pTcp->window = htons(65535);//!!!
	pTcp->check = 0;
	pTcp->check = checksum((u8*)sendBuf, sizeof(struct PseudoHdr)+40);
 
	len = sendto(finfd, (void *)pTcp, 40, 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
	if(len <= 0)
	{
		pthread_mutex_lock(&fin_printf_mutex);
		perror("sendto");
		pthread_mutex_unlock(&fin_printf_mutex);
	}
	free(ss);
	close(finfd);//!!!
}
 
void* tcpFinScanRecv(void *arg)
{
	u8 recvBuf[MAXLINE];
	char recvIP[INET_ADDRSTRLEN];
	int len;
	struct tcphdr *pTcp;
	struct ip *pIp;
	struct ScanSock *ss = (struct ScanSock*)arg;
	
	int finfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	
	int num_port = ss->portEnd - ss->portStart + 1;
 
	u16 port_now;
	while(1)
	{
		memset(recvBuf, 0, MAXLINE);
		len = recvfrom(finfd, recvBuf, MAXLINE, 0, NULL, NULL);
		if(len <= 0)
		{
			pthread_mutex_lock(&fin_printf_mutex);
			perror("recvfrom\n");
			pthread_mutex_unlock(&fin_printf_mutex);
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
                    //printf("ack:%d, rst:%d, syn:%d   ",pTcp->ack, pTcp->rst, pTcp->syn);
					pthread_mutex_lock(&fin_printf_mutex);
					printf("port now = %d\t", port_now);
					// if(flag_err >= 1)
					// {
					// 	for(i = 0 ; i < len ; i++)
					// 	{
					// 		printf("%02x ", recvBuf[i]);
					// 		if( (i+1)%12 == 0)
					// 			printf("\n");
					// 	}
					// 	printf("\n");
					// }
					pthread_mutex_unlock(&fin_printf_mutex);
 
					if( (pTcp->ack == 1)&&( ntohl(pTcp->ack_seq) == 123456+port_now+1) && (pTcp->rst == 1) )
					{
						pthread_mutex_lock(&fin_printf_mutex);
						printf("close\n");
						pthread_mutex_unlock(&fin_printf_mutex);
 
						flag_port[port_now] = 2;
						pthread_mutex_lock(&fin_num_mutex);
						finCnt--;
						pthread_mutex_unlock(&fin_num_mutex);
 
					}
					else
					{
						// pthread_mutex_lock(&fin_printf_mutex);
						// printf("!!!3\n");
						// pthread_mutex_unlock(&fin_printf_mutex);
 
						// pthread_mutex_lock(&fin_printf_mutex);
						// for(i = 0 ; i < len ; i++)
						// {
						// 	printf("%02x ", recvBuf[i]);
						// 	if( (i+1)%12 == 0)
						// 		printf("\n");
						// }
						// printf("\n");
						// pthread_mutex_unlock(&fin_printf_mutex);
                        pthread_mutex_lock(&fin_printf_mutex);
						printf("open\n");
						pthread_mutex_unlock(&fin_printf_mutex);
					}
				}
			}
		}
	}
}
void* tcpFinScanPort(void *arg)
{
	int cnt_delay = 0; 
	flag_err = 0;
	struct ScanSock *ss = (struct ScanSock*)arg;
	int i;
	struct ScanParam *scanAddr;
	pthread_t pidTh;
	int err;
	pthread_attr_t attr;
	int recv_th;
	recv_th = pthread_create(&pidTh, NULL, tcpFinScanRecv, arg);
	if(recv_th != 0)
	{
		printf("pthread_create:%s\n", strerror(recv_th));
		exit(1);
	}
	memset(flag_port, 0, 65535);	
	finCnt = 0;
resend:
	for(i = ss->portStart ; i <= ss->portEnd ; i++)
	{
		if(flag_port[i] == 0)
		{
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
			err = pthread_create(&pidTh, &attr, tcpFinScanEach, (void*)scanAddr);
			if(err != 0)
			{
				printf("pthread_create:%s\n", strerror(err));
				exit(1);
			}
			pthread_attr_destroy(&attr);
			if(flag_err == 0)
			{
				pthread_mutex_lock(&fin_num_mutex);
				finCnt++;
				flag_port[i] = 0;
				pthread_mutex_unlock(&fin_num_mutex);
 
			}
			while(finCnt > 100)
				sleep(3);
		}
	}
	while(finCnt > 0)//!!!
	{
		sleep(1);
		cnt_delay++;
		if(cnt_delay == 2)
		{
			cnt_delay = 0;
			flag_err++;
			if(flag_err > 1)
			{
				for(i = ss->portStart ; i <= ss->portEnd ; i++)
				{
					if(flag_port[i] == 0)
					{
						struct Queue *p = malloc(sizeof(struct Queue));
						p->data = i;
						p->next = NULL;
						pthread_mutex_lock(&fin_num_mutex);
						p->next = existPort;
						existPort = p;
						pthread_mutex_unlock(&fin_num_mutex);
					}
				}
				break;
			}
 
			goto resend;
		}
		// pthread_mutex_lock(&fin_printf_mutex);
		// printf("cnt_delay = %d\tflag_err = %d\n", cnt_delay, flag_err);
		// pthread_mutex_unlock(&fin_printf_mutex);
	}
	pthread_cancel(recv_th);
 
}
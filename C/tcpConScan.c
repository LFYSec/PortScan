#include "tcpConScan.h"
//pthread_mutex_t connect_printf_mutex = PTHREAD_MUTEX_INITIALIZER;
//pthread_mutex_t connect_num_mutex = PTHREAD_MUTEX_INITIALIZER;

void* tcpConScanEach(void *arg)
{
    int connectFd;
    struct sockaddr_in *destAddr = (struct sockaddr_in*)arg;
    connectFd = socket(AF_INET, SOCK_STREAM, 0);
    u16 portNow = ntohs(destAddr->sin_port);
    if(connectFd < 0)
    {
        perror("connect socket");
        exit(1);
    }
    if( connect(connectFd, (struct sockaddr*)destAddr, sizeof(struct sockaddr_in)) < 0)
    {
        pthread_mutex_lock(&connect_printf_mutex);
        printf("port\t%d\t is  closed.\n", portNow );//
        pthread_mutex_unlock(&connect_printf_mutex);

    }
    else
    {
        struct Queue *p = malloc(sizeof(struct Queue));
        p->data = portNow;
        p->next = NULL;
        pthread_mutex_lock(&connect_printf_mutex);
        printf("port\t%d\t is opened.\n", portNow );
        p->next = existPort;
        existPort = p;
        pthread_mutex_unlock(&connect_printf_mutex);
    }
    free(destAddr);//别忘了释放空间
    pthread_mutex_lock(&connect_num_mutex);
    connectCnt--;
    pthread_mutex_unlock(&connect_num_mutex);
    close(connectFd);
}

void* tcpConScanPort(void *arg)
{

    int i;
    struct ScanSock *ss = (struct ScanSock *)arg;
    struct sockaddr_in *destAddr;
    pthread_t pidTh;
    int err;
    pthread_attr_t attr;

    existPort = NULL;
    connectCnt = 0;
    for(i = ss->portStart ; i <= ss->portEnd ; i++)//为每个端口创建线程
    {
        destAddr = malloc( sizeof(struct sockaddr_in));
        destAddr->sin_family = AF_INET;
        inet_pton(AF_INET, ss->destIP, &destAddr->sin_addr);

        destAddr->sin_port = htons(i);

        pthread_attr_init(&attr);//子线程设置成可分离的
        err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if(err != 0)
        {
            printf("pthread_attr_setdetachstate:%s\n", strerror(err));
            exit(1);
        }
        err = pthread_create(&pidTh, &attr, tcpConScanEach, (void*)destAddr);//创建子线程
        if(err != 0)
        {
            printf("pthread_create:%s\n", strerror(err));
            exit(1);
        }
        pthread_attr_destroy(&attr);
        pthread_mutex_lock(&connect_num_mutex);//线程安全方式计数
        connectCnt++;
        pthread_mutex_unlock(&connect_num_mutex);
        while(connectCnt > 100)//如果线程池中线程太多
            sleep(3);
    }
    while(connectCnt > 0)//等待connectCnt为0则扫描结束
    {
        sleep(1);
    }

    // printf("---exit port:\n");//打印
    // struct Queue *tempQ;
    // while(existPort != NULL)
    // {
    //     printf("%d\n",existPort->data);
    //     tempQ = existPort;
    //     existPort = existPort->next;
    //     free(tempQ);
    // }
}
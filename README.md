# PortScan

## Introduction
本科各种水课课设皆可用的端口扫描器2333

NWPU网络攻防课课设，用Go和C两种语言分别实现了TCP、SYN、FIN、UDP的端口扫描，C的实现参考了Github的一些项目。

Go使用了协程实现基本的生产者消费者模型，C使用多线程，速度都还可以。

## Usage

### GO
go run portscan.go -r 127.0.0.1 -w SYN -p 1-1024

### C
队友写的，自己看代码吧
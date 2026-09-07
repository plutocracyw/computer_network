#ifndef _GLOBAL_H_
#define _GLOBAL_H_
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "global.h"
#include <pthread.h>
#include <sys/select.h>
#include <arpa/inet.h>

// 单位是byte
#define SIZE32 4
#define SIZE16 2
#define SIZE8 1

// 一些Flag
#define NO_FLAG 0
#define NO_WAIT 1
#define TIMEOUT 2
#define TRUE 1
#define FALSE 0

// 定义最大包长 防止IP层分片
#define MAX_DLEN 1375 // 历史遗留常量，仅用于接收窗口容量估算，不用于发送分段
#define MAX_LEN 1400  // 最大包长度（20B报头+数据）

/* ===== 第二阶段：分段与缓冲区容量（指导书要求缓冲 ≥5000×SMSS）===== */
#define SMSS (MAX_LEN - 20)		   // 发送最大段长 = 1400-20 = 1380
#define SEND_BUF_CAP (5000 * SMSS) // 发送缓冲区容量（字节）
#define RECV_BUF_CAP (5000 * SMSS) // 接收缓冲区容量（字节）

/* RTT/RTO 相关，单位毫秒（RFC6298；最终取值以《说明书v2》为准）*/
#define RTO_INIT_MS 1000 // 数据阶段初始 RTO = 1s
#define RTO_MIN_MS 200	 // RTO 下限（教学取值）
#define RTO_MAX_MS 3000	 // RTO 上限；SYN 重传后数据阶段重置为 3s
#define MAX_RXT 12		 // 单个报文最大重传次数（教学取值）

/* TIME_WAIT 等待 2×TJU_MSL*/
#define TJU_MSL_MS 1000

// TCP socket 状态定义
#define CLOSED 0
#define LISTEN 1
#define SYN_SENT 2
#define SYN_RECV 3
#define ESTABLISHED 4
#define FIN_WAIT_1 5
#define FIN_WAIT_2 6
#define CLOSE_WAIT 7
#define CLOSING 8
#define LAST_ACK 9
#define TIME_WAIT 10

// TCP 拥塞控制状态
#define SLOW_START 0
#define CONGESTION_AVOIDANCE 1
#define FAST_RECOVERY 2

// TCP 接受窗口大小
#define TCP_RECVWN_SIZE 32 * MAX_DLEN // 比如最多放32个满载数据包

// TCP 发送窗口
typedef struct
{
	uint16_t window_size;	  // 保留：本端通告窗口
	uint32_t base;			  // SND.UNA：最早已发未确认序号
	uint32_t nextseq;		  // SND.NXT：下一个待发序号
	uint32_t rwnd;			  // 接收方通告窗口（流量控制）
	uint32_t cwnd;			  // 拥塞窗口（第二阶段置大上限，第三阶段Reno）
	uint32_t ssthresh;		  // 慢启动门限
	uint32_t srtt;			  // 平滑 RTT（毫秒）
	uint32_t rttvar;		  // RTT 偏差（毫秒）
	uint32_t rto;			  // 当前重传超时（毫秒）
	uint8_t rtt_ready;		  // 是否已取得首个 RTT 样本
	int dupack;				  // 重复 ACK 计数（达 3 触发快速重传）
	struct timeval send_time; // 最早未确认报文的发送时刻
} sender_window_t;

// TCP 接受窗口（第二阶段启用期望序号）
typedef struct
{
	char received[TCP_RECVWN_SIZE];
	uint32_t expect_seq; // RCV.NXT：下一个期望收到的字节序号
	uint32_t adv_window; // 即将通告给对方的可用接收窗口
} receiver_window_t;

// TCP 窗口 每个建立了连接的TCP都包括发送和接受两个窗口
typedef struct
{
	sender_window_t *wnd_send;
	receiver_window_t *wnd_recv;
} window_t;

typedef struct
{
	uint32_t ip;
	uint16_t port;
} tju_sock_addr;

// TJU_TCP 结构体 保存TJU_TCP用到的各种数据
typedef struct
{
	int state;							   // TCP的状态
	tju_sock_addr bind_addr;			   // 存放bind和listen时该socket绑定的IP和端口
	tju_sock_addr established_local_addr;  // 存放建立连接后 本机的 IP和端口
	tju_sock_addr established_remote_addr; // 存放建立连接后 连接对方的 IP和端口
	pthread_mutex_t send_lock;			   // 发送数据锁
	char *sending_buf;					   // 发送数据缓存区
	int sending_len;					   // 发送数据缓存长度
	pthread_mutex_t recv_lock;			   // 接收数据锁
	char *received_buf;					   // 接收数据缓存区
	int received_len;					   // 接收数据缓存长度
	pthread_cond_t wait_cond;			   // 可以被用来唤醒recv函数调用时等待的线程
	window_t window;					   // 发送和接受两个窗口
	/* ===== 第二阶段新增 ===== */
	uint32_t iss;				// 本端初始序号 ISN
	pthread_t timer_thread;		// 每连接一个的重传定时器线程
	uint8_t timer_on;			// 定时器是否正在运行
	pthread_mutex_t timer_lock; // 保护定时器/RTO 的锁
	pthread_cond_t timer_cond;	// 定时器等待与提前唤醒
} tju_tcp_t;

#endif
#include "tju_tcp.h"
/* ===================== M1：报文发送与序号工具（内部使用）===================== */

/* 生成单调递增、不易预测的初始序号 ISN（经典做法：时钟每 4 微秒递增 1）*/
static uint32_t gen_iss(void)
{
    static uint32_t last_isn = 0;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t isn = (uint32_t)(((uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec) / 4);
    if (isn <= last_isn)
        isn = last_isn + 1; // 保证同一进程内严格单调递增
    last_isn = isn;
    return isn;
}

/* 发送报文的统一出口：组装 20B 报头(+数据)并交给仿真内核，发送完释放缓冲区 */
static int send_packet(tju_tcp_t *sock, char *data, uint16_t dlen,
                       uint8_t flags, uint32_t seq, uint32_t ack)
{
    uint16_t plen = DEFAULT_HEADER_LEN + dlen;
    uint16_t adv = sock->window.wnd_recv ? (uint16_t)sock->window.wnd_recv->adv_window
                                         : (uint16_t)TCP_RECVWN_SIZE;
    char *out = create_packet_buf(
        sock->established_local_addr.port,
        sock->established_remote_addr.port,
        seq, ack,
        DEFAULT_HEADER_LEN, plen, flags, adv, 0,
        data, (int)dlen);
    sendToLayer3(out, plen);
    free(out); // create_packet_buf 内部 calloc，基线没释放会泄漏，这里统一回收
    return 0;
}

/* 释放一个 TCP 连接的全部资源：从表中移除、释放缓冲/窗口、销毁锁、free */
static void free_tcp(tju_tcp_t *sock)
{
    // 从 established 表移除
    int h = cal_hash(sock->established_local_addr.ip, sock->established_local_addr.port,
                     sock->established_remote_addr.ip, sock->established_remote_addr.port);
    if (established_socks[h] == sock)
        established_socks[h] = NULL;
    // 释放字节流缓冲
    free(sock->sending_buf);
    free(sock->received_buf);
    // 释放窗口
    free(sock->window.wnd_send);
    free(sock->window.wnd_recv);
    // 销毁同步原语
    pthread_mutex_destroy(&(sock->send_lock));
    pthread_mutex_destroy(&(sock->recv_lock));
    pthread_mutex_destroy(&(sock->timer_lock));
    pthread_cond_destroy(&(sock->wait_cond));
    pthread_cond_destroy(&(sock->timer_cond));
    free(sock);
}

/* 发送一个纯 ACK：seq=SND.NXT，ack=RCV.NXT（期望序号）*/
static void send_ack(tju_tcp_t *sock)
{
    uint32_t seq = sock->window.wnd_send->nextseq;
    uint32_t ack = sock->window.wnd_recv->expect_seq;
    send_packet(sock, NULL, 0, ACK_FLAG_MASK, seq, ack);
}

/* 已完成三次握手、等待 tju_accept 取走的连接*/
static tju_tcp_t *g_accept_queue = NULL;
static pthread_mutex_t g_accept_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_accept_cond = PTHREAD_COND_INITIALIZER;

/*
创建 TCP socket 
初始化对应的结构体
设置初始状态为 CLOSED
*/
tju_tcp_t *tju_socket()
{
    // 整体清零，保证所有数值/指针字段有确定的 0 初值，避免野值
    tju_tcp_t *sock = (tju_tcp_t *)malloc(sizeof(tju_tcp_t));
    if (sock == NULL)
    {
        perror("ERROR malloc tju_tcp_t\n");
        exit(-1);
    }
    memset(sock, 0, sizeof(tju_tcp_t));
    sock->state = CLOSED;

    // 发送/接收字节流缓冲（真正的数据在 M3 按需 malloc，这里先置空）
    sock->sending_buf = NULL;
    sock->sending_len = 0;
    sock->received_buf = NULL;
    sock->received_len = 0;

    // 三把互斥锁
    pthread_mutex_init(&(sock->send_lock), NULL);
    pthread_mutex_init(&(sock->recv_lock), NULL);
    pthread_mutex_init(&(sock->timer_lock), NULL);
    // 两个条件变量：wait_cond 唤醒阻塞的 recv/accept/connect，timer_cond 供重传定时器等待
    if (pthread_cond_init(&(sock->wait_cond), NULL) != 0 ||
        pthread_cond_init(&(sock->timer_cond), NULL) != 0)
    {
        perror("ERROR condition variable not set\n");
        exit(-1);
    }

    // ---- 分配并初始化发送窗口 ----
    sock->window.wnd_send = (sender_window_t *)malloc(sizeof(sender_window_t));
    if (sock->window.wnd_send == NULL)
    {
        perror("malloc wnd_send");
        exit(-1);
    }
    memset(sock->window.wnd_send, 0, sizeof(sender_window_t));
    sender_window_t *sw = sock->window.wnd_send;
    sw->base = 0;               // SND.UNA
    sw->nextseq = 0;            // SND.NXT
    sw->rwnd = TCP_RECVWN_SIZE; // 尚不知对方窗口，先给宽松初值，握手时用通告窗口更新
    sw->cwnd = SEND_BUF_CAP;    // 第二阶段不做拥塞控制：cwnd 置大上限，使窗口实际只受 rwnd 约束
    sw->ssthresh = SEND_BUF_CAP;
    sw->window_size = TCP_RECVWN_SIZE;
    sw->srtt = 0;
    sw->rttvar = 0;
    sw->rto = RTO_INIT_MS; // RFC6298 初始 RTO=1s
    sw->rtt_ready = 0;
    sw->dupack = 0;
    memset(&(sw->send_time), 0, sizeof(struct timeval));

    // ---- 分配并初始化接收窗口 ----
    sock->window.wnd_recv = (receiver_window_t *)malloc(sizeof(receiver_window_t));
    if (sock->window.wnd_recv == NULL)
    {
        perror("malloc wnd_recv");
        exit(-1);
    }
    memset(sock->window.wnd_recv, 0, sizeof(receiver_window_t));
    sock->window.wnd_recv->expect_seq = 0; // RCV.NXT
    sock->window.wnd_recv->adv_window = TCP_RECVWN_SIZE;

    // ---- 定时器与初始序号（定时器线程 M5 才启动；ISN 在 M1 握手时生成）----
    sock->timer_on = 0;
    sock->timer_thread = 0;
    sock->iss = 0;

    return sock;
}

/*
绑定监听的地址 包括ip和端口
*/
int tju_bind(tju_tcp_t* sock, tju_sock_addr bind_addr){
    sock->bind_addr = bind_addr;
    return 0;
}

/*
被动打开 监听bind的地址和端口
设置socket的状态为LISTEN
注册该socket到内核的监听socket哈希表
*/
int tju_listen(tju_tcp_t* sock){
    sock->state = LISTEN;
    int hashval = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
    listen_socks[hashval] = sock;
    return 0;
}

/*
接受连接 
返回与客户端通信用的socket
这里返回的socket一定是已经完成3次握手建立了连接的socket
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
tju_tcp_t *tju_accept(tju_tcp_t *listen_sock)
{
    (void)listen_sock; // 教学单连接场景用全局队列；多连接需每 listen socket 独立队列
    // 阻塞等待，直到 handle_ack 把握手完成的连接放入队列
    pthread_mutex_lock(&g_accept_lock);
    while (g_accept_queue == NULL)
    {
        pthread_cond_wait(&g_accept_cond, &g_accept_lock);
    }
    tju_tcp_t *new_conn = g_accept_queue;
    g_accept_queue = NULL;
    pthread_mutex_unlock(&g_accept_lock);
#ifdef DEBUG
    printf("[accept] return new_conn state=%d\n", new_conn->state);
#endif
    return new_conn;
}

/*
连接到服务端
该函数以一个socket为参数
调用函数前, 该socket还未建立连接
函数正常返回后, 该socket一定是已经完成了3次握手, 建立了连接
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
int tju_connect(tju_tcp_t *sock, tju_sock_addr target_addr)
{
    // 1) 记录四元组：本端固定 CLIENT_IP:5678，对端为目标地址
    tju_sock_addr local_addr;
    local_addr.ip = inet_network(CLIENT_IP);
    local_addr.port = 5678;
    sock->established_local_addr = local_addr;
    sock->established_remote_addr = target_addr;

    // 2) 生成 ISN；SYN 占用一个序号，故 nextseq = iss+1
    sock->iss = gen_iss();
    sock->window.wnd_send->base = sock->iss;
    sock->window.wnd_send->nextseq = sock->iss + 1;

    // 3) 关键：先按四元组把本 socket 注册进 established 表。
    //    否则对端回来的 SYN+ACK 到达时 onTCPPocket 查不到 socket，会被直接丢弃
    int hashval = cal_hash(local_addr.ip, local_addr.port,
                           target_addr.ip, target_addr.port);
    established_socks[hashval] = sock;

    // 4) 进入 SYN_SENT，发送 SYN（无数据，ack 字段填 0）
    sock->state = SYN_SENT;
    send_packet(sock, NULL, 0, SYN_FLAG_MASK, sock->iss, 0);
#ifdef DEBUG
    printf("[connect] send SYN iss=%u -> SYN_SENT\n", sock->iss);
#endif

    // 5) 阻塞等待，直到接收线程在 handle_syn 中把状态推进到 ESTABLISHED 并唤醒
    pthread_mutex_lock(&(sock->recv_lock));
    while (sock->state != ESTABLISHED)
    {
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
    }
    pthread_mutex_unlock(&(sock->recv_lock));
#ifdef DEBUG
    printf("[connect] handshake done -> ESTABLISHED\n");
#endif
    return 0;
}

int tju_send(tju_tcp_t* sock, const void *buffer, int len){
    // 这里当然不能直接简单地调用sendToLayer3
    char* data = malloc(len);
    memcpy(data, buffer, len);

    char* msg;
    uint32_t seq = 464;
    uint16_t plen = DEFAULT_HEADER_LEN + len;

    msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, 0, 
              DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, data, len);

    sendToLayer3(msg, plen);
    
    return 0;
}
int tju_recv(tju_tcp_t* sock, void *buffer, int len){
    while(sock->received_len<=0){
        // 阻塞
    }

    while(pthread_mutex_lock(&(sock->recv_lock)) != 0); // 加锁

    int read_len = 0;
    if (sock->received_len >= len){ // 从中读取len长度的数据
        read_len = len;
    }else{
        read_len = sock->received_len; // 读取sock->received_len长度的数据(全读出来)
    }

    memcpy(buffer, sock->received_buf, read_len);

    if(read_len < sock->received_len) { // 还剩下一些
        char* new_buf = malloc(sock->received_len - read_len);
        memcpy(new_buf, sock->received_buf + read_len, sock->received_len - read_len);
        free(sock->received_buf);
        sock->received_len -= read_len;
        sock->received_buf = new_buf;
    }else{
        free(sock->received_buf);
        sock->received_buf = NULL;
        sock->received_len = 0;
    }
    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁

    return 0;
}

//第二阶段：报文内部分发

static void handle_syn(tju_tcp_t *sock, char *pkt)
{
    uint32_t seq = get_seq(pkt);
    uint32_t ack = get_ack(pkt);

    /* ---- 客户端：SYN_SENT 收到服务端的 SYN+ACK ---- */
    if (sock->state == SYN_SENT)
    {
        sock->window.wnd_recv->expect_seq = seq + 1; // 对端 SYN 占一个序号
        sock->window.wnd_send->base = ack;           // 确认了我方 SYN
        send_ack(sock);                              // 发第三段 ACK
        pthread_mutex_lock(&(sock->recv_lock));
        sock->state = ESTABLISHED;
        pthread_cond_signal(&(sock->wait_cond)); // 唤醒阻塞的 tju_connect
        pthread_mutex_unlock(&(sock->recv_lock));
#ifdef DEBUG
        printf("[client] recv SYN+ACK(seq=%u,ack=%u) -> ACK, ESTABLISHED\n", seq, ack);
#endif
        return;
    }

    /* ---- 服务端：LISTEN 收到客户端 SYN ---- */
    if (sock->state == LISTEN)
    {
        uint32_t client_iss = seq;
        // 用 tju_socket 新建连接（不再 memcpy 监听 socket，避免锁/指针浅拷贝）
        tju_tcp_t *new_conn = tju_socket();
        new_conn->established_local_addr = sock->bind_addr; // 172.17.0.3:1234
        new_conn->established_remote_addr.ip = inet_network(CLIENT_IP);
        new_conn->established_remote_addr.port = get_src(pkt); // 客户端源端口 5678

        // 服务端生成 ISN；SYN 占一个序号
        new_conn->iss = gen_iss();
        new_conn->window.wnd_send->base = new_conn->iss;
        new_conn->window.wnd_send->nextseq = new_conn->iss + 1;
        new_conn->window.wnd_recv->expect_seq = client_iss + 1;

        // 按四元组注册 established 表，使后续第三段 ACK 能路由到 new_conn
        int h = cal_hash(new_conn->established_local_addr.ip,
                         new_conn->established_local_addr.port,
                         new_conn->established_remote_addr.ip,
                         new_conn->established_remote_addr.port);
        established_socks[h] = new_conn;

        // 回 SYN+ACK：seq=iss_s, ack=client_iss+1
        new_conn->state = SYN_RECV;
        send_packet(new_conn, NULL, 0, SYN_FLAG_MASK | ACK_FLAG_MASK,
                    new_conn->iss, client_iss + 1);
#ifdef DEBUG
        printf("[server] recv SYN(seq=%u) -> new_conn, SYN+ACK(seq=%u,ack=%u), SYN_RECV\n",
               client_iss, new_conn->iss, client_iss + 1);
#endif
        return;
    }
}

/* 处理收到的 FIN：回 ACK，并按当前状态迁移 */
static void handle_fin(tju_tcp_t *sock, char *pkt)
{
    uint32_t seq = get_seq(pkt);
    uint8_t flags = get_flags(pkt);
    int fin_acked = 0;

    // 若该包同时带 ACK 且确认了我方 FIN（FIN_WAIT_1 下的 FIN+ACK）
    if ((flags & ACK_FLAG_MASK) && sock->state == FIN_WAIT_1)
    {
        uint32_t ack = get_ack(pkt);
        if (ack == sock->window.wnd_send->nextseq)
        {
            sock->window.wnd_send->base = ack;
            fin_acked = 1;
        }
    }

    // 回 ACK 确认对方 FIN（FIN 占一个序号）
    sock->window.wnd_recv->expect_seq = seq + 1;
    send_ack(sock);

    if (sock->state == ESTABLISHED)
    {
        // 被动关闭：对方先调用 close
        sock->state = CLOSE_WAIT;
#ifdef DEBUG
        printf("[passive] recv FIN(seq=%u) -> ACK, CLOSE_WAIT\n", seq);
#endif
    }
    else if (sock->state == FIN_WAIT_1)
    {
        if (fin_acked)
        {
            // 同时关闭，对方 FIN+ACK 已确认我方 FIN → 直接 TIME_WAIT
            sock->state = TIME_WAIT;
            pthread_mutex_lock(&(sock->recv_lock));
            pthread_cond_signal(&(sock->wait_cond));
            pthread_mutex_unlock(&(sock->recv_lock));
#ifdef DEBUG
            printf("[simultaneous] recv FIN+ACK -> TIME_WAIT\n");
#endif
        }
        else
        {
            // 同时关闭，但我方 FIN 尚未被确认 → CLOSING
            sock->state = CLOSING;
#ifdef DEBUG
            printf("[simultaneous] recv FIN -> ACK, CLOSING\n");
#endif
        }
    }
    else if (sock->state == FIN_WAIT_2)
    {
        // 主动关闭第二阶段，收到对方 FIN
        sock->state = TIME_WAIT;
        pthread_mutex_lock(&(sock->recv_lock));
        pthread_cond_signal(&(sock->wait_cond));
        pthread_mutex_unlock(&(sock->recv_lock));
#ifdef DEBUG
        printf("[active] FIN_WAIT_2 recv FIN -> ACK, TIME_WAIT\n");
#endif
    }
}

static void handle_ack(tju_tcp_t *sock, char *pkt)
{
    uint32_t ack = get_ack(pkt);

    /* 服务端：SYN_RECV 收到第三段 ACK -> 握手完成 */
    if (sock->state == SYN_RECV)
    {
        sock->window.wnd_send->base = ack;
        sock->state = ESTABLISHED;
        pthread_mutex_lock(&g_accept_lock);
        g_accept_queue = sock;
        pthread_cond_signal(&g_accept_cond);
        pthread_mutex_unlock(&g_accept_lock);
#ifdef DEBUG
        printf("[server] recv ACK(ack=%u) -> ESTABLISHED, ready for accept\n", ack);
#endif
        return;
    }

    /* 主动关闭：FIN_WAIT_1 收到我方 FIN 的 ACK -> FIN_WAIT_2 */
    if (sock->state == FIN_WAIT_1)
    {
        if (ack == sock->window.wnd_send->nextseq)
        {
            sock->window.wnd_send->base = ack;
            sock->state = FIN_WAIT_2;
#ifdef DEBUG
            printf("[active] FIN_WAIT_1 recv ACK(ack=%u) -> FIN_WAIT_2\n", ack);
#endif
        }
        return;
    }

    /* 同时关闭：CLOSING 收到我方 FIN 的 ACK -> TIME_WAIT */
    if (sock->state == CLOSING)
    {
        if (ack == sock->window.wnd_send->nextseq)
        {
            sock->window.wnd_send->base = ack;
            sock->state = TIME_WAIT;
            pthread_mutex_lock(&(sock->recv_lock));
            pthread_cond_signal(&(sock->wait_cond));
            pthread_mutex_unlock(&(sock->recv_lock));
#ifdef DEBUG
            printf("[simultaneous] CLOSING recv ACK -> TIME_WAIT\n");
#endif
        }
        return;
    }

    /* 被动关闭：LAST_ACK 收到我方 FIN 的 ACK -> CLOSED */
    if (sock->state == LAST_ACK)
    {
        if (ack == sock->window.wnd_send->nextseq)
        {
            sock->window.wnd_send->base = ack;
            sock->state = CLOSED;
            pthread_mutex_lock(&(sock->recv_lock));
            pthread_cond_signal(&(sock->wait_cond));
            pthread_mutex_unlock(&(sock->recv_lock));
#ifdef DEBUG
            printf("[passive] LAST_ACK recv ACK -> CLOSED\n");
#endif
        }
        return;
    }

    /* TODO(M3): ESTABLISHED 下的数据 ACK：滑动窗口、累计确认、RTT 采样、重复 ACK 计数 */
}

/* 数据载荷入接收缓冲：现阶段保留基线"直接追加"行为；M3 改为按 expect_seq 重组并回 ACK */
static void append_payload(tju_tcp_t *sock, char *pkt, uint32_t data_len)
{
    if (data_len <= 0)
        return;
    while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
        ; // 加锁
    if (sock->received_buf == NULL)
    {
        sock->received_buf = malloc(data_len);
    }
    else
    {
        sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len);
    }
    memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN, data_len);
    sock->received_len += data_len;
    pthread_cond_signal(&(sock->wait_cond));  // 数据到达，唤醒可能阻塞的 tju_recv（M3 配套使用）
    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁
}

/* 统一报文入口：按 标志位 / 是否带载荷 分发 */
int tju_handle_packet(tju_tcp_t *sock, char *pkt)
{
    uint8_t flags = get_flags(pkt);
    uint32_t data_len = get_plen(pkt) - get_hlen(pkt); // hlen 恒为 20

    // 1) SYN：握手段，不带数据、无需再走后续分支，处理完直接返回
    if (flags & SYN_FLAG_MASK)
    {
        handle_syn(sock, pkt);
        return 0;
    }
    // 2) FIN：挥手段（往往同时带 ACK，所以这里不 return，继续处理 ACK）
    if (flags & FIN_FLAG_MASK)
    {
        handle_fin(sock, pkt);
    }
    // 3) ACK：确认/推进。数据包也常同时带 ACK，因此 ACK 与数据不是互斥关系
    if (flags & ACK_FLAG_MASK)
    {
        handle_ack(sock, pkt);
    }
    // 4) 有数据载荷：放入接收缓冲
    if (data_len > 0)
    {
        append_payload(sock, pkt, data_len);
    }
    return 0;
}

int tju_close(tju_tcp_t *sock)
{
    /* ---- 情况1：ESTABLISHED 主动关闭 ---- */
    if (sock->state == ESTABLISHED)
    {
        uint32_t fin_seq = sock->window.wnd_send->nextseq;
        // 发 FIN+ACK：FIN 占一个序号，同时确认对方数据
        send_packet(sock, NULL, 0, FIN_FLAG_MASK | ACK_FLAG_MASK,
                    fin_seq, sock->window.wnd_recv->expect_seq);
        sock->window.wnd_send->nextseq = fin_seq + 1;
        sock->state = FIN_WAIT_1;
#ifdef DEBUG
        printf("[close] send FIN+ACK(seq=%u) -> FIN_WAIT_1\n", fin_seq);
#endif
        // 阻塞等待，直到接收线程把状态推进到 TIME_WAIT 或 CLOSED
        pthread_mutex_lock(&(sock->recv_lock));
        while (sock->state != TIME_WAIT && sock->state != CLOSED)
        {
            pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
        }
        pthread_mutex_unlock(&(sock->recv_lock));

        // TIME_WAIT：等待 2×MSL 后释放
        if (sock->state == TIME_WAIT)
        {
#ifdef DEBUG
            printf("[close] TIME_WAIT, waiting 2*MSL=%d ms\n", 2 * TJU_MSL_MS);
#endif
            usleep(2 * TJU_MSL_MS * 1000);
            sock->state = CLOSED;
        }
        free_tcp(sock);
        return 0;
    }

    /* ---- 情况2：CLOSE_WAIT 被动关闭（已收到对方 FIN，应用层现在调用 close）---- */
    if (sock->state == CLOSE_WAIT)
    {
        uint32_t fin_seq = sock->window.wnd_send->nextseq;
        send_packet(sock, NULL, 0, FIN_FLAG_MASK | ACK_FLAG_MASK,
                    fin_seq, sock->window.wnd_recv->expect_seq);
        sock->window.wnd_send->nextseq = fin_seq + 1;
        sock->state = LAST_ACK;
#ifdef DEBUG
        printf("[close] CLOSE_WAIT send FIN+ACK(seq=%u) -> LAST_ACK\n", fin_seq);
#endif
        // 阻塞等待对方最后一个 ACK
        pthread_mutex_lock(&(sock->recv_lock));
        while (sock->state != CLOSED)
        {
            pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
        }
        pthread_mutex_unlock(&(sock->recv_lock));
        free_tcp(sock);
        return 0;
    }

    /* ---- 情况3：已在关闭过程中（重复调用 close），等待完成 ---- */
    pthread_mutex_lock(&(sock->recv_lock));
    while (sock->state != TIME_WAIT && sock->state != CLOSED)
    {
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
    }
    pthread_mutex_unlock(&(sock->recv_lock));
    if (sock->state == TIME_WAIT)
    {
        usleep(2 * TJU_MSL_MS * 1000);
        sock->state = CLOSED;
    }
    free_tcp(sock);
    return 0;
}

#include "tju_tcp.h"
#include <errno.h>
#include <stdarg.h>
    /* ========== 前向声明 ========== */
    static void flush_send(tju_tcp_t *sock);
static void send_ack(tju_tcp_t *sock);
static void start_timer(tju_tcp_t *sock);
static void stop_timer(tju_tcp_t *sock);
static void reset_timer(tju_tcp_t *sock);
static uint16_t calc_adv_window(tju_tcp_t *sock);
#define FIXED_RTO 500
/* ========== 调试输出（写文件，避免干扰测试 stdout） ========== */
static void dbg_printf(const char *fmt, ...)
{
    char hn[16];
    gethostname(hn, sizeof(hn));
    FILE *fp = fopen("/vagrant/tju_tcp/test/rdt_dbg.log", "a");
    if (fp == NULL)
        return;
    fprintf(fp, "[%s] ", hn);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fclose(fp);
}
/* ========== 构建/发送分离：build 在锁内，send_out 在锁外 ========== */
typedef struct
{
    char *buf;
    uint16_t len;
} pkt_t;
static pkt_t build_pkt(tju_tcp_t *sock, char *data, uint16_t dlen,
                       uint8_t flags, uint32_t seq, uint32_t ack)
{
    pkt_t p;
    uint16_t plen = DEFAULT_HEADER_LEN + dlen;
    uint16_t adv = calc_adv_window(sock);
    p.buf = create_packet_buf(
        sock->established_local_addr.port,
        sock->established_remote_addr.port,
        seq, ack,
        DEFAULT_HEADER_LEN, plen, flags, adv, 0,
        data, (int)dlen);
    p.len = plen;
    return p;
}
static void send_out(pkt_t p)
{
    sendToLayer3(p.buf, p.len);
    free(p.buf);
}
/* 兼容旧调用：控制报文（SYN/FIN/ACK）发送频率低，直接构建+发送 */
static int send_packet(tju_tcp_t *sock, char *data, uint16_t dlen,
                       uint8_t flags, uint32_t seq, uint32_t ack)
{
    pkt_t p = build_pkt(sock, data, dlen, flags, seq, ack);
    send_out(p);
    return 0;
}
/* ===================== 选择重传：在途包链表 ===================== */
static void inflight_add(tju_tcp_t *sock, uint32_t seq, uint32_t len)
{
    inflight_node_t *node = (inflight_node_t *)malloc(sizeof(inflight_node_t));
    if (node == NULL)
        return;
    node->seq = seq;
    node->len = len;
    gettimeofday(&node->send_time, NULL);
    node->next = NULL;
    if (sock->inflight_head == NULL || sock->inflight_head->seq > seq)
    {
        node->next = sock->inflight_head;
        sock->inflight_head = node;
    }
    else
    {
        inflight_node_t *cur = sock->inflight_head;
        while (cur->next != NULL && cur->next->seq < seq)
            cur = cur->next;
        node->next = cur->next;
        cur->next = node;
    }
}
static void inflight_remove_acked(tju_tcp_t *sock, uint32_t ack)
{
    while (sock->inflight_head != NULL &&
           sock->inflight_head->seq + sock->inflight_head->len <= ack)
    {
        inflight_node_t *node = sock->inflight_head;
        sock->inflight_head = node->next;
        free(node);
    }
}
static void inflight_free(tju_tcp_t *sock)
{
    inflight_node_t *cur = sock->inflight_head;
    while (cur != NULL)
    {
        inflight_node_t *next = cur->next;
        free(cur);
        cur = next;
    }
    sock->inflight_head = NULL;
}
/* ===================== 工具函数 ===================== */
static uint32_t gen_iss(void)
{
    static uint32_t last_isn = 0;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t isn = (uint32_t)(((uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec) / 4);
    if (isn <= last_isn)
        isn = last_isn + 1;
    last_isn = isn;
    return isn;
}
static uint16_t calc_adv_window(tju_tcp_t *sock)
{
    receiver_window_t *rw = sock->window.wnd_recv;
    uint32_t used = (uint32_t)sock->received_len + rw->ooo_bytes;
    uint32_t avail = (used >= RECV_BUF_CAP) ? 0 : (RECV_BUF_CAP - used);
    if (avail < (uint32_t)SMSS)
        avail = 0;
    return (uint16_t)((avail > 65535) ? 65535 : avail);
}
static void send_ack(tju_tcp_t *sock)
{
    uint32_t seq = sock->window.wnd_send->nextseq;
    uint32_t ack = sock->window.wnd_recv->expect_seq;
    send_packet(sock, NULL, 0, ACK_FLAG_MASK, seq, ack);
}
static void free_tcp(tju_tcp_t *sock)
{
    if (sock->timer_on)
    {
        pthread_mutex_lock(&(sock->timer_lock));
        sock->timer_on = 0;
        pthread_cond_signal(&(sock->timer_cond));
        pthread_mutex_unlock(&(sock->timer_lock));
        pthread_join(sock->timer_thread, NULL);
    }
    int h = cal_hash(sock->established_local_addr.ip, sock->established_local_addr.port,
                     sock->established_remote_addr.ip, sock->established_remote_addr.port);
    if (h >= 0 && h < MAX_SOCK && established_socks[h] == sock)
        established_socks[h] = NULL;
    free(sock->sending_buf);
    free(sock->received_buf);
    free(sock->window.wnd_send);
    if (sock->window.wnd_recv != NULL)
    {
        ooo_node_t *p = sock->window.wnd_recv->ooo_head;
        while (p != NULL)
        {
            ooo_node_t *next = p->next;
            free(p->data);
            free(p);
            p = next;
        }
        free(sock->window.wnd_recv);
    }
    pthread_mutex_destroy(&(sock->send_lock));
    pthread_mutex_destroy(&(sock->recv_lock));
    pthread_mutex_destroy(&(sock->timer_lock));
    pthread_cond_destroy(&(sock->wait_cond));
    pthread_cond_destroy(&(sock->timer_cond));
    inflight_free(sock);
    free(sock);
}
/* ===================== 重传定时器 ===================== */
static void retransmit_control(tju_tcp_t *sock)
{
    sender_window_t *sw = sock->window.wnd_send;
    receiver_window_t *rw = sock->window.wnd_recv;
    if (sock->state == SYN_SENT)
        send_packet(sock, NULL, 0, SYN_FLAG_MASK, sock->iss, 0);
    else if (sock->state == SYN_RECV)
    {
        uint32_t peer_iss = (rw->expect_seq > 0) ? (rw->expect_seq - 1) : 0;
        send_packet(sock, NULL, 0, SYN_FLAG_MASK | ACK_FLAG_MASK, sock->iss, peer_iss + 1);
    }
    else if (sock->state == FIN_WAIT_1 || sock->state == CLOSING || sock->state == LAST_ACK)
    {
        uint32_t fin_seq = sw->nextseq - 1;
        send_packet(sock, NULL, 0, FIN_FLAG_MASK | ACK_FLAG_MASK, fin_seq, rw->expect_seq);
    }
}
/* SR 定时器：固定小间隔唤醒检查；数据包超时阈值固定 */
#define SR_TICK_MS 20
#define SR_RTO_MS 100
#define SR_REXMIT_MAX 4
static void *timer_thread_func(void *arg)
{
    tju_tcp_t *sock = (tju_tcp_t *)arg;
    while (1)
    {
        pthread_mutex_lock(&(sock->timer_lock));
        if (!sock->timer_on)
        {
            pthread_mutex_unlock(&(sock->timer_lock));
            break;
        }
        struct timespec ts;
        struct timeval now;
        gettimeofday(&now, NULL);
        ts.tv_sec = now.tv_sec + SR_TICK_MS / 1000;
        ts.tv_nsec = (now.tv_usec + (SR_TICK_MS % 1000) * 1000) * 1000;
        if (ts.tv_nsec >= 1000000000)
        {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }
        int ret = pthread_cond_timedwait(&(sock->timer_cond), &(sock->timer_lock), &ts);
        pthread_mutex_unlock(&(sock->timer_lock));
        if (ret != ETIMEDOUT)
            continue;
        int st = sock->state;
        if (st == SYN_SENT || st == SYN_RECV ||
            st == FIN_WAIT_1 || st == CLOSING || st == LAST_ACK)
        {
            /* 控制报文（SYN/FIN）：按 sw->rto 指数退避重传 */
            pthread_mutex_lock(&(sock->send_lock));
            struct timeval cnow;
            gettimeofday(&cnow, NULL);
            uint32_t elapsed = (uint32_t)((cnow.tv_sec - sock->window.wnd_send->send_time.tv_sec) * 1000 +
                                          (cnow.tv_usec - sock->window.wnd_send->send_time.tv_usec) / 1000);
            if (elapsed >= sock->window.wnd_send->rto)
            {
                sock->rexmit_count++;
                if (st == SYN_SENT || st == SYN_RECV)
                    sock->syn_rexmitted = 1;
                retransmit_control(sock);
                sock->window.wnd_send->rto *= 2;
                if (sock->window.wnd_send->rto > RTO_MAX_MS)
                    sock->window.wnd_send->rto = RTO_MAX_MS;
                sock->window.wnd_send->send_time = cnow;
                if (sock->rexmit_count >= MAX_RXT)
                {
                    sock->state = CLOSED;
                    pthread_mutex_lock(&(sock->recv_lock));
                    pthread_cond_signal(&(sock->wait_cond));
                    pthread_mutex_unlock(&(sock->recv_lock));
                }
            }
            pthread_mutex_unlock(&(sock->send_lock));
        }
        else if (st == ESTABLISHED)
        {
            pthread_mutex_lock(&(sock->send_lock));
            sender_window_t *sw = sock->window.wnd_send;
            uint32_t in_flight = sw->nextseq - sw->base;
            if (in_flight > 0)
            {
                /* 选择重传：只重传发送时间真正超过 SR_RTO_MS 的最早若干包 */
                pkt_t rpkts[SR_REXMIT_MAX];
                int nrpkt = 0;
                struct timeval now2;
                gettimeofday(&now2, NULL);
                inflight_node_t *cur = sock->inflight_head;
                while (cur != NULL && nrpkt < SR_REXMIT_MAX)
                {
                    uint32_t elapsed = (uint32_t)((now2.tv_sec - cur->send_time.tv_sec) * 1000 +
                                                  (now2.tv_usec - cur->send_time.tv_usec) / 1000);
                    if (elapsed >= SR_RTO_MS)
                    {
                        uint32_t offset = cur->seq - sw->base;
                        rpkts[nrpkt] = build_pkt(sock, sock->sending_buf + offset, (uint16_t)cur->len,
                                                 ACK_FLAG_MASK, cur->seq, sock->window.wnd_recv->expect_seq);
                        nrpkt++;
                        cur->send_time = now2;
                    }
                    cur = cur->next;
                }
                if (nrpkt > 0)
                    dbg_printf("SR retransmit %d pkts base=%u nextseq=%u\n",
                               nrpkt, sw->base, sw->nextseq);
                pthread_mutex_unlock(&(sock->send_lock));
                for (int i = 0; i < nrpkt; i++)
                    send_out(rpkts[i]);
            }
            else if (sw->rwnd == 0 && (uint32_t)sock->sending_len > 0)
            {
                uint32_t probe_seq = sw->nextseq;
                uint32_t offset = probe_seq - sw->base;
                if (offset < (uint32_t)sock->sending_len)
                {
                    pkt_t ppkt = build_pkt(sock, sock->sending_buf + offset, 1,
                                           ACK_FLAG_MASK, probe_seq, sock->window.wnd_recv->expect_seq);
                    pthread_mutex_unlock(&(sock->send_lock));
                    send_out(ppkt);
                }
                else
                {
                    pthread_mutex_unlock(&(sock->send_lock));
                }
            }
            else
            {
                pthread_mutex_unlock(&(sock->send_lock));
            }
        }
    }
    return NULL;
}
static void start_timer(tju_tcp_t *sock)
{
    if (sock->timer_on)
        return;
    sock->timer_on = 1;
    pthread_create(&(sock->timer_thread), NULL, timer_thread_func, (void *)sock);
}
static void stop_timer(tju_tcp_t *sock)
{
    if (!sock->timer_on)
        return;
    pthread_mutex_lock(&(sock->timer_lock));
    sock->timer_on = 0;
    pthread_cond_signal(&(sock->timer_cond));
    pthread_mutex_unlock(&(sock->timer_lock));
    pthread_join(sock->timer_thread, NULL);
}
static void reset_timer(tju_tcp_t *sock)
{
    if (!sock->timer_on)
        return;
    pthread_mutex_lock(&(sock->timer_lock));
    pthread_cond_signal(&(sock->timer_cond));
    pthread_mutex_unlock(&(sock->timer_lock));
}
/* ===================== 发送端滑动窗口（锁内构建，锁外发送） ===================== */
#define MAX_BURST 16
static void flush_send(tju_tcp_t *sock)
{
    pkt_t pkts[MAX_BURST];
    int npkt = 0;
    uint32_t first_seq = 0;
    pthread_mutex_lock(&(sock->send_lock));
    sender_window_t *sw = sock->window.wnd_send;
    uint32_t eff_window = (sw->rwnd < sw->cwnd) ? sw->rwnd : sw->cwnd;
    uint32_t in_flight_before = sw->nextseq - sw->base;
    uint32_t available = (eff_window > in_flight_before) ? (eff_window - in_flight_before) : 0;
    uint32_t unsent = (uint32_t)sock->sending_len - in_flight_before;
    while (available > 0 && unsent > 0 && npkt < MAX_BURST)
    {
        uint32_t seg_len = SMSS;
        if (seg_len > available) seg_len = available;
        if (seg_len > unsent) seg_len = unsent;
        uint32_t seq = sw->nextseq;
        if (npkt == 0)
            first_seq = seq;
        uint32_t offset = seq - sw->base;
        pkts[npkt] = build_pkt(sock, sock->sending_buf + offset, (uint16_t)seg_len,
                               ACK_FLAG_MASK, seq, sock->window.wnd_recv->expect_seq);
        inflight_add(sock, seq, seg_len);
        npkt++;
        sw->nextseq += seg_len;
        available -= seg_len;
        unsent -= seg_len;
    }
    int need_timer = (sw->nextseq > sw->base) && !sock->timer_on;
    pthread_mutex_unlock(&(sock->send_lock));
    /* 锁外批量发送——sendto 可能阻塞，但不影响接收线程 */
    for (int i = 0; i < npkt; i++)
        send_out(pkts[i]);
    if (npkt > 0)
        dbg_printf("FLUSH sent %d segs, first_seq=%u\n", npkt, first_seq);
    if (need_timer)
        start_timer(sock);
}
/* ===================== 全连接队列 ===================== */
static tju_tcp_t *g_accept_queue = NULL;
static pthread_mutex_t g_accept_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_accept_cond = PTHREAD_COND_INITIALIZER;
/* ===================== 八个规定接口 ===================== */
tju_tcp_t *tju_socket()
{
    tju_tcp_t *sock = (tju_tcp_t *)malloc(sizeof(tju_tcp_t));
    if (sock == NULL)
    {
        perror("malloc");
        exit(-1);
    }
    memset(sock, 0, sizeof(tju_tcp_t));
    sock->state = CLOSED;
    pthread_mutex_init(&(sock->send_lock), NULL);
    pthread_mutex_init(&(sock->recv_lock), NULL);
    pthread_mutex_init(&(sock->timer_lock), NULL);
    pthread_cond_init(&(sock->wait_cond), NULL);
    pthread_cond_init(&(sock->timer_cond), NULL);
    sock->window.wnd_send = (sender_window_t *)malloc(sizeof(sender_window_t));
    memset(sock->window.wnd_send, 0, sizeof(sender_window_t));
    sender_window_t *sw = sock->window.wnd_send;
    sw->rwnd = 65535;
    sw->cwnd = 24 * SMSS;
    sw->ssthresh = 24 * SMSS;
    sw->window_size = 65535;
    sw->rto = FIXED_RTO;
    sock->window.wnd_recv = (receiver_window_t *)malloc(sizeof(receiver_window_t));
    memset(sock->window.wnd_recv, 0, sizeof(receiver_window_t));
    sock->window.wnd_recv->adv_window = 65535;
    return sock;
}
int tju_bind(tju_tcp_t *sock, tju_sock_addr bind_addr)
{
    sock->bind_addr = bind_addr;
    return 0;
}
int tju_listen(tju_tcp_t *sock)
{
    sock->state = LISTEN;
    int hashval = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
    listen_socks[hashval] = sock;
    return 0;
}
tju_tcp_t *tju_accept(tju_tcp_t *listen_sock)
{
    (void)listen_sock;
    pthread_mutex_lock(&g_accept_lock);
    while (g_accept_queue == NULL)
        pthread_cond_wait(&g_accept_cond, &g_accept_lock);
    tju_tcp_t *new_conn = g_accept_queue;
    g_accept_queue = NULL;
    pthread_mutex_unlock(&g_accept_lock);
    return new_conn;
}
int tju_connect(tju_tcp_t *sock, tju_sock_addr target_addr)
{
    tju_sock_addr local_addr;
    local_addr.ip = inet_network(CLIENT_IP);
    local_addr.port = 5678;
    sock->established_local_addr = local_addr;
    sock->established_remote_addr = target_addr;
    sock->iss = gen_iss();
    sock->window.wnd_send->base = sock->iss;
    sock->window.wnd_send->nextseq = sock->iss + 1;
    int hashval = cal_hash(local_addr.ip, local_addr.port, target_addr.ip, target_addr.port);
    established_socks[hashval] = sock;
    sock->state = SYN_SENT;
    send_packet(sock, NULL, 0, SYN_FLAG_MASK, sock->iss, 0);
    gettimeofday(&(sock->window.wnd_send->send_time), NULL);
    start_timer(sock);
    pthread_mutex_lock(&(sock->recv_lock));
    while (sock->state != ESTABLISHED && sock->state != CLOSED)
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
    int connected = (sock->state == ESTABLISHED);
    pthread_mutex_unlock(&(sock->recv_lock));
    return connected ? 0 : -1;
}
int tju_send(tju_tcp_t *sock, const void *buffer, int len)
{
    if (len <= 0)
        return 0;
    int total = 0;
    while (total < len)
    {
        pthread_mutex_lock(&(sock->send_lock));
        while ((uint32_t)sock->sending_len >= SEND_BUF_CAP && sock->state == ESTABLISHED)
            pthread_cond_wait(&(sock->wait_cond), &(sock->send_lock));
        if (sock->state != ESTABLISHED)
        {
            pthread_mutex_unlock(&(sock->send_lock));
            return -1;
        }
        uint32_t space = SEND_BUF_CAP - (uint32_t)sock->sending_len;
        uint32_t to_copy = ((uint32_t)(len - total) < space) ? (uint32_t)(len - total) : space;
        char *new_buf = (char *)realloc(sock->sending_buf, (uint32_t)sock->sending_len + to_copy);
        if (new_buf == NULL)
        {
            pthread_mutex_unlock(&(sock->send_lock));
            return -1;
        }
        sock->sending_buf = new_buf;
        memcpy(sock->sending_buf + sock->sending_len, (const char *)buffer + total, to_copy);
        sock->sending_len += (int)to_copy;
        total += (int)to_copy;
        pthread_mutex_unlock(&(sock->send_lock));
        flush_send(sock);
    }
    return len;
}
int tju_recv(tju_tcp_t *sock, void *buffer, int len)
{
    pthread_mutex_lock(&(sock->recv_lock));
    while (sock->received_len <= 0 && !sock->peer_fin)
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
    if (sock->received_len <= 0 && sock->peer_fin)
    {
        pthread_mutex_unlock(&(sock->recv_lock));
        return 0;
    }
    int read_len = (len < sock->received_len) ? len : sock->received_len;
    memcpy(buffer, sock->received_buf, read_len);
    if (read_len < sock->received_len)
    {
        memmove(sock->received_buf, sock->received_buf + read_len, sock->received_len - read_len);
        sock->received_len -= read_len;
    }
    else
        sock->received_len = 0;
    pthread_mutex_unlock(&(sock->recv_lock));
    send_ack(sock);
    return read_len;
}
/* ===================== 接收端按序交付与乱序缓存 ===================== */
static void deliver_segment(tju_tcp_t *sock, uint32_t seq, char *data, uint32_t len)
{
    (void)seq;
    if (len == 0)
        return;
    char *new_buf = (char *)realloc(sock->received_buf, (size_t)sock->received_len + len);
    if (new_buf == NULL)
        return;
    sock->received_buf = new_buf;
    memcpy(sock->received_buf + sock->received_len, data, len);
    sock->received_len += (int)len;
    sock->window.wnd_recv->expect_seq += len;
    pthread_cond_signal(&(sock->wait_cond));
}
static void deliver_contiguous(tju_tcp_t *sock)
{
    receiver_window_t *rw = sock->window.wnd_recv;
    while (rw->ooo_head != NULL && rw->ooo_head->seq == rw->expect_seq)
    {
        ooo_node_t *node = rw->ooo_head;
        deliver_segment(sock, node->seq, node->data, node->len);
        rw->ooo_head = node->next;
        rw->ooo_bytes -= node->len;
        free(node->data);
        free(node);
    }
}
static void insert_ooo(tju_tcp_t *sock, uint32_t seq, char *data, uint32_t len)
{
    receiver_window_t *rw = sock->window.wnd_recv;
    ooo_node_t *cur = rw->ooo_head;
    while (cur != NULL)
    {
        if (cur->seq == seq)
            return;
        cur = cur->next;
    }
    ooo_node_t *node = (ooo_node_t *)malloc(sizeof(ooo_node_t));
    if (node == NULL)
        return;
    node->seq = seq;
    node->len = len;
    node->data = (char *)malloc(len);
    if (node->data == NULL)
    {
        free(node);
        return;
    }
    memcpy(node->data, data, len);
    node->next = NULL;
    if (rw->ooo_head == NULL || rw->ooo_head->seq > seq)
    {
        node->next = rw->ooo_head;
        rw->ooo_head = node;
    }
    else
    {
        cur = rw->ooo_head;
        while (cur->next != NULL && cur->next->seq < seq)
            cur = cur->next;
        node->next = cur->next;
        cur->next = node;
    }
    rw->ooo_bytes += len;
}
static void handle_data(tju_tcp_t *sock, char *pkt, uint32_t data_len)
{
    if (data_len <= 0)
        return;
    dbg_printf("RECV_DATA seq=%u len=%u expect=%u\n", get_seq(pkt), data_len, sock->window.wnd_recv->expect_seq);
    uint32_t seq = get_seq(pkt);
    uint32_t end = seq + data_len;
    receiver_window_t *rw = sock->window.wnd_recv;
    pthread_mutex_lock(&(sock->recv_lock));
    if (end <= rw->expect_seq)
    { /* duplicate */
    }
    else if ((uint32_t)sock->received_len + rw->ooo_bytes >= RECV_BUF_CAP)
    { /* drop */
    }
    else if (seq < rw->expect_seq)
    {
        uint32_t offset = rw->expect_seq - seq;
        uint32_t new_len = end - rw->expect_seq;
        deliver_segment(sock, rw->expect_seq, pkt + DEFAULT_HEADER_LEN + offset, new_len);
        deliver_contiguous(sock);
    }
    else if (seq == rw->expect_seq)
    {
        deliver_segment(sock, seq, pkt + DEFAULT_HEADER_LEN, data_len);
        deliver_contiguous(sock);
    }
    else
        insert_ooo(sock, seq, pkt + DEFAULT_HEADER_LEN, data_len);
    pthread_mutex_unlock(&(sock->recv_lock));
    send_ack(sock);
}
/* ===================== 报文分发 ===================== */
static void handle_syn(tju_tcp_t *sock, char *pkt)
{
    uint32_t seq = get_seq(pkt);
    if (sock->state == SYN_SENT)
    {
        sock->window.wnd_recv->expect_seq = seq + 1;
        sock->window.wnd_send->base = get_ack(pkt);
        sock->window.wnd_send->rwnd = get_advertised_window(pkt);
        send_ack(sock);
        pthread_mutex_lock(&(sock->recv_lock));
        sock->state = ESTABLISHED;
        sock->rexmit_count = 0;
        sock->window.wnd_send->rto = sock->syn_rexmitted ? RTO_MAX_MS : FIXED_RTO;
        pthread_cond_signal(&(sock->wait_cond));
        pthread_mutex_unlock(&(sock->recv_lock));
        return;
    }
    if (sock->state == ESTABLISHED)
    {
        send_ack(sock);
        return;
    }
    if (sock->state == LISTEN)
    {
        uint32_t client_iss = seq;
        tju_tcp_t *new_conn = tju_socket();
        new_conn->established_local_addr = sock->bind_addr;
        new_conn->established_remote_addr.ip = inet_network(CLIENT_IP);
        new_conn->established_remote_addr.port = get_src(pkt);
        new_conn->iss = gen_iss();
        new_conn->window.wnd_send->base = new_conn->iss;
        new_conn->window.wnd_send->nextseq = new_conn->iss + 1;
        new_conn->window.wnd_recv->expect_seq = client_iss + 1;
        int h = cal_hash(new_conn->established_local_addr.ip, new_conn->established_local_addr.port,
                         new_conn->established_remote_addr.ip, new_conn->established_remote_addr.port);
        established_socks[h] = new_conn;
        new_conn->state = SYN_RECV;
        send_packet(new_conn, NULL, 0, SYN_FLAG_MASK | ACK_FLAG_MASK, new_conn->iss, client_iss + 1);
        gettimeofday(&(new_conn->window.wnd_send->send_time), NULL);
        start_timer(new_conn);
        return;
    }
}
static void handle_fin(tju_tcp_t *sock, char *pkt)
{
    uint32_t seq = get_seq(pkt);
    if (sock->state == ESTABLISHED)
    {
        pthread_mutex_lock(&(sock->recv_lock));
        if (seq == sock->window.wnd_recv->expect_seq)
            sock->window.wnd_recv->expect_seq++;
        sock->peer_fin = 1;
        pthread_cond_signal(&(sock->wait_cond));
        pthread_mutex_unlock(&(sock->recv_lock));
        sock->state = CLOSE_WAIT;
        send_ack(sock);
        return;
    }
    if (sock->state == FIN_WAIT_1)
    {
        pthread_mutex_lock(&(sock->recv_lock));
        if (seq == sock->window.wnd_recv->expect_seq)
            sock->window.wnd_recv->expect_seq++;
        pthread_mutex_unlock(&(sock->recv_lock));
        sock->state = CLOSING;
        send_ack(sock);
        return;
    }
    if (sock->state == FIN_WAIT_2)
    {
        pthread_mutex_lock(&(sock->recv_lock));
        if (seq == sock->window.wnd_recv->expect_seq)
            sock->window.wnd_recv->expect_seq++;
        pthread_mutex_unlock(&(sock->recv_lock));
        sock->state = TIME_WAIT;
        send_ack(sock);
        pthread_mutex_lock(&(sock->recv_lock));
        pthread_cond_signal(&(sock->wait_cond));
        pthread_mutex_unlock(&(sock->recv_lock));
        return;
    }
    if (sock->state == TIME_WAIT)
    {
        send_ack(sock);
        return;
    }
    if (sock->state == CLOSE_WAIT || sock->state == LAST_ACK || sock->state == CLOSING)
    {
        send_ack(sock);
        return;
    }
}
static void handle_ack(tju_tcp_t *sock, char *pkt)
{
    uint32_t ack = get_ack(pkt);
    if (sock->state == SYN_RECV)
    {
        sock->window.wnd_send->base = ack;
        sock->state = ESTABLISHED;
        sock->rexmit_count = 0;
        sock->window.wnd_send->rto = sock->syn_rexmitted ? RTO_MAX_MS : FIXED_RTO;
        pthread_mutex_lock(&g_accept_lock);
        g_accept_queue = sock;
        pthread_cond_signal(&g_accept_cond);
        pthread_mutex_unlock(&g_accept_lock);
        return;
    }
    if (sock->state == FIN_WAIT_1)
    {
        if (ack == sock->window.wnd_send->nextseq)
        {
            sock->window.wnd_send->base = ack;
            sock->state = FIN_WAIT_2;
        }
        return;
    }
    if (sock->state == CLOSING)
    {
        if (ack == sock->window.wnd_send->nextseq)
        {
            sock->window.wnd_send->base = ack;
            sock->state = TIME_WAIT;
            pthread_mutex_lock(&(sock->recv_lock));
            pthread_cond_signal(&(sock->wait_cond));
            pthread_mutex_unlock(&(sock->recv_lock));
        }
        return;
    }
    if (sock->state == LAST_ACK)
    {
        if (ack == sock->window.wnd_send->nextseq)
        {
            sock->window.wnd_send->base = ack;
            sock->state = CLOSED;
            pthread_mutex_lock(&(sock->recv_lock));
            pthread_cond_signal(&(sock->wait_cond));
            pthread_mutex_unlock(&(sock->recv_lock));
        }
        return;
    }
    if (sock->state == ESTABLISHED)
    {
        uint16_t adv = get_advertised_window(pkt);
        pthread_mutex_lock(&(sock->send_lock));
        sender_window_t *sw = sock->window.wnd_send;
        sw->rwnd = adv;
        if (ack > sw->base)
        {
            if (ack > sw->nextseq)
                ack = sw->nextseq;
            if (ack <= sw->base)
            {
                pthread_mutex_unlock(&(sock->send_lock));
                return;
            }
            uint32_t acked = ack - sw->base;
            if (acked > (uint32_t)sock->sending_len)
                acked = (uint32_t)sock->sending_len;
            sock->sending_len -= (int)acked;
            if (sock->sending_len > 0)
                memmove(sock->sending_buf, sock->sending_buf + acked, (size_t)sock->sending_len);
            sw->base = ack;
            sw->dupack = 0;
            sw->rexmitted = 0;
            sw->rto = FIXED_RTO;
            sock->rexmit_count = 0;
            inflight_remove_acked(sock, ack);
            dbg_printf("NEWACK ack=%u base=%u nextseq=%u send_len=%d rwnd=%u\n",
                       ack, sw->base, sw->nextseq, sock->sending_len, adv);
            pthread_cond_signal(&(sock->wait_cond));
            pthread_mutex_unlock(&(sock->send_lock));
            flush_send(sock);
            return;
        }
        else if (ack == sw->base && ack > 0)
        {
            sw->dupack++;
            /* 快速重传：3个dup ACK触发；一次补上在途链表最早的若干疑似丢包，
               rexmitted保证同一base只触发一次，杜绝风暴 */
            if (sw->dupack >= 3 && !sw->rexmitted && (sw->nextseq > sw->base))
            {
                pkt_t fpkts[SR_REXMIT_MAX];
                int nfpkt = 0;
                inflight_node_t *c = sock->inflight_head;
                struct timeval fnow;
                gettimeofday(&fnow, NULL);
                while (c != NULL && nfpkt < SR_REXMIT_MAX)
                {
                    uint32_t off = c->seq - sw->base;
                    fpkts[nfpkt] = build_pkt(sock, sock->sending_buf + off, (uint16_t)c->len,
                                             ACK_FLAG_MASK, c->seq, sock->window.wnd_recv->expect_seq);
                    c->send_time = fnow; /* 同步计时，避免SR立刻重复重传 */
                    nfpkt++;
                    c = c->next;
                }
                dbg_printf("FASTXMIT %d pkts base=%u dupack=%d\n", nfpkt, sw->base, sw->dupack);
                sw->rexmitted = 1;
                pthread_mutex_unlock(&(sock->send_lock));
                for (int i = 0; i < nfpkt; i++)
                    send_out(fpkts[i]);
                flush_send(sock);
                return;
            }
            pthread_mutex_unlock(&(sock->send_lock));
            flush_send(sock);
            return;
        }
        pthread_mutex_unlock(&(sock->send_lock));
    }
}
int tju_handle_packet(tju_tcp_t *sock, char *pkt)
{
    uint8_t flags = get_flags(pkt);
    uint32_t data_len = get_plen(pkt) - get_hlen(pkt);
    static uint32_t dbg_cnt = 0;
    if (sock->state == ESTABLISHED && (flags & ACK_FLAG_MASK) && data_len == 0)
    {
        dbg_cnt++;
        if (dbg_cnt % 100 == 0)
            dbg_printf("recv ACK #%u ack=%u base=%u nextseq=%u rwnd=%u\n",
                       dbg_cnt, get_ack(pkt), sock->window.wnd_send->base,
                       sock->window.wnd_send->nextseq, get_advertised_window(pkt));
    }
    if (flags & SYN_FLAG_MASK)
    {
        handle_syn(sock, pkt);
        return 0;
    }
    if (flags & FIN_FLAG_MASK)
        handle_fin(sock, pkt);
    if (flags & ACK_FLAG_MASK)
        handle_ack(sock, pkt);
    if (data_len > 0)
        handle_data(sock, pkt, data_len);
    return 0;
}
int tju_close(tju_tcp_t *sock)
{
    if (sock->state == ESTABLISHED)
    {
        pthread_mutex_lock(&(sock->send_lock));
        while (sock->sending_len > 0 || (sock->window.wnd_send->nextseq > sock->window.wnd_send->base))
        {
            if (sock->state != ESTABLISHED)
                break;
            pthread_cond_wait(&(sock->wait_cond), &(sock->send_lock));
        }
        pthread_mutex_unlock(&(sock->send_lock));
        if (sock->state != ESTABLISHED)
            return -1;
        pthread_mutex_lock(&(sock->send_lock));
        uint32_t fin_seq = sock->window.wnd_send->nextseq;
        sock->window.wnd_send->nextseq = fin_seq + 1;
        sock->state = FIN_WAIT_1;
        sock->rexmit_count = 0;
        pthread_mutex_unlock(&(sock->send_lock));
        send_packet(sock, NULL, 0, FIN_FLAG_MASK | ACK_FLAG_MASK, fin_seq, sock->window.wnd_recv->expect_seq);
        gettimeofday(&(sock->window.wnd_send->send_time), NULL);
        if (!sock->timer_on)
            start_timer(sock);
        pthread_mutex_lock(&(sock->recv_lock));
        while (sock->state != TIME_WAIT && sock->state != CLOSED)
            pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
        pthread_mutex_unlock(&(sock->recv_lock));
        if (sock->state == TIME_WAIT)
        {
            usleep(TJU_MSL_MS * 2 * 1000);
            sock->state = CLOSED;
        }
    }
    else if (sock->state == CLOSE_WAIT)
    {
        pthread_mutex_lock(&(sock->send_lock));
        uint32_t fin_seq = sock->window.wnd_send->nextseq;
        sock->window.wnd_send->nextseq = fin_seq + 1;
        sock->state = LAST_ACK;
        sock->rexmit_count = 0;
        pthread_mutex_unlock(&(sock->send_lock));
        send_packet(sock, NULL, 0, FIN_FLAG_MASK | ACK_FLAG_MASK, fin_seq, sock->window.wnd_recv->expect_seq);
        gettimeofday(&(sock->window.wnd_send->send_time), NULL);
        if (!sock->timer_on)
            start_timer(sock);
        pthread_mutex_lock(&(sock->recv_lock));
        while (sock->state != CLOSED)
            pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
        pthread_mutex_unlock(&(sock->recv_lock));
    }
    free_tcp(sock);
    return 0;
}

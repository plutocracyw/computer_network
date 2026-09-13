#include "tju_tcp.h"
#include <errno.h>
#include <stdarg.h>
#include <time.h>
    /* ========== 前向声明 ========== */
    static void flush_send(tju_tcp_t *sock);
static void send_ack(tju_tcp_t *sock);
static void start_timer(tju_tcp_t *sock);
static void stop_timer(tju_tcp_t *sock);
static void reset_timer(tju_tcp_t *sock);
static uint16_t calc_adv_window(tju_tcp_t *sock);
#define FIXED_RTO 500
/* ===== 第三阶段：基础 Reno（RFC 5681）初始参数 ===== */
#define CWND_INIT (3 * SMSS)    /* 初始拥塞窗口 IW：SMSS=1380∈(1095,2190]，RFC5681 规定 IW=3 SMSS */
#define SSTH_INIT 65535u        /* 初始慢启动门限 = 课程允许的最大接收窗口（16位 advertised_window 上限） */
/* 发送节拍(pacing)：同一窗口的多个段不允许在同一微秒瞬时灌入网卡。
   根因——整窗段同刻 sendto，经 netem 固定延迟后同刻"倾倒"到对端，内核调度使相邻段
   产生 0~0.2ms 的微乱序，一个段晚到即令其后所有段回相同 dupACK，被误判为快重而连环砍窗。
   段间留 100us 间隔，使进入 qdisc 的时间戳严格递增、出队严格有序，从源头消除微乱序；
   100us 远小于 RTT(数百ms)，一窗47段发完仅约4.7ms，不影响慢启动/吞吐形态。 */
#define PACE_NS 100000L
/* ========== 调试输出（写文件，避免干扰测试 stdout） ==========
   hostname只取一次、文件句柄常开带大缓冲、静态锁保证多线程安全，
   避免每包数万次 gethostname/fopen/fclose 的系统调用开销 ========== */
static void dbg_printf(const char *fmt, ...)
{
    static char hn[16] = {0};
    static FILE *dbg_fp = NULL;
    static pthread_mutex_t dbg_lock = PTHREAD_MUTEX_INITIALIZER;
    if (hn[0] == 0)
        gethostname(hn, sizeof(hn));
    pthread_mutex_lock(&dbg_lock);
    if (dbg_fp == NULL)
    {
        dbg_fp = fopen("/vagrant/tju_tcp/test/rdt_dbg.log", "a");
        if (dbg_fp == NULL)
        {
            pthread_mutex_unlock(&dbg_lock);
            return;
        }
        static char dbg_iobuf[1 << 16];
        setvbuf(dbg_fp, dbg_iobuf, _IOFBF, sizeof(dbg_iobuf));
    }
    fprintf(dbg_fp, "[%s] ", hn);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(dbg_fp, fmt, ap);
    va_end(ap);
    pthread_mutex_unlock(&dbg_lock);
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
/* ===================== Trace 事件记录（流量控制/拥塞控制作图） =====================
   输出 client.event.trace / server.event.trace，格式 [us] [EVENT] [k:v ...]
   文件句柄常开+全缓冲，避免拖慢收发；首次使用时按 hostname 决定文件名并覆盖打开 */
#define TRACE_MSS 1375 /* gen_graph 脚本把窗口字节数 /1375 还原成段数 */
static FILE *trace_fp = NULL;
static pthread_once_t trace_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t trace_lock = PTHREAD_MUTEX_INITIALIZER;

static long trace_now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000000L + (long)tv.tv_usec;
}
static void trace_open_once(void)
{
    char hn[32] = {0};
    gethostname(hn, sizeof(hn));
    const char *fn = (strncmp(hn, "client", 6) == 0)
                         ? "/vagrant/tju_tcp/test/client.event.trace"
                         : "/vagrant/tju_tcp/test/server.event.trace";
    trace_fp = fopen(fn, "w"); /* 每次启动覆盖旧日志 */
    if (trace_fp != NULL)
    {
        static char trace_iobuf[1 << 16];
        setvbuf(trace_fp, trace_iobuf, _IOFBF, sizeof(trace_iobuf));
    }
}
static void trace_open(void)
{
    pthread_once(&trace_once, trace_open_once);
}
static void trace_emit(const char *ev, const char *fmt, ...)
{
    if (trace_fp == NULL)
        return;
    va_list ap;
    pthread_mutex_lock(&trace_lock);
    fprintf(trace_fp, "[%ld] [%s] [", trace_now_us(), ev);
    va_start(ap, fmt);
    vfprintf(trace_fp, fmt, ap);
    va_end(ap);
    fprintf(trace_fp, "]\n");
    static unsigned int emit_cnt = 0;
    if (++emit_cnt >= 200)
    { /* 周期落盘，避免测试结束kill进程时丢失全缓冲尾部 */
        fflush(trace_fp);
        emit_cnt = 0;
    }
    pthread_mutex_unlock(&trace_lock);
}
/* trace flag：8=SYN 12=SYN|ACK 2=FIN 4=纯ACK 0=数据段(NO_FLAG) */
static int trace_pkt_flag(uint8_t flags, uint32_t dlen)
{
    if (flags & SYN_FLAG_MASK)
        return (flags & ACK_FLAG_MASK) ? 12 : 8;
    if (flags & FIN_FLAG_MASK)
        return 2;
    return (dlen > 0) ? 0 : 4;
}
static void trace_pkt(const char *ev, char *buf)
{
    if (trace_fp == NULL)
        return;
    uint32_t dlen = (uint32_t)get_plen(buf) - (uint32_t)get_hlen(buf);
    trace_emit(ev, "seq:%u ack:%u flag:%d length:%u",
               get_seq(buf), get_ack(buf),
               trace_pkt_flag(get_flags(buf), dlen), dlen);
}
/* 窗口事件：记录"段数*TRACE_MSS"，脚本 /1375 后纵轴即段数 */
static void trace_cwnd(int type, uint32_t cwnd_bytes)
{
    trace_emit("CWND", "type:%d size:%u", type, (cwnd_bytes / SMSS) * TRACE_MSS);
}
static void trace_swnd_locked(tju_tcp_t *sock)
{
    sender_window_t *sw = sock->window.wnd_send;
    uint32_t eff = (sw->rwnd < sw->cwnd) ? sw->rwnd : sw->cwnd;
    trace_emit("SWND", "size:%u", (eff / SMSS) * TRACE_MSS);
}
static void trace_rwnd_locked(tju_tcp_t *sock)
{
    receiver_window_t *rw = sock->window.wnd_recv;
    uint32_t used = (uint32_t)sock->received_len + rw->ooo_bytes;
    uint32_t avail = (used >= RECV_BUF_CAP) ? 0 : (RECV_BUF_CAP - used);
    trace_emit("RWND", "size:%u", (avail / SMSS) * TRACE_MSS);
}
static void trace_delv(uint32_t seq, uint32_t size)
{
    trace_emit("DELV", "seq:%u size:%u", seq, size);
}
static void send_out(pkt_t p)
{
    trace_open();
    sendToLayer3(p.buf, p.len);
    trace_pkt("SEND", p.buf); /* 须在 free 前解析 */
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
/* SR 定时器：固定小间隔唤醒检查；数据段超时阈值采用动态 RTO(RFC6298)，
   首个 RTT 样本前用 RTO_INIT_MS，避免在高延迟(如单向300ms/RTT≈600ms)下虚假超时 */
#define SR_TICK_MS 20
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
                /* 选择重传：只重传发送时间真正超过动态RTO的最早若干包。
                   数据段超时阈值 = 已有RTT样本时用Jacobson估计 sw->rto，
                   尚无样本时用 RFC6298 初始 RTO(RTO_INIT_MS=1s)，
                   保证300ms高延迟链路首个RTT内不会被虚假判超时 */
                uint32_t data_rto = sw->rtt_ready ? sw->rto : RTO_INIT_MS;
                pkt_t rpkts[SR_REXMIT_MAX];
                int nrpkt = 0;
                struct timeval now2;
                gettimeofday(&now2, NULL);
                inflight_node_t *cur = sock->inflight_head;
                while (cur != NULL && nrpkt < SR_REXMIT_MAX)
                {
                    uint32_t elapsed = (uint32_t)((now2.tv_sec - cur->send_time.tv_sec) * 1000 +
                                                  (now2.tv_usec - cur->send_time.tv_usec) / 1000);
                    if (elapsed >= data_rto)
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
                {
                    dbg_printf("SR retransmit %d pkts base=%u nextseq=%u\n",
                               nrpkt, sw->base, sw->nextseq);
                    /* Karn算法：超时重传过的段，其ACK不用于RTT采样(重传时刻已刷新send_time，
                       否则会算出偏小的污染样本)；同时避免与快速重传重复触发，NEWACK后清零 */
                    sw->rexmitted = 1;
                    /* 标准Reno RTO响应(RFC5681)：ssthresh=max(FlightSize/2, 2*SMSS)，
                       cwnd 降到 1 个 SMSS 并重新慢启动；同一丢失轮次用 loss_hold 只降一次，
                       NEWACK 后清 loss_hold */
                    if (!sw->loss_hold)
                    {
                        uint32_t flight = sw->nextseq - sw->base; /* FlightSize：已发未累计确认字节 */
                        uint32_t half_flight = flight / 2;
                        sw->ssthresh = (half_flight >= 2 * SMSS) ? half_flight : (2 * SMSS);
                        sw->cwnd = SMSS;          /* 超时后 cwnd 不超过 1 个 SMSS */
                        sw->ca_state = SLOW_START;/* 重新进入慢启动 */
                        sw->ca_inc = 0;
                        sw->loss_hold = 1;
                        /* RFC6298：超时后 RTO 指数退避(×2、上限RTO_MAX_MS)，
                           Karn 算法下重传期间不采样，待下一个干净ACK样本再收敛 */
                        uint32_t backoff = sw->rto * 2;
                        sw->rto = (backoff > RTO_MAX_MS || backoff < sw->rto) ? RTO_MAX_MS : backoff;
                        trace_cwnd(3, sw->cwnd);
                        trace_swnd_locked(sock);
                    }
                }
                /* 锁内按序发送重传段，保证与 flush_send 新段的全局发送顺序一致 */
                for (int i = 0; i < nrpkt; i++)
                {
                    send_out(rpkts[i]);
                    if (i + 1 < nrpkt)
                    {
                        struct timespec pace_ts = {0, PACE_NS};
                        nanosleep(&pace_ts, NULL);
                    }
                }
                pthread_mutex_unlock(&(sock->send_lock));
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
#define MAX_BURST 24
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
    /* 锁内按序发送：nextseq 推进与实际 sendto 必须在同一临界区，杜绝多线程并发时
       "后构建的段抢先发出"造成发送顺序与序号顺序颠倒（会被对端误判为乱序而回 dupACK）。
       段间 pacing 拉开进入 qdisc 的时间戳，避免整窗同刻突发经固定延迟后微乱序。
       UDP sendto 到本地虚拟网卡不阻塞，一批 pacing 持锁仅数 ms，远小于 RTT，不影响接收 */
    for (int i = 0; i < npkt; i++)
    {
        send_out(pkts[i]);
        if (i + 1 < npkt)
        {
            struct timespec pace_ts = {0, PACE_NS};
            nanosleep(&pace_ts, NULL);
        }
    }
    if (npkt > 0)
        dbg_printf("FLUSH sent %d segs, first_seq=%u\n", npkt, first_seq);
    pthread_mutex_unlock(&(sock->send_lock));
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
    sw->cwnd = CWND_INIT;     /* RFC5681 IW=3 SMSS，慢启动起点 */
    sw->ssthresh = SSTH_INIT; /* 初始门限=课程最大接收窗口65535 */
    sw->ca_state = SLOW_START;/* 拥塞控制状态：初始慢启动 */
    sw->ca_inc = 0;
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
    trace_rwnd_locked(sock); /* 应用取走数据，接收可用缓冲区变大 */
    pthread_mutex_unlock(&(sock->recv_lock));
    send_ack(sock);
    return read_len;
}
/* ===================== 接收端按序交付与乱序缓存 ===================== */
static void deliver_segment(tju_tcp_t *sock, uint32_t seq, char *data, uint32_t len)
{
    if (len == 0)
        return;
    char *new_buf = (char *)realloc(sock->received_buf, (size_t)sock->received_len + len);
    if (new_buf == NULL)
        return;
    sock->received_buf = new_buf;
    memcpy(sock->received_buf + sock->received_len, data, len);
    sock->received_len += (int)len;
    sock->window.wnd_recv->expect_seq += len;
    trace_delv(seq, len); /* 按序交付给接收缓冲区 */
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
    uint32_t seq = get_seq(pkt);
    uint32_t end = seq + data_len;
    receiver_window_t *rw = sock->window.wnd_recv;
    pthread_mutex_lock(&(sock->recv_lock));
    if (end <= rw->expect_seq)
    {
        /* 完全落在已按序交付区间内的冗余副本（如重传副本）：不交付、不推进序号，
           也不再回 ACK——避免陈旧/重复 ACK 在发送端被累计成 dupACK 而误触发快重 */
        pthread_mutex_unlock(&(sock->recv_lock));
        return;
    }
    else if ((uint32_t)sock->received_len + rw->ooo_bytes >= RECV_BUF_CAP)
    { /* 接收缓冲满：丢弃，但仍在锁外回带最新通告窗口(可能为0)的 ACK */
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
    trace_rwnd_locked(sock); /* 接收方可用缓冲区变化 */
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
        trace_cwnd(0, sock->window.wnd_send->cwnd); /* 连接建立：初始拥塞窗口 */
        trace_swnd_locked(sock);
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
        trace_cwnd(0, sock->window.wnd_send->cwnd);
        trace_swnd_locked(sock);
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
            /* Karn算法：本轮发生过重传、或处于快恢复中的"部分确认"，都不采样RTT
               （部分确认对应的仍是重传段，其 send_time 被刷新过，采样会得到几ms的假样本）；
               在移除在途节点前取最早包发送时刻 */
            int fr_partial = (sw->ca_state == FAST_RECOVERY &&
                              (int32_t)(ack - sw->recovery_point) < 0);
            int karn_skip = sw->rexmitted || fr_partial;
            struct timeval sample_tv;
            int have_sample = (!karn_skip && sock->inflight_head != NULL);
            if (have_sample)
                sample_tv = sock->inflight_head->send_time;
            sw->base = ack;
            sw->dupack = 0;
            if (!fr_partial)
                sw->rexmitted = 0; /* FR全程保持Karn标记，直到恢复ACK(退出FR)才解除 */
            sw->loss_hold = 0;
            sock->rexmit_count = 0;
            inflight_remove_acked(sock, ack);
            /* RTT 采样与 Jacobson 估计(RFC6298)：结果写回 sw->rto 驱动数据段超时判定；
               Karn 算法下重传轮不采样，sw->rto 保留超时退避值直到出现干净样本 */
            if (have_sample)
            {
                struct timeval anow;
                gettimeofday(&anow, NULL);
                int32_t sample = (int32_t)((anow.tv_sec - sample_tv.tv_sec) * 1000 +
                                           (anow.tv_usec - sample_tv.tv_usec) / 1000);
                if (sample > 0 && sample < 3000)
                {
                    if (!sw->rtt_ready)
                    {
                        sw->srtt = (uint32_t)sample;
                        sw->rttvar = (uint32_t)sample / 2;
                        sw->rtt_ready = 1;
                    }
                    else
                    {
                        int32_t err = sample - (int32_t)sw->srtt;                                   /* Err=Sample-SRTT */
                        sw->srtt = (uint32_t)((int32_t)sw->srtt + err / 8);                        /* SRTT+=Err/8 */
                        int32_t verr = (err >= 0 ? err : -err) - (int32_t)sw->rttvar;              /* |Err|-RTTVAR */
                        sw->rttvar = (uint32_t)((int32_t)sw->rttvar + verr / 4);                   /* RTTVAR+=.../4 */
                    }
                    uint32_t rto_calc = sw->srtt + 4 * sw->rttvar;
                    if (rto_calc < RTO_MIN_MS)
                        rto_calc = RTO_MIN_MS;
                    if (rto_calc > RTO_MAX_MS)
                        rto_calc = RTO_MAX_MS;
                    sw->rto = rto_calc; /* 动态RTO真正用于数据段超时判定 */
                    trace_emit("RTTS", "SampleRTT:%.3f EstimatedRTT:%.3f DeviationRTT:%.3f TimeoutInterval:%.3f",
                               (double)sample, (double)sw->srtt, (double)sw->rttvar, (double)rto_calc);
                }
            }
            /* ===== 基础Reno(RFC5681) 拥塞窗口增长：仅对"累计确认新数据的ACK"执行 ===== */
            int ca_type;
            if (sw->ca_state == FAST_RECOVERY)
            {
                if ((int32_t)(ack - sw->recovery_point) >= 0)
                {
                    /* 恢复ACK：已确认进入快恢复时的全部在途数据(ack≥recovery_point)，
                       cwnd收缩到ssthresh，转入拥塞避免，本轮不再增长 */
                    sw->cwnd = sw->ssthresh;
                    sw->ca_state = CONGESTION_AVOIDANCE;
                    sw->ca_inc = 0;
                    ca_type = 1;
                }
                else
                {
                    /* 部分确认(SR一窗多丢)：仍在快恢复中，窗口维持——不增长、也不重复降窗 */
                    ca_type = 2;
                }
            }
            else if (sw->cwnd < sw->ssthresh)
            {
                /* 慢启动：每个新ACK使 cwnd 增加，单次增量不超过 1 个 SMSS */
                sw->cwnd += SMSS;
                sw->ca_state = SLOW_START;
                ca_type = 0;
                if (sw->cwnd >= sw->ssthresh)
                {
                    /* 增长达到门限即转入拥塞避免；钳到 ssthresh，保证不比Reno更激进 */
                    sw->cwnd = sw->ssthresh;
                    sw->ca_state = CONGESTION_AVOIDANCE;
                    sw->ca_inc = 0;
                }
            }
            else
            {
                /* 拥塞避免：约每RTT增1个SMSS。用 ca_inc 累加 SMSS^2/cwnd 的整数余数，
                   攒够一个SMSS才增长，避免"不足1字节也+1"而比RFC5681更激进 */
                sw->ca_state = CONGESTION_AVOIDANCE;
                sw->ca_inc += (uint32_t)(((uint64_t)SMSS * SMSS) / sw->cwnd);
                if (sw->ca_inc >= SMSS)
                {
                    sw->cwnd += SMSS;
                    sw->ca_inc -= SMSS;
                }
                ca_type = 1;
            }
            /* 标准Reno不设cwnd硬上限：实际在途量由 flush_send 中 min(rwnd,cwnd) 约束 */
            trace_cwnd(ca_type, sw->cwnd);
            trace_swnd_locked(sock);
            dbg_printf("NEWACK ack=%u base=%u nextseq=%u send_len=%d rwnd=%u cwnd=%u\n",
                       ack, sw->base, sw->nextseq, sock->sending_len, adv, sw->cwnd);
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
                if (sw->ca_state != FAST_RECOVERY)
                {
                    /* 三次重复ACK的标准Reno响应(RFC5681)：一次拥塞事件只降一次窗。
                       ssthresh=max(FlightSize/2,2*SMSS)，cwnd=ssthresh，进入快速恢复，
                       记录恢复点 recovery_point=当前SND.NXT；FR期间不再重复降窗。
                       待 ACK≥recovery_point(恢复ACK)后 cwnd=ssthresh 转入拥塞避免 */
                    uint32_t fflight = sw->nextseq - sw->base; /* FlightSize */
                    uint32_t fhalf = fflight / 2;
                    sw->ssthresh = (fhalf >= 2 * SMSS) ? fhalf : (2 * SMSS);
                    sw->cwnd = sw->ssthresh;
                    sw->recovery_point = sw->nextseq;
                    sw->ca_state = FAST_RECOVERY;
                    sw->ca_inc = 0;
                    dbg_printf("  enter-FR ssthresh=%u recover=%u\n", sw->ssthresh, sw->recovery_point);
                    trace_cwnd(2, sw->cwnd);
                    trace_swnd_locked(sock);
                }
                /* 锁内按序发送快重段，发完再释放锁；flush_send 自行加锁补发新段，
                   保证快重旧段与新段的全局发送顺序、不与其他线程的发送交错颠倒 */
                for (int i = 0; i < nfpkt; i++)
                {
                    send_out(fpkts[i]);
                    if (i + 1 < nfpkt)
                    {
                        struct timespec pace_ts = {0, PACE_NS};
                        nanosleep(&pace_ts, NULL);
                    }
                }
                pthread_mutex_unlock(&(sock->send_lock));
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
    trace_open();
    uint8_t flags = get_flags(pkt);
    uint32_t data_len = get_plen(pkt) - get_hlen(pkt);
    trace_pkt("RECV", pkt);
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

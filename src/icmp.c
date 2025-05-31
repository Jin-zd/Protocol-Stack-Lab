#include "icmp.h"

#include "ip.h"
#include "net.h"

#include <stdio.h>

// PING相关全局变量
#define MAX_PING_ENTRIES 10
static ping_entry_t ping_table[MAX_PING_ENTRIES];
static ping_stats_t ping_stats = {0, 0, 0.0, 0.0, 0.0};
static uint16_t ping_id = 1;
static uint16_t ping_seq = 1;

// 查找PING表项
static ping_entry_t* find_ping_entry(uint16_t id, uint16_t seq) {
    for (int i = 0; i < MAX_PING_ENTRIES; i++) {
        if (ping_table[i].id == id && ping_table[i].seq == seq && !ping_table[i].replied) {
            return &ping_table[i];
        }
    }
    return NULL;
}

// 添加PING表项
static ping_entry_t* add_ping_entry(uint8_t *dst_ip, uint16_t id, uint16_t seq) {
    for (int i = 0; i < MAX_PING_ENTRIES; i++) {
        if (ping_table[i].id == 0 || ping_table[i].replied) {
            memcpy(ping_table[i].dst_ip, dst_ip, NET_IP_LEN);
            ping_table[i].id = id;
            ping_table[i].seq = seq;
            ping_table[i].send_time = time(NULL);
            ping_table[i].replied = 0;
            return &ping_table[i];
        }
    }
    return NULL;
}

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // TO-DO
    buf_init(&txbuf, req_buf->len);
    memcpy(txbuf.data, req_buf->data, req_buf->len);

    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;
    icmp_hdr->code = 0;

    icmp_hdr->checksum16 = 0;
    uint16_t checksum = checksum16((uint16_t *)txbuf.data, txbuf.len);
    icmp_hdr->checksum16 = checksum;

    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    if (buf->len < sizeof(icmp_hdr_t)) {
        return;
    }
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;
    
    if (icmp_hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        icmp_resp(buf, src_ip);
    } else if (icmp_hdr->type == ICMP_TYPE_ECHO_REPLY) {        // 处理PING回复
        uint16_t id = swap16(icmp_hdr->id16);
        uint16_t seq = swap16(icmp_hdr->seq16);
        
        ping_entry_t *entry = find_ping_entry(id, seq);
        if (entry != NULL) {
            entry->replied = 1;
            ping_stats.received++;
            
            // 计算响应时间（简化版本，实际应使用更精确的时间测量）
            double rtt_ms = (time(NULL) - entry->send_time) * 1000.0;
            
            // 更新统计信息
            if (ping_stats.received == 1) {
                ping_stats.min_time = rtt_ms;
                ping_stats.max_time = rtt_ms;
            } else {
                if (rtt_ms < ping_stats.min_time) ping_stats.min_time = rtt_ms;
                if (rtt_ms > ping_stats.max_time) ping_stats.max_time = rtt_ms;
            }
            ping_stats.total_time += rtt_ms;
            
            // 打印PING结果
            printf("64 bytes from %s: icmp_seq=%d time=%.0fms\n", 
                   iptos(src_ip), seq, rtt_ms);
        }
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // TO-DO
    buf_init(&txbuf, sizeof(ip_hdr_t) + sizeof(icmp_hdr_t));
    memcpy(txbuf.data, recv_buf->data, txbuf.len);

    buf_add_header(&txbuf, sizeof(icmp_hdr_t));
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;

    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;

    icmp_hdr->checksum16 = 0;
    uint16_t checksum = checksum16((uint16_t *)txbuf.data, txbuf.len);
    icmp_hdr->checksum16 = checksum;

    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
    // 初始化PING表
    memset(ping_table, 0, sizeof(ping_table));
}

/**
 * @brief 发送ICMP回显请求（PING）
 *
 * @param dst_ip 目标IP地址
 * @return int 成功返回0，失败返回-1
 */
int icmp_ping_request(uint8_t *dst_ip) {
    // 创建ICMP数据包
    buf_init(&txbuf, sizeof(icmp_hdr_t) + 32);  // 32字节数据
    
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_ECHO_REQUEST;
    icmp_hdr->code = 0;
    icmp_hdr->id16 = swap16(ping_id);
    icmp_hdr->seq16 = swap16(ping_seq);
    
    // 填充数据
    for (int i = 0; i < 32; i++) {
        txbuf.data[sizeof(icmp_hdr_t) + i] = (uint8_t)(i + 0x20);
    }
    
    // 添加到PING表
    ping_entry_t *entry = add_ping_entry(dst_ip, ping_id, ping_seq);
    if (entry == NULL) {
        printf("PING table full\n");
        return -1;
    }
    
    // 计算校验和
    icmp_hdr->checksum16 = 0;
    uint16_t checksum = checksum16((uint16_t *)txbuf.data, txbuf.len);
    icmp_hdr->checksum16 = checksum;
    
    // 发送数据包
    ip_out(&txbuf, dst_ip, NET_PROTOCOL_ICMP);
      ping_stats.sent++;
    printf("Request sent to %s: icmp_seq=%d\n", iptos(dst_ip), ping_seq);
    
    ping_seq++;
    return 0;
}

/**
 * @brief 处理PING超时
 */
void icmp_ping_process() {
    time_t current_time = time(NULL);
    
    for (int i = 0; i < MAX_PING_ENTRIES; i++) {
        if (ping_table[i].id != 0 && !ping_table[i].replied) {
            // 检查超时（5秒超时）
            if (current_time - ping_table[i].send_time > 5) {
                printf("Request timeout for icmp_seq %d\n", ping_table[i].seq);
                ping_table[i].replied = 1;  // 标记为已处理
            }
        }
    }
}

/**
 * @brief 打印PING统计信息
 */
void icmp_ping_print_stats() {
    printf("\n--- PING Statistics ---\n");
    printf("%d packets transmitted, %d received, %.1f%% packet loss\n",
           ping_stats.sent, ping_stats.received,
           ping_stats.sent > 0 ? (100.0 * (ping_stats.sent - ping_stats.received) / ping_stats.sent) : 0.0);
    
    if (ping_stats.received > 0) {
        double avg_time = ping_stats.total_time / ping_stats.received;
        printf("round-trip min/avg/max = %.1f/%.1f/%.1f ms\n",
               ping_stats.min_time, avg_time, ping_stats.max_time);
    }
}
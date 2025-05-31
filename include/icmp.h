#ifndef ICMP_H
#define ICMP_H

#include "net.h"

#pragma pack(1)
typedef struct icmp_hdr {
    uint8_t type;         // 类型
    uint8_t code;         // 代码
    uint16_t checksum16;  // ICMP报文的校验和
    uint16_t id16;        // 标识符
    uint16_t seq16;       // 序号
} icmp_hdr_t;

#pragma pack()
typedef enum icmp_type {
    ICMP_TYPE_ECHO_REQUEST = 8,  // 回显请求
    ICMP_TYPE_ECHO_REPLY = 0,    // 回显响应
    ICMP_TYPE_UNREACH = 3,       // 目的不可达
} icmp_type_t;

typedef enum icmp_code {
    ICMP_CODE_PROTOCOL_UNREACH = 2,  // 协议不可达
    ICMP_CODE_PORT_UNREACH = 3       // 端口不可达
} icmp_code_t;

// PING请求记录结构
typedef struct ping_entry {
    uint8_t dst_ip[NET_IP_LEN];    // 目标IP地址
    uint16_t id;                   // ICMP标识符
    uint16_t seq;                  // 序列号
    time_t send_time;              // 发送时间戳
    int replied;                   // 是否已收到回复
} ping_entry_t;

// PING统计信息
typedef struct ping_stats {
    int sent;                      // 发送数量
    int received;                  // 接收数量
    double min_time;               // 最小响应时间(ms)
    double max_time;               // 最大响应时间(ms) 
    double total_time;             // 总响应时间(ms)
} ping_stats_t;

void icmp_in(buf_t *buf, uint8_t *src_ip);
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code);
void icmp_init();

// PING相关函数
int icmp_ping_request(uint8_t *dst_ip);
void icmp_ping_process();
void icmp_ping_print_stats();
#endif

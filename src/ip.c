#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    if (buf->len < sizeof(ip_hdr_t)) {
        return;
    }    
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    
    // 检查目标IP是否是本机IP或回环地址
    int is_for_me = (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) == 0) ||
                    (ip_hdr->dst_ip[0] == 127 && ip_hdr->dst_ip[1] == 0 && 
                     ip_hdr->dst_ip[2] == 0 && ip_hdr->dst_ip[3] == 1);
    
    if (ip_hdr->version != IP_VERSION_4 || swap16(ip_hdr->total_len16) > buf->len || !is_for_me) {
        return;
    }

    uint16_t hdr_checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    uint16_t checksum = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    if (hdr_checksum != checksum) {
        return;
    }
    ip_hdr->hdr_checksum16 = hdr_checksum;

    if (buf->len > swap16(ip_hdr->total_len16)) {
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));
    }

    buf_remove_header(buf, sizeof(ip_hdr_t));

    if (net_in(buf, ip_hdr->protocol, ip_hdr->src_ip) < 0) {
        buf_add_header(buf, sizeof(ip_hdr_t));
        memcpy(buf->data, ip_hdr, sizeof(ip_hdr_t));
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;

    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = 5;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->ttl = 64;
    ip_hdr->id16 = swap16(id);
    ip_hdr->flags_fragment16 = swap16(offset | mf);
    ip_hdr->protocol = protocol;
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);

    ip_hdr->hdr_checksum16 = 0;
    uint16_t checksum = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    ip_hdr->hdr_checksum16 = checksum;

    arp_out(buf, ip);
}


int id = 0;
/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    
    // 检查是否是ping自己(loopback处理)
    if (memcmp(ip, net_if_ip, NET_IP_LEN) == 0 || 
        (ip[0] == 127 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1)) {
        // 创建临时缓冲区添加IP头部
        buf_t loopback_buf;
        buf_init(&loopback_buf, buf->len + sizeof(ip_hdr_t));
        
        // 复制原始数据
        memcpy(loopback_buf.data + sizeof(ip_hdr_t), buf->data, buf->len);
        
        // 构造IP头部
        ip_hdr_t *ip_hdr = (ip_hdr_t *)loopback_buf.data;
        ip_hdr->version = IP_VERSION_4;
        ip_hdr->hdr_len = 5;
        ip_hdr->tos = 0;
        ip_hdr->total_len16 = swap16(loopback_buf.len);
        ip_hdr->ttl = 64;
        id++;
        ip_hdr->id16 = swap16(id);
        ip_hdr->flags_fragment16 = 0;
        ip_hdr->protocol = protocol;
        memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
        memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
        
        ip_hdr->hdr_checksum16 = 0;
        uint16_t checksum = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
        ip_hdr->hdr_checksum16 = checksum;
          // 直接调用ip_in处理（模拟收到自己发送的包）
        ip_in(&loopback_buf, net_if_mac);
        return;
    }
    
    int max_payload_len = 1480;
    int offset = 0;

    
    while(buf->len > max_payload_len) {
        buf_t ip_buf;
        buf_init(&ip_buf, max_payload_len);
        memcpy(ip_buf.data, buf->data, max_payload_len);
        buf_remove_header(buf, max_payload_len);

        ip_fragment_out(&ip_buf, ip, protocol, id, offset, IP_MORE_FRAGMENT);
        
        offset += max_payload_len / 8;
    }
    
    buf_t ip_buf;
    buf_init(&ip_buf, buf->len);
    memcpy(ip_buf.data, buf->data, buf->len);
    ip_fragment_out(&ip_buf, ip, protocol, id, offset, 0);
    id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}
#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

#ifdef _WIN32
#include <winsock2.h>  // 提供网络字节序转换函数 htons, htonl, ntohs, ntohl
#else
#include <arpa/inet.h>  // 在非Windows系统提供网络字节序转换函数
#endif

// IPv4映射的IPv6地址前缀 (::FFFF:0:0/96)
const uint8_t IPV4_MAPPED_PREFIX[NET_IP6_LEN] = {
    0x00, 0x00, 0x00, 0x00,  // 10字节的0
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0xff, 0xff,  // 0:0:0:0:0:0:FFFF:
    0x00, 0x00, 0x00, 0x00   // IPv4地址位置
};

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
    if (ip_hdr->version != IP_VERSION_4 || swap16(ip_hdr->total_len16) > buf->len || memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
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

/**
 * @brief 处理一个收到的IPv6数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip6_in(buf_t *buf, uint8_t *src_mac) {
    if (buf->len < sizeof(ip6_hdr_t)) {
        return;
    }

    ip6_hdr_t *ip6_hdr = (ip6_hdr_t *)buf->data;
    
    // 检查版本号（版本号在最高的4位）
    uint8_t version = (ntohl(ip6_hdr->version_tc_flowlabel) >> 28) & 0xF;
    if (version != IP_VERSION_6) {
        return;
    }
    
    // 检查数据包长度
    uint16_t payload_len = ntohs(ip6_hdr->payload_len);
    if (payload_len + sizeof(ip6_hdr_t) > buf->len) {
        return;
    }
    
    // 检查目标地址是否是本机地址
    if (memcmp(ip6_hdr->dst_ip, net_if_ip6, NET_IP6_LEN) != 0) {
        // 不是发给本机的IPv6地址
        // 检查是否是IPv4映射地址
        uint8_t ipv4_addr[NET_IP_LEN];
        if (is_ip4_mapped_ip6(ip6_hdr->dst_ip) && 
            ip6_to_ip4_addr(ip6_hdr->dst_ip, ipv4_addr) && 
            memcmp(ipv4_addr, net_if_ip, NET_IP_LEN) == 0) {
            // 是发给本机IPv4的映射地址
        } else {
            return;
        }
    }
    
    // 移除IPv6头部
    buf_remove_header(buf, sizeof(ip6_hdr_t));
    
    // 获取下一个头部（相当于IPv4的协议字段）
    uint8_t next_header = ip6_hdr->next_header;
    
    // 调用上层协议处理
    uint8_t src_ip6[NET_IP6_LEN];
    memcpy(src_ip6, ip6_hdr->src_ip, NET_IP6_LEN);
      // 使用net_in6函数处理IPv6数据包
    if (net_in6(buf, next_header, src_ip6) < 0) {
        // 上层协议无法处理，可以考虑发送ICMPv6错误消息
        // TODO: 实现ICMPv6协议
        return;
    }
}

/**
 * @brief 处理一个要发送的IPv6数据包
 *
 * @param buf 要处理的包
 * @param ip6 目标IPv6地址
 * @param protocol 上层协议
 */
void ip6_out(buf_t *buf, uint8_t *ip6, net_protocol_t protocol) {
    // 检查数据包大小，确保不超过以太网MTU减去IPv6头部大小
    int max_payload_len = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip6_hdr_t);
    if (buf->len > max_payload_len) {
        // 超过最大传输单元，截断数据包
        buf->len = max_payload_len;
    }
    
    // 保存原始负载长度
    uint16_t payload_len = buf->len;
    
    // 添加IPv6头部
    buf_add_header(buf, sizeof(ip6_hdr_t));
    ip6_hdr_t *ip6_hdr = (ip6_hdr_t *)buf->data;
    
    // 设置版本号(4位)、流量类别(8位)、流标签(20位)
    // 版本号为6，其他设为0
    uint32_t version_tc_flowlabel = IP_VERSION_6 << 28;
    ip6_hdr->version_tc_flowlabel = htonl(version_tc_flowlabel);
    
    // 设置有效载荷长度（不包括IPv6头部）
    ip6_hdr->payload_len = htons(payload_len);
    
    // 设置下一个头部（协议类型）
    ip6_hdr->next_header = protocol;
      // 设置跳数限制
    ip6_hdr->hop_limit = IP6_DEFAULT_HOP_LIMIT;

    // 设置源地址和目标地址
    memcpy(ip6_hdr->src_ip, net_if_ip6, NET_IP6_LEN);
    memcpy(ip6_hdr->dst_ip, ip6, NET_IP6_LEN);
    
    // IPv6应该使用邻居发现协议，但这里简化处理
    // 对于IPv4映射地址，提取IPv4地址并使用ARP
#ifndef TEST
    uint8_t ipv4_addr[NET_IP_LEN];
    if (is_ip4_mapped_ip6(ip6) && ip6_to_ip4_addr(ip6, ipv4_addr)) {
        // 是IPv4映射地址，使用ARP
        arp_out(buf, ipv4_addr);
    } else {
        // 纯IPv6地址，简化处理：使用广播MAC地址
        // 在实际应用中应该实现邻居发现协议
        uint8_t broadcast_mac[NET_MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        ethernet_out(buf, broadcast_mac, NET_PROTOCOL_IP6);
    }
#endif
}

/**
 * @brief 初始化IPv6协议
 */
void ip6_init() {
    net_add_protocol(NET_PROTOCOL_IP6, ip6_in);
}

/**
 * @brief 将IPv4地址转换为IPv4映射的IPv6地址
 * 
 * @param ip4_addr IPv4地址 (4字节)
 * @param ip6_addr 输出的IPv6地址 (16字节)
 * @return int 1表示成功，0表示失败
 */
int ip4_to_ip6_addr(const uint8_t *ip4_addr, uint8_t *ip6_addr) {
    if (!ip4_addr || !ip6_addr) {
        return 0;
    }
    
    // 复制IPv4映射IPv6地址前缀
    memcpy(ip6_addr, IPV4_MAPPED_PREFIX, NET_IP6_LEN);
    
    // 复制IPv4地址到最后4个字节
    memcpy(ip6_addr + 12, ip4_addr, NET_IP_LEN);
    
    return 1;
}

/**
 * @brief 检查IPv6地址是否是IPv4映射地址
 * 
 * @param ip6_addr IPv6地址 (16字节)
 * @return int 1表示是IPv4映射地址，0表示不是
 */
int is_ip4_mapped_ip6(const uint8_t *ip6_addr) {
    if (!ip6_addr) {
        return 0;
    }
    
    // 检查前10个字节是否为0
    for (int i = 0; i < 10; i++) {
        if (ip6_addr[i] != 0) {
            return 0;
        }
    }
    
    // 检查第11、12字节是否为0xFF
    if (ip6_addr[10] != 0xFF || ip6_addr[11] != 0xFF) {
        return 0;
    }
    
    // 是IPv4映射的IPv6地址
    return 1;
}

/**
 * @brief 从IPv4映射的IPv6地址中提取IPv4地址
 * 
 * @param ip6_addr IPv6地址 (16字节)
 * @param ip4_addr 输出的IPv4地址 (4字节)
 * @return int 1表示成功，0表示失败或不是IPv4映射地址
 */
int ip6_to_ip4_addr(const uint8_t *ip6_addr, uint8_t *ip4_addr) {
    if (!ip6_addr || !ip4_addr) {
        return 0;
    }
    
    // 检查是否是IPv4映射的IPv6地址
    if (!is_ip4_mapped_ip6(ip6_addr)) {
        return 0;
    }
    
    // 复制最后4个字节作为IPv4地址
    memcpy(ip4_addr, ip6_addr + 12, NET_IP_LEN);
    
    return 1;
}
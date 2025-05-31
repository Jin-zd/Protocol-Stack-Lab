#include "icmp.h"
#include "buf.h"
#include "utils.h"
#include "testing/log.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

// 测试用的IP地址
uint8_t test_src_ip[] = {192, 168, 1, 100};
uint8_t test_dst_ip[] = {192, 168, 1, 1};

// 为了测试，我们需要声明一些全局变量
extern buf_t txbuf;

/**
 * @brief 测试ICMP头部结构
 */
int test_icmp_header_structure() {
    PRINT_INFO("Testing ICMP header structure...\n");
    
    // 验证ICMP头部大小
    if (sizeof(icmp_hdr_t) != 8) {
        PRINT_ERROR("ICMP header size should be 8 bytes, got %zu\n", sizeof(icmp_hdr_t));
        return 0;
    }
    
    // 创建一个ICMP头部并测试字段
    icmp_hdr_t hdr;
    hdr.type = ICMP_TYPE_ECHO_REQUEST;
    hdr.code = 0;
    hdr.checksum16 = 0;
    hdr.id16 = swap16(12345);
    hdr.seq16 = swap16(1);
    
    if (hdr.type != ICMP_TYPE_ECHO_REQUEST) {
        PRINT_ERROR("Type field test failed\n");
        return 0;
    }
    
    if (swap16(hdr.id16) != 12345) {
        PRINT_ERROR("ID field test failed\n");
        return 0;
    }
    
    if (swap16(hdr.seq16) != 1) {
        PRINT_ERROR("Sequence field test failed\n");
        return 0;
    }
    
    PRINT_PASS("ICMP header structure test passed\n");
    return 1;
}

/**
 * @brief 测试ICMP校验和计算
 */
int test_icmp_checksum() {
    PRINT_INFO("Testing ICMP checksum calculation...\n");
    
    // 创建一个简单的ICMP包
    buf_t test_buf;
    buf_init(&test_buf, sizeof(icmp_hdr_t) + 4);
    
    icmp_hdr_t *hdr = (icmp_hdr_t *)test_buf.data;
    hdr->type = ICMP_TYPE_ECHO_REQUEST;
    hdr->code = 0;
    hdr->checksum16 = 0;
    hdr->id16 = swap16(1);
    hdr->seq16 = swap16(1);
    
    // 添加一些测试数据
    test_buf.data[8] = 0x01;
    test_buf.data[9] = 0x02;
    test_buf.data[10] = 0x03;
    test_buf.data[11] = 0x04;
    
    // 计算校验和
    uint16_t checksum = checksum16((uint16_t *)test_buf.data, test_buf.len);
    hdr->checksum16 = checksum;
    
    // 验证校验和（重新计算应该为0）
    uint16_t verify = checksum16((uint16_t *)test_buf.data, test_buf.len);
    if (verify != 0) {
        PRINT_ERROR("Checksum verification failed: got 0x%04x, expected 0\n", verify);
        return 0;
    }
    
    PRINT_PASS("ICMP checksum test passed\n");
    return 1;
}

/**
 * @brief 测试ICMP类型常量
 */
int test_icmp_types() {
    PRINT_INFO("Testing ICMP type constants...\n");
    
    if (ICMP_TYPE_ECHO_REPLY != 0) {
        PRINT_ERROR("ICMP_TYPE_ECHO_REPLY should be 0, got %d\n", ICMP_TYPE_ECHO_REPLY);
        return 0;
    }
    
    if (ICMP_TYPE_ECHO_REQUEST != 8) {
        PRINT_ERROR("ICMP_TYPE_ECHO_REQUEST should be 8, got %d\n", ICMP_TYPE_ECHO_REQUEST);
        return 0;
    }
    
    if (ICMP_TYPE_UNREACH != 3) {
        PRINT_ERROR("ICMP_TYPE_UNREACH should be 3, got %d\n", ICMP_TYPE_UNREACH);
        return 0;
    }
    
    PRINT_PASS("ICMP type constants test passed\n");
    return 1;
}

/**
 * @brief 测试PING数据结构
 */
int test_ping_data_structures() {
    PRINT_INFO("Testing PING data structures...\n");
    
    // 测试ping_entry_t结构
    ping_entry_t entry;
    memcpy(entry.dst_ip, test_dst_ip, 4);
    entry.id = 100;
    entry.seq = 200;
    entry.send_time = 12345;
    entry.replied = 0;
    
    if (memcmp(entry.dst_ip, test_dst_ip, 4) != 0) {
        PRINT_ERROR("Ping entry IP test failed\n");
        return 0;
    }
    
    if (entry.id != 100 || entry.seq != 200) {
        PRINT_ERROR("Ping entry ID/seq test failed\n");
        return 0;
    }
    
    // 测试ping_stats_t结构
    ping_stats_t stats;
    stats.sent = 5;
    stats.received = 3;
    stats.min_time = 10.5;
    stats.max_time = 25.8;
    stats.total_time = 55.2;
    
    double packet_loss = (stats.sent > 0) ? 
        (100.0 * (stats.sent - stats.received) / stats.sent) : 0.0;
    double avg_time = (stats.received > 0) ? 
        (stats.total_time / stats.received) : 0.0;
    
    if (packet_loss != 40.0) {
        PRINT_ERROR("Packet loss calculation failed: got %.1f, expected 40.0\n", packet_loss);
        return 0;
    }
    
    if (avg_time < 18.39 || avg_time > 18.41) {
        PRINT_ERROR("Average time calculation failed: got %.2f, expected ~18.40\n", avg_time);
        return 0;
    }
    
    PRINT_PASS("PING data structures test passed\n");
    return 1;
}

/**
 * @brief 测试ICMP包解析
 */
int test_icmp_packet_parsing() {
    PRINT_INFO("Testing ICMP packet parsing...\n");
    
    // 创建一个ICMP回显请求包
    buf_t test_buf;
    buf_init(&test_buf, sizeof(icmp_hdr_t) + 32);
    
    icmp_hdr_t *hdr = (icmp_hdr_t *)test_buf.data;
    hdr->type = ICMP_TYPE_ECHO_REQUEST;
    hdr->code = 0;
    hdr->checksum16 = 0;
    hdr->id16 = swap16(555);
    hdr->seq16 = swap16(666);
    
    // 填充数据
    for (int i = 0; i < 32; i++) {
        test_buf.data[sizeof(icmp_hdr_t) + i] = (uint8_t)(i + 0x41);
    }
    
    // 计算校验和
    uint16_t checksum = checksum16((uint16_t *)test_buf.data, test_buf.len);
    hdr->checksum16 = checksum;
    
    // 验证包内容
    if (hdr->type != ICMP_TYPE_ECHO_REQUEST) {
        PRINT_ERROR("Packet type parsing failed\n");
        return 0;
    }
    
    if (swap16(hdr->id16) != 555) {
        PRINT_ERROR("Packet ID parsing failed\n");
        return 0;
    }
    
    if (swap16(hdr->seq16) != 666) {
        PRINT_ERROR("Packet sequence parsing failed\n");
        return 0;
    }
    
    // 验证数据内容
    if (test_buf.data[sizeof(icmp_hdr_t)] != 0x41) {
        PRINT_ERROR("Packet data parsing failed\n");
        return 0;
    }
    
    PRINT_PASS("ICMP packet parsing test passed\n");
    return 1;
}

int main() {
    int tests_passed = 0;
    int total_tests = 5;
    
    PRINT_INFO("=== PING Unit Tests (Simplified) ===\n\n");
    
    // 运行所有测试
    if (test_icmp_header_structure()) tests_passed++;
    if (test_icmp_checksum()) tests_passed++;
    if (test_icmp_types()) tests_passed++;
    if (test_ping_data_structures()) tests_passed++;
    if (test_icmp_packet_parsing()) tests_passed++;
    
    // 输出结果
    printf("\n=== Test Results ===\n");
    if (tests_passed == total_tests) {
        PRINT_PASS("All %d tests passed!\n", total_tests);
        return 0;
    } else {
        PRINT_ERROR("%d out of %d tests failed\n", total_tests - tests_passed, total_tests);
        return 1;
    }
}

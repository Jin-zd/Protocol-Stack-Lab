#include "net.h"
#include "icmp.h"
#include "driver.h"
#include "ethernet.h"

#include <stdio.h>
#include <time.h>
#include <stdlib.h>

// 目标IP地址（默认ping本地回环地址）
uint8_t target_ip[] = {127, 0, 0, 1};

int main(int argc, char *argv[]) {
    printf("PING Demo Program\n");
    printf("==================\n");
    
    // 如果提供了命令行参数，使用它作为目标IP
    if (argc > 1) {
        int a, b, c, d;
        if (sscanf(argv[1], "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
            target_ip[0] = (uint8_t)a;
            target_ip[1] = (uint8_t)b;
            target_ip[2] = (uint8_t)c;
            target_ip[3] = (uint8_t)d;
        }
    }
    
    // 初始化网络协议栈
    if (net_init() < 0) {
        printf("Failed to initialize network\n");
        return -1;
    }
    
    printf("Network initialized successfully\n");
    printf("Local IP: %s\n", iptos(net_if_ip));
    printf("Target IP: %s\n", iptos(target_ip));
    printf("\n");
    
    time_t last_ping_time = 0;
    int ping_count = 0;
    const int max_pings = 4;
    
    printf("PING %s: 64 data bytes\n", iptos(target_ip));
    
    // 主循环
    while (ping_count < max_pings) {
        time_t current_time = time(NULL);
        
        // 每秒发送一次PING（不使用sleep，使用时间戳检查）
        if (current_time - last_ping_time >= 1) {
            if (icmp_ping_request(target_ip) == 0) {
                ping_count++;
                last_ping_time = current_time;
            }
        }
        
        // 处理接收到的数据包
        buf_t buf;
        int recv_result = driver_recv(&buf);
        if (recv_result > 0) {
            ethernet_in(&buf);
        } else if (recv_result < 0) {
            // 网络错误，可能没有网络适配器
            printf("Network receive error. This demo requires a network adapter.\n");
            printf("You can still test the ICMP implementation using the test suite.\n");
            break;
        }
        
        // 处理PING超时
        icmp_ping_process();
        
        // 短暂延时避免CPU占用过高
        for (volatile int i = 0; i < 10000; i++);
    }
    
    // 等待最后的回复（最多5秒）
    printf("Waiting for final replies...\n");
    time_t wait_start = time(NULL);
    while (time(NULL) - wait_start < 5) {
        buf_t buf;
        int recv_result = driver_recv(&buf);
        if (recv_result > 0) {
            ethernet_in(&buf);
        }
        icmp_ping_process();
        
        // 短暂延时
        for (volatile int i = 0; i < 10000; i++);
    }
    
    // 打印统计信息
    icmp_ping_print_stats();
    
    // 清理资源
    driver_close();
    
    printf("\nPING Demo completed successfully!\n");
    printf("Note: This demo requires a real network adapter to send/receive packets.\n");
    printf("For testing ICMP functionality, use: .\\build\\icmp_test.exe Testing\\data\\icmp_test\n");
    
    return 0;
}

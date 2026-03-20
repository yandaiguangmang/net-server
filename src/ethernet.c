#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
   if(buf->len<sizeof(ether_hdr_t))
   {
    return;//不予处理，丢弃
   }

ether_hdr_t *hdr = (ether_hdr_t *)buf->data;// 先提取以太网头信息
uint16_t protocol = swap16(hdr->protocol16);  // 获取协议类型

   uint8_t src_mac[NET_MAC_LEN];
 memcpy(src_mac, hdr->src, NET_MAC_LEN);  // 从帧头提取源MAC
   
   buf_remove_header(buf,sizeof(ether_hdr_t));//移除以太网包头
   net_in(buf,protocol,src_mac);

}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    
    if(buf->len<46) 
     {
        int padlen=46-(buf->len);
        buf_add_padding(buf,padlen);
    }//不足46字节填充0
    buf_add_header(buf,sizeof(ether_hdr_t));
    ether_hdr_t *hdr=(ether_hdr_t *)buf->data;
    //添加以太网包头
    memcpy(hdr->dst,mac,NET_MAC_LEN);//添加目的
    uint8_t src_mac[NET_MAC_LEN]=NET_IF_MAC;
    memcpy(hdr->src,src_mac,NET_MAC_LEN);//添加源mac
   
   hdr->protocol16 =swap16(protocol);//设置协议类型
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}

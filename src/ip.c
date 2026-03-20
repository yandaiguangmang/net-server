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
    if(buf->len<sizeof(ip_hdr_t)){return;}//太短。丢弃
    ip_hdr_t* iphdr=(ip_hdr_t *)buf->data;
    if(iphdr->version!=IP_VERSION_4||swap16(iphdr->total_len16)>buf->len)//版本号是否为ipv4,长度是否正常
    {
          return;//不正常丢弃
    }
 
    


    uint16_t sum=iphdr->hdr_checksum16;
    iphdr->hdr_checksum16=0;
    size_t len=iphdr->hdr_len*4;//头部长度，以字节为单位
   uint16_t answer= checksum16((uint16_t*)iphdr,len);
 

   if(answer!=sum) return;//丢弃
   iphdr->hdr_checksum16=sum;//恢复原来的值



   if(memcmp(iphdr->dst_ip,net_if_ip,NET_IP_LEN)!=0)
   {
    return;//丢弃
   }
    uint16_t total_len = swap16(iphdr->total_len16);// Step5: 去除填充字段
   if(buf->len>total_len)
   {
    buf_remove_padding(buf,(size_t)buf->len-total_len);
   }//去除填充字段
       // 保存协议类型
    uint8_t proto = iphdr->protocol;
uint8_t *src_ip = iphdr->src_ip;  // 获取源IP地址
   buf_remove_header(buf,sizeof(ip_hdr_t));//去除ip报头
  
   

   if(net_in(buf,proto,src_ip)==-1)
   {

     buf_add_header(buf, sizeof(ip_hdr_t));
        memcpy(buf->data, iphdr, sizeof(ip_hdr_t));
           icmp_unreachable(buf,iphdr->src_ip,ICMP_CODE_PROTOCOL_UNREACH);
   }//不可达


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
    buf_add_header(buf,sizeof(ip_hdr_t));//增加 IP 数据报头部缓存空间，为后续填写头部信息做准备。
    ip_hdr_t* hdr=(ip_hdr_t*)buf->data;

hdr->ttl = 64; 
    hdr->hdr_len = 5;
    hdr->protocol=protocol;
    hdr->version=IP_VERSION_4;
     hdr->total_len16 = swap16(buf->len);
 hdr->id16 = swap16(id);
hdr->tos = 0; // 默认服务类型
memcpy(hdr->dst_ip,ip,NET_IP_LEN);
     memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
// 设置标志和分片偏移
    uint16_t flags_fragment = offset  & 0x1FFF; // 13位分片偏移
    if(mf) {
        flags_fragment |= IP_MORE_FRAGMENT;
    }
    hdr->flags_fragment16 = swap16(flags_fragment);

    

    hdr->hdr_checksum16=0;
    uint16_t sum=checksum16((uint16_t*)hdr,(hdr->hdr_len)*4);
    hdr->hdr_checksum16=sum;
  
    arp_out(buf,ip);


}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    size_t sizeframme=(size_t)(1500-sizeof(ip_hdr_t));
 static uint16_t id_counter = 0; 
 uint16_t id = id_counter++;  // 统一使用计数器
 sizeframme=(sizeframme/8)*8;
    if(buf->len<=sizeframme)
    {
         ip_fragment_out(buf,ip,protocol,id,0,0);
          return;// 如果不需要分片，直接发送
    }

    //大于最大负载包长需要分片
    uint16_t offset = 0;

 while(offset < buf->len) {
        buf_t bufip;
        size_t fragment_size = buf->len - offset;
        if(fragment_size > sizeframme) {
            fragment_size = sizeframme;
        }
        
        // 初始化分片缓冲区
        buf_init(&bufip, fragment_size);
        // 拷贝数据
        memcpy(bufip.data, buf->data + offset, fragment_size);
        
        // 判断是否是最后一个分片
        int mf = (offset + fragment_size < buf->len);
         // 计算分片偏移（以8字节为单位）
        uint16_t fragment_offset = offset / 8;
        // 发送分片
        ip_fragment_out(&bufip, ip, protocol, id, fragment_offset, mf);
        
        offset += fragment_size;
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}
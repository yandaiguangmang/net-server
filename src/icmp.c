#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
   buf_init(&txbuf,BUF_MAX_LEN);
  // 复制原始请求的整个ICMP报文（包括头部和数据）
    memcpy(txbuf.data, req_buf->data, req_buf->len);
    txbuf.len = req_buf->len;
  icmp_hdr_t *req_hdr = (icmp_hdr_t *)req_buf->data; //请求报文
   icmp_hdr_t* hdr=(icmp_hdr_t*)txbuf.data;
    hdr->checksum16 = 0;  // 先置0再计算
   hdr->type=ICMP_TYPE_ECHO_REPLY;//回显应答
   hdr->code=0;
   hdr->id16 = req_hdr->id16;
    hdr->seq16 = req_hdr->seq16;
   hdr->checksum16= checksum16((uint16_t*)txbuf.data,txbuf.len); 
   ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP);




}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    if(buf->len<sizeof(icmp_hdr_t)) return;//小于ICMP首部的长度（固定8字节）则丢弃
    icmp_hdr_t *hdr=(icmp_hdr_t*)buf->data;
    if( hdr->type==ICMP_TYPE_ECHO_REQUEST)//类型是回显请求
    {
           icmp_resp(buf,src_ip);//如果该报文的 ICMP 类型是回显请求，则调用 icmp_resp() 函数回送一个回显应答（ping 应答）。
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
  buf_init(&txbuf,BUF_MAX_LEN);
// 先添加ICMP头部
    buf_add_header(&txbuf, sizeof(icmp_hdr_t));
    icmp_hdr_t* hdr = (icmp_hdr_t*)txbuf.data;
hdr->type=ICMP_TYPE_UNREACH;
   hdr->code=code;
   hdr->id16 = 0;
    hdr->seq16 = 0;
    hdr->checksum16 = 0;  // 先置0

    uint16_t copy_len = sizeof(ip_hdr_t) + 8;
     memcpy(txbuf.data + sizeof(icmp_hdr_t), recv_buf->data, copy_len);
     txbuf.len =  sizeof(icmp_hdr_t) + copy_len;
    
  hdr->checksum16=checksum16((uint16_t*)txbuf.data, txbuf.len);
   ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}
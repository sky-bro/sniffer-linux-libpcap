#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include "headers.h"

pcap_t *handle;

void callback(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data);
void terminate_process(int signum)
{
   pcap_breakloop(handle);
   printf("****************closing session handle***************\n");
   pcap_close(handle);
   printf("bye!\n");
}

int main(int argc, char *argv[])
{
  int ret;
  // pcap_t *handle;			/* Session handle */ // 通过handle访问一个session
  char *dev;			/* The device to sniff on */ // 设备名
  char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */ // 存放错误时的错误提示
  struct bpf_program fp;		/* The compiled filter */ // 存放编译后的规则
  // char filter_exp[] = "port 23";	/* The filter expression */ // 规则字符串
  // char filter_exp[] = "dst host 219.217.228.102"; // 目的ip为教务处网站 jwts.hit.edu.cn
  char filter_exp[] = "tcp";
  bpf_u_int32 mask;		/* Our netmask */ // 掩码
  bpf_u_int32 net;		/* Our IP */ // 网络地址部分
  struct pcap_pkthdr header;	/* The header that pcap gives us */
  const u_char *packet;		/* The actual packet */

  /* Define the device */
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
  	fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
  	return(2);
  }

  // 直接打开设备handle
  /* Open the session in promiscuous mode */
  // handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  // if (handle == NULL) {
  // 	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
  // 	return(2);
  // }

  // 创建handle
  dev = "wlp3s0";
  handle = pcap_create(dev, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return(2);
  }

  // 配置handle
  // 开启monitor模式
  // 不知道怎么关闭, 打开后需要重启wifi才能再上网
  if (pcap_set_rfmon(handle, 1)){
    printf("开启monitor模式失败, handle已激活\n");
  } else {
    printf("已打开monitor mode\n");
  }
  // 设置snapshot length
  pcap_set_snaplen(handle, 65535);
  // printf("BUFSIZ: %u", BUFSIZ); // 8192
  // 打开混淆模式
  pcap_set_promisc(handle, 1);
  //  set capture protocol
  // pcap_set_protocol_linux(pcap_t *p, int protocol);
  // set the packet buffer timeout (milliseconds)
  pcap_set_timeout(handle, 1000);
  // set buffer size
  // int pcap_set_buffer_size(pcap_t *p, int buffer_size);


  // 激活handle
  ret = pcap_activate(handle);
  if (ret == 0){
    printf("激活%s handle成功\n", dev);
  } else if (ret > 0){
    printf("激活%s handle成功, 但有警告: %d\n", dev, ret);
    pcap_perror(handle, dev);
  } else {
    printf("激活%s handle失败, 错误号: %d\n", dev, ret);
    pcap_perror(handle, dev);
  }

  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
  	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
  	return(2);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
  	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
  	return(2);
  }

  // 捕获一个包
  /* Grab a packet */
  // packet = pcap_next(handle, &header);
  /* Print its length */
  // printf("Jacked a packet with length of [%d]\n", header.len);

  // 关闭session
  /* And close the session */
  signal(SIGINT, terminate_process);
  pcap_loop(handle, -1, callback, NULL);

  return(0);
}


void callback(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data)
{
    // cout<<"\t\t抓到一个包"<<endl;
    // cout<<"-------------------------------------------------"<<endl;
    //解析数据包IP头部
    // printf("-------------------ORIGINAL BEGIN------------------------\n");
    // for (int i = 0; i < 15; i++){
    //   for (int j = 0; j < 8; j++) {
    //     printf("%02x ", *(pkt_data+i*8+j));
    //   }
    //   printf("\n");
    // }
    // // printf("first four bytes: %c%c%c%c\n", *pkt_data, *(pkt_data+1), *(pkt_data+2), *(pkt_data+3));
    // printf("\n-------------------ORIGINAL FINISH------------------------\n");
    // return;
    ieee80211_radiotap_header *radio_header = (ieee80211_radiotap_header*)(pkt_data);
    int radio_header_len = /*ntohs*/(radio_header->len);
    printf("radio_header_len: %d\n", radio_header_len);
    pkt_data += radio_header_len;//+34; // IP头开始
    // printf("first byte: %0x--%0x\n", *(pkt_data), (*pkt_data)&0xc);
    if (((*pkt_data)&0xc) == 8) { //is data frame
      // printf("********IAMIN*****");
      // pkt_data += 26; // LLC开始
      pkt_data += 34; // IP开始
      // printf("radio_header_len: %d\n", radio_header_len);
      IPHeader_t *ip_header=(IPHeader_t*)(pkt_data);

      if (ip_header->Protocol == 6){
        int ip_total_len = ntohs(ip_header->TotalLen);
        int ip_header_len = ((ip_header->Ver_HLen)&0xf)*4;

        pkt_data += ip_header_len; // TCP头开始
        TCPHeader_t *tcp_header=(TCPHeader_t*)(pkt_data);
        int tcp_header_len = tcp_header->HeaderLen >> 2;
        int tcp_content_len = ip_total_len-ip_header_len-tcp_header_len;
        printf("got a TCP packet, ip_total_len: %d, ip_header_len: %d, tcp_header_len: %d, content_len: %d\n", ip_total_len, ip_header_len, tcp_header_len, tcp_content_len);

        // 读取TCP内容
        pkt_data += tcp_header_len;
        if (strncmp(pkt_data, "POST", 3) == 0){
          printf("-------------------GET BEGIN------------------------\n");
          for (int i = 0; i < tcp_content_len; i++){
            printf("%c", *(pkt_data+i));
          }
          printf("\n-------------------GET FINISH------------------------\n");
        }else if (strncmp(pkt_data, "POST", 4) == 0){
          printf("-------------------POST BEGIN------------------------\n");
          for (int i = 0; i < tcp_content_len; i++){
            printf("%c", *(pkt_data+i));
          }
          // printf("first four bytes: %c%c%c%c\n", *pkt_data, *(pkt_data+1), *(pkt_data+2), *(pkt_data+3));
          printf("\n-------------------POST FINISH------------------------\n");
        }
      }
    }

    // if(header->len>=14){
    //
    // }
}

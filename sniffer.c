#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include "headers.h"
#include <unistd.h>
#define DEV_LEN 30
pcap_t *handle = NULL;
FILE *logFile = NULL;
int isMonitor = 0;

void callback(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data);
void terminate_process(int signum)
{
   pcap_breakloop(handle);
   printf("****************closing session handle & logFile***************\n");
   pcap_close(handle);
   if (logFile)
    fclose(logFile);
   printf("bye!\n");
}

int main(int argc, char *argv[])
{
  char *cmds = "-m ---- monitor mode on\n\
-f /path/to/log.txt ---- logFile path\n\
-l 65535 ---- snap length\n\
-i eth0 ---- specify interface\n";
  int ret;
  int snaplen = 65535;
  // pcap_t *handle;			/* Session handle */ // 通过handle访问一个session
  char dev[DEV_LEN] = {0};			/* The device to sniff on */ // 设备名
  char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */ // 存放错误时的错误提示
  struct bpf_program fp;		/* The compiled filter */ // 存放编译后的规则
  // char filter_exp[] = "port 23";	/* The filter expression */ // 规则字符串
  // char filter_exp[] = "tcp and dst host 219.217.228.102"; // 目的ip为教务处网站 jwts.hit.edu.cn
  // char filter_exp[] = "host 219.217.228.102 or 202.118.253.94 or 202.118.224.24"; //http://202.118.224.24
  char filter_exp[] = "tcp";
  bpf_u_int32 mask;		/* Our netmask */ // 掩码
  bpf_u_int32 net;		/* Our IP */ // 网络地址部分
  struct pcap_pkthdr header;	/* The header that pcap gives us */
  const u_char *packet;		/* The actual packet */
  char ch;
	while ((ch = getopt(argc, argv, "l:i:mh")) != EOF /*-1*/) {
		// printf("optind: %d\n", optind);
   	switch (ch){
	       // case 'f': // 指定filter expression
					// 			 PORT = atoi(optarg);
					// 			 break;
				 case 'm': // 是否采用monitor mode
								 isMonitor = 1;
								 break;
         case 'l': // 是否采用monitor mode
								 snaplen = atoi(optarg);
								 break;
         case 'f': // 指定log文件路径,不使用此参数则不记录日志
								 logFile = fopen(optarg, "a");
                  if (logFile == NULL){
                    printf("open log file: %s failed\n", optarg);
                    return(2);
                  }
								 break;
         case 'i': // 指定网卡设备
                strncpy(dev, optarg, strlen(optarg)>DEV_LEN-1?DEV_LEN-1:strlen(optarg));
                handle = pcap_create(optarg, errbuf);
                if (handle == NULL) {
                  fprintf(stderr, "Couldn't open device %s: %s\n", optarg, errbuf);
                  return(2);
                }
                break;
				 default:
				 				printf("%s", cmds);
								return 0;
		}
	}


  /* Define the device */
  if (!handle){
    pcap_if_t *alldevs;
    pcap_findalldevs(&alldevs, errbuf);
    int choice = 0;
    for (pcap_if_t *i = alldevs; i; i = i -> next, ++choice){
      printf("%d: name: %s, description: %s\n", choice, i -> name, i -> description);
    }
    int tmp;
    scanf("%d", &tmp);
    if (tmp >= choice){
      printf("Wrong dev choice!\n");
      return(2);
    }
    pcap_if_t * i = alldevs;
    while (tmp--){
      i = i -> next;
    }
    strncpy(dev, i->name, strlen(i->name)>DEV_LEN-1?DEV_LEN-1:strlen(i->name));
    handle = pcap_create(i->name, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
      return(2);
    }
    pcap_freealldevs(alldevs);
  }

  // 直接打开设备handle
  /* Open the session in promiscuous mode */
  // handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  // if (handle == NULL) {
  // 	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
  // 	return(2);
  // }




  // 配置handle
  // 开启monitor模式
  if (isMonitor){
    if (pcap_set_rfmon(handle, 1)){
      printf("开启monitor模式失败, handle已激活\n");
    } else {
      printf("已打开monitor mode\n");
    }
  }

  // 设置snapshot length
  pcap_set_snaplen(handle, snaplen);
  // printf("BUFSIZ: %u", BUFSIZ); // 8192
  // 打开混淆模式
  pcap_set_promisc(handle, 1); // for 802.11, may not work, monitor mode may work!
  //  set capture protocol
  // pcap_set_protocol_linux(pcap_t *p, int protocol);
  // set the packet buffer timeout (milliseconds)
  // pcap_set_timeout(handle, 100000);
  // set buffer size
  // int pcap_set_buffer_size(pcap_t *p, int buffer_size);

  // directly delever packets with no bufferring
  pcap_set_immediate_mode(handle, 1);


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

    // Monitor模式
    if (isMonitor){
      ieee80211_radiotap_header *radio_header = (ieee80211_radiotap_header*)(pkt_data);
      int radio_header_len = /*ntohs*/(radio_header->len);
      // printf("radio_header_len: %d\n", radio_header_len);
      pkt_data += radio_header_len; // ieee80211 frame
      // printf("first byte: %0x--%0x\n", *(pkt_data), (*pkt_data)&0xc);

      if (((*pkt_data)&0xc) != 8){ // not data frame
        return;
      }
      //is data frame
      pkt_data += 34; // IP开始
    } else {
      // 非monitor模式
      if (header->len>14){
        pkt_data+=14; // IP开始
      }
    }

    // printf("radio_header_len: %d\n", radio_header_len);
    IPHeader_t *ip_header=(IPHeader_t*)(pkt_data);

    if (ip_header->Protocol == 6){ // is tcp

      int ip_total_len = ntohs(ip_header->TotalLen);
      int ip_header_len = ((ip_header->Ver_HLen)&0xf)*4;

      IPv4_Addr srcIP = ip_header->SrcIP;
      IPv4_Addr dstIP = ip_header->DstIP;

      pkt_data += ip_header_len; // TCP头开始
      TCPHeader_t *tcp_header=(TCPHeader_t*)(pkt_data);
      int tcp_header_len = tcp_header->HeaderLen >> 2;
      int tcp_content_len = ip_total_len-ip_header_len-tcp_header_len;

      u_int16 srcPort = ntohs(tcp_header->SrcPort);
      u_int16 dstPort = ntohs(tcp_header->DstPort);
      // printf("got a TCP packet, ip_total_len: %d, ip_header_len: %d, tcp_header_len: %d, content_len: %d\n", ip_total_len, ip_header_len, tcp_header_len, tcp_content_len);
      printf("src --- %d.%d.%d.%d:%d\tdst --- %d.%d.%d.%d:%d\n",
       srcIP.addr0, srcIP.addr1, srcIP.addr2, srcIP.addr3, srcPort,
       dstIP.addr0, dstIP.addr1, dstIP.addr2, dstIP.addr3, dstPort);
       if (logFile){
         fprintf(logFile, "src --- %d.%d.%d.%d:%d\tdst --- %d.%d.%d.%d:%d\n",
           srcIP.addr0, srcIP.addr1, srcIP.addr2, srcIP.addr3, srcPort,
           dstIP.addr0, dstIP.addr1, dstIP.addr2, dstIP.addr3, dstPort);
       }

      // 读取TCP内容
      pkt_data += tcp_header_len;
      // if (strncmp(pkt_data, "GET", 3) == 0){
      //   printf("-------------------GET BEGIN------------------------\n");
      //   for (int i = 0; i < 40; i++){
      //     printf("%c", *(pkt_data+i));
      //   }
      //   printf("\n-------------------GET FINISH------------------------\n");
      // }else
      if (strncmp(pkt_data, "POST", 4) == 0){
        printf("-------------------POST BEGIN------------------------\n");
        for (int i = 0; i < tcp_content_len; i++){
          printf("%c", *(pkt_data+i));
        }
        // printf("first four bytes: %c%c%c%c\n", *pkt_data, *(pkt_data+1), *(pkt_data+2), *(pkt_data+3));
        printf("\n-------------------POST FINISH------------------------\n");
      }
    }
    fflush(stdout);


    // if(header->len>=14){
    //
    // }
}

#include <pcap.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
  int ret;
  pcap_t *handle;			/* Session handle */ // 通过handle访问一个session
  char *dev;			/* The device to sniff on */ // 设备名
  char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */ // 存放错误时的错误提示
  struct bpf_program fp;		/* The compiled filter */ // 存放编译后的规则
  char filter_exp[] = "port 23";	/* The filter expression */ // 规则字符串
  bpf_u_int32 mask;		/* Our netmask */ // 掩码
  bpf_u_int32 net;		/* Our IP */ //
  struct pcap_pkthdr header;	/* The header that pcap gives us */
  const u_char *packet;		/* The actual packet */

  /* Define the device */
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
  	fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
  	return(2);
  }
  /* Find the properties for the device */
  // 决定IPv4网络号和掩码
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
  	fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
  	net = 0;
  	mask = 0;
  }


  /* Open the session in promiscuous mode */
  // handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  // if (handle == NULL) {
  // 	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
  // 	return(2);
  // }

  // 打开设备
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
  pcap_set_snaplen(handle, BUFSIZ);
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
  // if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
  // 	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
  // 	return(2);
  // }
  // if (pcap_setfilter(handle, &fp) == -1) {
  // 	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
  // 	return(2);
  // }
  /* Grab a packet */
  packet = pcap_next(handle, &header);
  /* Print its length */
  printf("Jacked a packet with length of [%d]\n", header.len);
  /* And close the session */
    // 开启monitor模式

  pcap_close(handle);
  return(0);
}

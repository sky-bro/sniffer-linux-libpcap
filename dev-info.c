// #include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
  pcap_t *handle;			/* Session handle */
  char *dev;			/* The device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
  struct bpf_program fp;		/* The compiled filter */
  char filter_exp[] = "port 23";	/* The filter expression */
  bpf_u_int32 mask;		/* Our netmask */
  bpf_u_int32 net;		/* Our IP */
  struct pcap_pkthdr header;	/* The header that pcap gives us */
  const u_char *packet;		/* The actual packet */

  // int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
  // void pcap_freealldevs(pcap_if_t *alldevs);
  pcap_if_t *alldevs;
  pcap_findalldevs(&alldevs, errbuf);
  for (pcap_if_t *i = alldevs; i; i = i -> next){
    printf("name: %s, description: %s\n", i -> name, i -> description);
  }
  pcap_freealldevs(alldevs);

  /* Define the device */
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
  	fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
  	return(2);
  }
  /* Find the properties for the device */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
  	fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
  	net = 0;
  	mask = 0;
  }
  /* Open the session in promiscuous mode */
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
  	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
  	return(2);
  }

  // int pcap_list_datalinks(pcap_t *p, int **dlt_buf);
  // void pcap_free_datalinks(int *dlt_list);
  // const char *pcap_datalink_val_to_name(int dlt);
  // const char *pcap_datalink_val_to_description(int dlt);
  int *dlt_list;
  int typeNum = pcap_list_datalinks(handle, &dlt_list);
  printf("\n%s supports %d types of header\n", dev, typeNum);
  pcap_free_datalinks(dlt_list);

  // link-layer header type
  int dlt = pcap_datalink(handle);
  printf("%s's current type of header: %d\n", dev, dlt);
  const char* description = pcap_datalink_val_to_description(dlt);
  const char* typeName = pcap_datalink_val_to_name(dlt);
  printf("type: %s, description: %s\n\n", typeName, description);

  printf("device: %s %s be set to monitor mode\n", dev, pcap_can_set_rfmon(handle)==1?"can":"cannot");

  pcap_close(handle);
  return(0);
}

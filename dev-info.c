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
  int dlt = pcap_datalink(handle);
  printf("%s 's type of header: %d\n", dev, dlt);
  const char* description = pcap_datalink_val_to_description(dlt);
  const char* name = pcap_datalink_val_to_name(dlt);
  printf("name: %s\n", name);
  printf("description: %s\n", description);

  pcap_close(handle);
  return(0);
}

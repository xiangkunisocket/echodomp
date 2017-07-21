/*************************************************************************
	> File Name: func.h
	> Author: ECHO
	> Mail: 1406451659@QQ.com 
	> Created Time: 2017年04月10日 星期一 10时21分15秒
 **************************************************************************/
//#include "pcap.h"
void ethernet_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);

/****arp数据包捕获函数****/
void arp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);

/****ip数据包捕捉函数****/
void ip_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);

/*********TCP数据包捕获函数***********/
void tcp_protocol_packet_callback(u_char *argument,const  struct pcap_pkthdr *packet_header,const u_char *packet_content);

/**********UDP数据包的捕获****************/
void udp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr * packet_header,const u_char *packet_content);

/**********ICMP数据包的捕获*************/
void icmp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);

/*****以太网数据包分析*******/
void ethernet_protocol_packet_print(const struct pcap_pkthdr *packet_header,const u_char *packet_content);

/*****arp数据包分析函数*******/
void arp_protocol_packet_print(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);

/**********ip数据包分析函数************/
void ip_protocol_packet_print(const struct pcap_pkthdr *packet_header,const u_char *packet_content);

/**********TCP分析函数*******************/
void tcp_protocol_packet_print(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);

/**********DUP数据包分析函数************/
void udp_protocol_packet_print(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);

/*********ICMP数据包分析函数**********/
void icmp_protocol_packet_print(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);

/**********端口捕获函数**********/
void port_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);

/************help函数************/
void mohodump_help();



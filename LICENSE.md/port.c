/*************************************************************************
	> File Name: func.c
	> Author: ECHO
	> Mail: 1406451659@QQ.com 
	> Created Time: 2017年04月05日 星期三 11时30分04秒
 ************************************************************************/
/**********端口捕获函数**********/
void port_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{	
	pcap_dump(argument,packet_header,packet_content);  //写入文件
	printf("Jacked a packet with length of [%d]\n",packet_header->len);
	if(pcap_print.ethernet_print)
	{
		ethernet_protocol_packet_print(packet_header,packet_content);
		ip_protocol_packet_print(packet_header,packet_content);
		arp_protocol_packet_print(argument,packet_header,packet_content);
		tcp_protocol_packet_print(argument,packet_header,packet_content);
		udp_protocol_packet_print(argument,packet_header,packet_content);
		icmp_protocol_packet_print(argument,packet_header,packet_content);	
	}
}






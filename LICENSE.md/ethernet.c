/*************************************************************************
	> File Name: func.c
	> Author: ECHO
	> Mail: 1406451659@QQ.com 
	> Created Time: 2017年04月05日 星期三 11时30分04秒
 ************************************************************************/
/****以太网数据包捕捉函数****/
void ethernet_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{ 
	//pcap_dump(argument,packet_header,packet_content);   //保存数据包到文件
	struct ether_header * ethernet_protocol;   //以太网类型
	ethernet_protocol = (struct ether_header*)packet_content;
    u_short ethernet_type;      //以太网协议类型
	ethernet_type = ntohs(ethernet_protocol->ether_type);
	switch(ethernet_type)
	{
		case 0x0806:
			arp_protocol_packet_callback(argument,packet_header,packet_content); 
					break;
		case 0x0800:
			ip_protocol_packet_callback(argument,packet_header,packet_content);
					break;
		default :break;
	}
	
	if(pcap_print.ethernet_print){
		ethernet_protocol_packet_print(packet_header,packet_content);      //调用分析函数
	}
}


/*****以太网数据包分析*******/
void ethernet_protocol_packet_print(const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	int i;
	struct ether_header * ethernet_protocol;   //以太网类型
	ethernet_protocol = (struct ether_header*)packet_content;
    u_short ethernet_type;      //以太网协议类型
	ethernet_type = ntohs(ethernet_protocol->ether_type);
	printf("---------------Ethernet Protocol ---------------\n");
	printf("Receive Packet Size :%d bytes \n",packet_header->len); 
	printf("Ethernet_Type :%04x\n",ethernet_type); //以太网协议类型
	printf("Souce Mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
		ethernet_protocol->ether_dhost[0],
		ethernet_protocol->ether_dhost[1],
		ethernet_protocol->ether_dhost[2],
		ethernet_protocol->ether_dhost[3],
		ethernet_protocol->ether_dhost[4],
		ethernet_protocol->ether_dhost[5]);
	printf("Destination Mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
		ethernet_protocol->ether_shost[0],
		ethernet_protocol->ether_shost[1],
		ethernet_protocol->ether_shost[2],
		ethernet_protocol->ether_shost[3],
		ethernet_protocol->ether_shost[4],
		ethernet_protocol->ether_shost[5]);
	printf("------------------content---------------\n");
	for(i = 0;i < (int)packet_header->len;++i)
	{
		printf(" %02x",packet_content[i]);
		if((i + 1)%16 ==0)
			printf("\n");
	}
	printf("\n\n");
		
}







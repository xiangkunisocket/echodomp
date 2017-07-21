
/****arp数据包捕获函数****/
void arp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	pcap_dump(argument,packet_header,packet_content);
	printf("Jacked a packet with length of [%d]\n",packet_header->len);
	if(pcap_print.arp_print)
	{
		arp_protocol_packet_print(argument,packet_header,packet_content);
	}
}

/*****arp数据包分析函数*******/
void arp_protocol_packet_print(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	int i;
	struct arp_header * arpheader = NULL;
	arpheader = (struct arp_header *)(packet_content  +14);
	printf("------------arp---------------\n");
	printf("Received Packet Size :%d bytes \n",packet_header->len);   //数据包大小
	printf("Hardware Type :%s\n",(ntohs(arpheader->arp_hardware_type)==1)?"Ethenet":"Unknown"); //硬件地址
	printf("Protocol type :%s\n",(ntohs(arpheader->arp_protocol_type)==0x0800)?"IPv4":"Unknown");
	printf("Operation : %s\n",(ntohs(arpheader->arp_operation_code)==ARP_REQUEST)?"ARP_REQUEST":"ARP_REPLY");
	/***输出数据包的内容****/
	if(ntohs(arpheader->arp_hardware_type)==1&&ntohs(arpheader->arp_protocol_type)==0x0800)
	{
		printf("Souce Mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
     	 		arpheader->arp_source_ethernet_address[0],
				arpheader->arp_source_ethernet_address[1],
				arpheader->arp_source_ethernet_address[2],
				arpheader->arp_source_ethernet_address[3],
				arpheader->arp_source_ethernet_address[4],
				arpheader->arp_source_ethernet_address[5]);
		printf("Souce Ip:%d.%d.%d.%d\n",
     	 		arpheader->arp_source_ip_address[0],
				arpheader->arp_source_ip_address[1],
				arpheader->arp_source_ip_address[2],
				arpheader->arp_source_ip_address[3]);
		printf("Destination Mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
    	 	 	arpheader->arp_destination_ethernet_address[0],
				arpheader->arp_destination_ethernet_address[1],
				arpheader->arp_destination_ethernet_address[2],
				arpheader->arp_destination_ethernet_address[3],
				arpheader->arp_destination_ethernet_address[4],
				arpheader->arp_destination_ethernet_address[5]);
		printf("Destination Ip:%d.%d.%d.%d\n",
    	 	 	arpheader->arp_destination_ip_address[0],
				arpheader->arp_destination_ip_address[1],
				arpheader->arp_destination_ip_address[2],
				arpheader->arp_destination_ip_address[3]);
	}
	printf("------------------content---------------\n");
	for(i = 0;i < (int)packet_header->len;++i)
	{
		printf(" %02x",packet_content[i]);
		if((i + 1)%16 ==0)
			printf("\n");
	}
	printf("\n\n");
}


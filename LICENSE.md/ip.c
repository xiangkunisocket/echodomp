/*************************************************************************
	> File Name: func.c
	> Author: ECHO
	> Mail: 1406451659@QQ.com 
	> Created Time: 2017年04月05日 星期三 11时30分04秒
 ************************************************************************/
/****ip数据包捕捉函数****/
void ip_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	pcap_dump(argument,packet_header,packet_content);
//	printf("Jacked a packet with length of [%d]\n",packet_header->len);
	struct ip_header *ip_protocol;  //ip协议变量
	ip_protocol = (struct ip_header *)(packet_content + 14);
	
	switch(ip_protocol->ip_protocol)
	{
		case 6:tcp_protocol_packet_callback(argument,packet_header,packet_content);break;
		case 17:udp_protocol_packet_callback(argument,packet_header,packet_content);break;
		case 1:icmp_protocol_packet_callback(argument,packet_header,packet_content);break;
		default:break;
	}
	if(pcap_print.ip_print)
	{
		ip_protocol_packet_print(packet_header,packet_content);
	}
}

/**********ip数据包分析函数************/
void ip_protocol_packet_print(const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	int i;
   struct ip_header *ip_protocol = (struct ip_header *)(packet_content+14);  //ip协议变量
	u_int offset = ntohs(ip_protocol->ip_off);  //获得偏移
	printf("-------------ip--------------\n");
	printf("Jacket a packet with length of [%d]\n",packet_header->len);
	printf("IP version :%d\n",ip_protocol->ip_version);
	printf("Header length :%d\n",ip_protocol->ip_header_length*4);   //获得ip头部长度
	printf("Tos :%d\n",ip_protocol->ip_tos);				//获得tos服务质量
	printf("Total length :%d\n",ntohs(ip_protocol->ip_length)); //获得总的长度
	printf("Identification :%d\n",ntohs(ip_protocol->ip_id));   //获得标识
	printf("offset :%d\n",(offset & 0x1fff)*8);
	printf("TTL :%d\n",ip_protocol->ip_ttl);				//获得ttl
	printf("Protocol :%d\n",ip_protocol->ip_protocol);     //获取协议类型
	switch(ip_protocol->ip_protocol)
	{
		case 6:printf("Transport layer : TCP\n");break;
		case 17:printf("Transport layer :UDP\n");break;
		case 1:printf("Transport layer :ICMP\n");break;
		default:break;
	}
	printf("Header Checksum:%d\n",ntohs(ip_protocol->ip_checksum));   //首部校验和
	printf("Souce IP:%s\n",inet_ntoa(ip_protocol->ip_souce_address)); //源ip地址
	printf("Destination IP:%s\n",inet_ntoa(ip_protocol->ip_destination_address));//目的ip地址
/*	printf("Source Ip:%d.%d.%d.%d\n",ip_protocol->ip_souce_address[0],ip_protocol->ip_souce_address[1],ip_protocol->ip_souce_address[2],ip_protocol->ip_souce_address[3]);
	printf("Destination Ip:%d.%d.%d.%d\n",ip_protocol->ip_destination_address[0],ip_protocol->ip_destination_address[1],ip_protocol->ip_destination_address[2],ip_protocol->ip_destination_address[3]);*/
	printf("------------------content---------------\n");
	for(i = 0;i < (int)packet_header->len;++i)
	{
		printf(" %02x",packet_content[i]);
		if((i + 1)%16 ==0)
			printf("\n");
	}
	printf("\n\n");
}




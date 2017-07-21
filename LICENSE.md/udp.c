/*************************************************************************
	> File Name: func.c
	> Author: ECHO
	> Mail: 1406451659@QQ.com 
	> Created Time: 2017年04月05日 星期三 11时30分04秒
 ************************************************************************/
/**********UDP数据包的捕获****************/
void udp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr * packet_header,const u_char *packet_content)
{
	pcap_dump(argument,packet_header,packet_content);
	printf("Jacked a packet with length of [%d]\n",packet_header->len);
	if(pcap_print.udp_print)
	{
		udp_protocol_packet_print(argument,packet_header,packet_content);
	}
}

/**********DUP数据包分析函数************/
void udp_protocol_packet_print(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	int i;
	struct udp_header *udp_protocol;     /***udp协议数据变量****/
	u_short source_port;				 /***源端口号****/
	u_short destination_port;            /****目的端口号****/
	u_short length;                     /**长度*****/
	udp_protocol = (struct udp_header *)(packet_content+14+20);   //获得UDP协议的内容
	source_port = ntohs(udp_protocol->udp_source_port);     //源端口
	destination_port = ntohs(udp_protocol->udp_destination_port);  //目的端口
	length = ntohs(udp_protocol->udp_length);               //长度
	printf("-------------UDP Protocol------------\n");
	printf("Source port :%d\n",source_port);           
	printf("Destination port:%d\n",destination_port);
	switch(destination_port)
	{
		case 138:printf("NETBIOS Datagram Service\n");break;
		case 137:printf("NETBIOS Name Service\n");break;
		case 139:printf("NETBIOS session service\n");break;
		case 53:printf("name-domain server\n");break;
		default:break;
	}

	printf("Length:%d\n",length);
	printf("Checksum :%d\n",ntohs(udp_protocol->udp_checksum));  
	printf("------------------content---------------\n");
	for(i = 0;i < (int)packet_header->len;++i)
	{
		printf(" %02x",packet_content[i]);
		if((i + 1)%16 ==0)
			printf("\n");
	}
	printf("\n\n");
}



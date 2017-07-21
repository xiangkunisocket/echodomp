/*************************************************************************
	> File Name: func.c
	> Author: ECHO
	> Mail: 1406451659@QQ.com 
	> Created Time: 2017年04月05日 星期三 11时30分04秒
 ************************************************************************/
/*********TCP数据包捕获函数***********/
void tcp_protocol_packet_callback(u_char *argument,const  struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	pcap_dump(argument,packet_header,packet_content);
	printf("Jacked a packet with length of [%d]\n",packet_header->len);
	if(pcap_print.tcp_print)
	{
		tcp_protocol_packet_print(argument,packet_header,packet_content);
	}
}

/**********TCP分析函数*******************/
void tcp_protocol_packet_print(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	int i;
	struct tcp_header * tcp_protocol;   //tcp协议变量
	u_char flags;               //标记
	int header_length;          //首部长度
	u_short source_port;        //源端口
	u_short destination_port;   //目的端口
	u_short windows;            //窗口大小
	u_short urgent_pointer;     //紧急指针
	u_int sequence;				//序列号
	u_int acknowledgement;      //确认号
	u_int16_t checksum;         //校验和
	tcp_protocol = (struct tcp_header*)(packet_content + 14+20); //获得tcp协议数据包的内容
	source_port = ntohs(tcp_protocol->tcp_source_port);    //获得端口号
	destination_port = ntohs(tcp_protocol->tcp_destination_port);  //获得端口号
	header_length = tcp_protocol->tcp_offset * 4;   //获取首部长度
	sequence = ntohl(tcp_protocol->tcp_acknowledgement);  //获得序列号
	acknowledgement = ntohl(tcp_protocol->tcp_ack);    //获得确认号
	windows = ntohs(tcp_protocol->tcp_windows);        //获得窗口大小
	urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);  //获得紧急指针
	flags = tcp_protocol->tcp_flags;                   //获得标记
	checksum = ntohs(tcp_protocol->tcp_checksum);      //获得校验和
	printf("-------------TCP--------------\n");
	printf("Source port:%d\n",source_port);       //输出源端口号
	printf("Destination port:%d\n",destination_port);  //输出目的端口
	//判断上层协议
	switch(destination_port)
	{
		case 80:printf("HTTP Protocol\n"); break;
		case 21:printf("FTP Protocol\n"); break;
		case 23:printf("TELNET Protocol\n"); break;
		case 25:printf("SMTP Protocol\n"); break;
		case 110:printf("POP3 Protocol\n"); break;
		default:break;
	}
	printf("Sequence Number:%u\n",sequence);  //输出序列号
	printf("Acknowledgement Number:%u\n",acknowledgement); //输出确认号
	printf("Header Length:%d\n",header_length);    //输出长度
	printf("Received:%d\n",tcp_protocol->tcp_reserved);   
	printf("Flags:");
	if(flags & 0x08) printf("PSH");
	if(flags & 0x10) printf("ACK");
	if(flags & 0x02) printf("SYN"); 
	if(flags & 0x20) printf("URG");
	if(flags & 0x01) printf("FIN");
	if(flags & 0x04) printf("RST");
	printf("\n");
	printf("Windows size:%d\n",windows);   //窗口大小
	printf("Checksum :%d\n",checksum);
	printf("Urgent pointer:%d\n",urgent_pointer); //紧急指针
	printf("------------------content---------------\n");
	for(i = 0;i < (int)packet_header->len;++i)
	{
		printf(" %02x",packet_content[i]);
		if((i + 1)%16 ==0)
			printf("\n");
	}
	printf("\n\n");
}


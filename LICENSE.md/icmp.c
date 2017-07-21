/*************************************************************************
	> File Name: func.c
	> Author: ECHO
	> Mail: 1406451659@QQ.com 
	> Created Time: 2017年04月05日 星期三 11时30分04秒
 ************************************************************************/
/**********ICMP数据包的捕获*************/
void icmp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	pcap_dump(argument,packet_header,packet_content);
	printf("Jacked a packet with length of [%d]\n",packet_header->len);
	if(pcap_print.icmp_print)
	{
		icmp_protocol_packet_print(argument,packet_header,packet_content);
	}
}

/*********ICMP数据包分析函数**********/
void icmp_protocol_packet_print(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	int i;
	struct icmp_header *icmp_protocol;    /***icmp协议变量*****/
	icmp_protocol = (struct icmp_header *)(packet_content +14+20);  //获取icmp的数据内容
	printf("--------------------ICMP---------------------\n");
	printf("ICMP　TYPE :%d\n",icmp_protocol->icmp_type);
	switch(icmp_protocol->icmp_type)
	{//类型是8表示的是会显请求报文
		case 8:printf("ICMP ECHO REQUEST PPROTOCOL\n");
			   printf("ICMP CODE:%d\n",icmp_protocol->icmp_code);
			   printf("Identifier :%d\n",icmp_protocol->icmp_id_kunxiang);
			   printf("Sequence Number:%d\n",icmp_protocol->icmp_sequence);
			   break;
		//类型是０表示的是回显应答报文
		case 0:printf("ICMP ECHO REPLY PPROTOCOL\n");
			   printf("ICMP CODE:%d\n",icmp_protocol->icmp_code);
			   printf("Identifier :%d\n",icmp_protocol->icmp_id_kunxiang);
			   printf("Sequence Number:%d\n",icmp_protocol->icmp_sequence);
			   break;
		default:break;
	}
	printf("TCMP Checksum :%d\n",ntohs(icmp_protocol->icmp_checksum));
	printf("------------------content---------------\n");
	for(i = 0;i < (int)packet_header->len;++i)
	{
		printf(" %02x",packet_content[i]);
		if((i + 1)%16 ==0)
			printf("\n");
	}
	printf("\n\n");
}


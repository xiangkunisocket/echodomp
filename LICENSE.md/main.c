/*************************************************************************
	> File Name: main.c
	> Author: ECHO
	> Mail: 1406451659@QQ.com 
	> Created Time: 2017年04月08日 星期六 10时21分20秒
 ************************************************************************/
#include "main.h"
#include "pkg_pcap.h"
#include "func.h"
#include "ethernet.c"
#include "arp.c"
#include "ip.c"
#include "udp.c"
#include "tcp.c"
#include "icmp.c"
#include "port.c"
#include "help.c"

int main(int argc,char *argv[])
{
	pcap_t *pcap_handle;   //会话句柄
	char error_content[PCAP_ERRBUF_SIZE];  //存储错误信息字符串
	char *net_interface;	//网络接口
	char *port_nmber;
	struct bpf_program bpf_filter;  //bpf过滤规则
	int count_num;
	pcap_print.arp_print = FALSE;
	pcap_print.ip_print = FALSE;
	pcap_print.tcp_print = FALSE;
	pcap_print.udp_print= FALSE;
	pcap_print.icmp_print = FALSE;
	pcap_print.ethernet_print = FALSE;
	port_nmber = argv[2];
	if(argc <  2)
	{
		printf("USAGE:-h for help!\n");
		exit(1);
	}
	char bpf_filter_string[MAXBYTECAPTURE] = " ";
	if(argv[1][0] == '-')
	{
		switch(argv[1][1])
		{
			case 'a':strcpy(bpf_filter_string,"arp"); //根据参数捕获arp数据报
					if(argv[1][3] == 's') pcap_print.arp_print  = TRUE;
					break;
			case 'i':strcpy(bpf_filter_string,"ip");
 	 				if(argv[1][3] == 's') pcap_print.ip_print  = TRUE;
					 break; 
			case 't':strcpy(bpf_filter_string,"tcp");
 	 				 if(argv [1][3] == 's') pcap_print.tcp_print  = TRUE;
					 break;
			case 'u':strcpy(bpf_filter_string,"udp");
	  				 if(argv[1][3] == 's') pcap_print.udp_print  = TRUE;
					 break;
			case 'c':strcpy(bpf_filter_string,"icmp");
	  				 if(argv[1][3] == 's') pcap_print.icmp_print  = TRUE;
					break;
			case 'p':strcpy(bpf_filter_string,port_nmber);
					 if(argv[1][6] == 's') pcap_print.ethernet_print = TRUE;
					break;
			case 'h':mohodump_help();exit(0);
			default:break;
		}
	}else{
		for(count_num = 1;count_num < argc;count_num++)
		{
			strncat(bpf_filter_string,argv[count_num],100);
			strncat(bpf_filter_string," ",10);
		}
	}
	printf("bpf_filter_string = %s\n",bpf_filter_string);
	bpf_u_int32 net_mask;   //网路掩码
	bpf_u_int32 net_ip;     //网络地址
	
	net_interface = pcap_lookupdev(error_content);   //获取网络接口
	pcap_handle = pcap_open_live(net_interface,MAXBYTECAPTURE,1,0,error_content);     //打开网络接口
	if(pcap_handle == NULL)
	{
		fprintf(stderr,"Can't open device %s:%s\n",net_interface,error_content);
		exit(1);
	}
	if(pcap_lookupnet(net_interface,&net_ip,&net_mask,error_content) == -1)
	{
		fprintf(stderr,"Can't get netmask for devoce %s:%s\n",net_interface,error_content);
		exit(1);
	}
	pcap_compile(pcap_handle,&bpf_filter,bpf_filter_string,0,net_ip); //编译过滤规则
	pcap_setfilter(pcap_handle,&bpf_filter);       //设置过滤规则

	pcap_dumper_t * out_pcap;    //打开文件句柄
	out_pcap = pcap_dump_open(pcap_handle,"/home/echo/study/code/undergrade/2.v/pack.pcap");

	pcap_loop(pcap_handle,-1,ethernet_protocol_packet_callback,(u_char *)out_pcap);  //注册回调函数循环捕捉数据包

	pcap_dump_flush(out_pcap);  //刷新缓冲区

	pcap_close(pcap_handle);    //关闭libpcap操作

	pcap_dump_close(out_pcap); //关闭文件
	return 0;
}


#include<stdafx.h>
#include "utilities.h"

/*pkt为网络中捕获的包，data为要存为本机上的数据*/


/*分析链路层*/
int analyze_frame(const u_char * pkt,struct datapkt * data,struct pktcount *npacket)
{
		int i;
		struct ethhdr *ethh = (struct ethhdr*)pkt;
		data->ethh = (struct ethhdr*)malloc(sizeof(struct ethhdr));
		if(NULL == data->ethh)
			return -1;

		for(i=0;i<6;i++)
		{
			data->ethh->dest[i] = ethh->dest[i];
			data->ethh->src[i] = ethh->src[i];
		}

		npacket->n_sum++;

		/*由于网络字节顺序原因，需要对*/
		data->ethh->type = ntohs(ethh->type);

		//处理ARP还是IP包？
		switch(data->ethh->type)
		{
			case 0x0806:
				return analyze_arp((u_char*)pkt+14,data,npacket);      //mac 头大小为14
				break;
			case 0x0800:
				return analyze_ip((u_char*)pkt+14,data,npacket);
				break;
			case 0x86dd:
				return analyze_ip6((u_char*)pkt+14,data,npacket);
				return -1;
				break;
			default:
				npacket->n_other++;
				return -1;
				break;
		}
		return 1;
}

/*分析网络层：ARP*/
int analyze_arp(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
	int i;
	struct arphdr *arph = (struct arphdr*)pkt;
	data->arph = (struct arphdr*)malloc(sizeof(struct arphdr));

	if(NULL == data->arph )
		return -1;

	//复制IP及MAC
	for(i=0;i<6;i++)
	{
		if(i<4)
		{
			data->arph->ar_destip[i] = arph->ar_destip[i];
			data->arph->ar_srcip[i] = arph->ar_srcip[i];
		}
		data->arph->ar_destmac[i] = arph->ar_destmac[i];
		data->arph->ar_srcmac[i]= arph->ar_srcmac[i];
	}

	data->arph->ar_hln = arph->ar_hln;
	data->arph->ar_hrd = ntohs(arph->ar_hrd);
	data->arph->ar_op = ntohs(arph->ar_op);
	data->arph->ar_pln = arph->ar_pln;
	data->arph->ar_pro = ntohs(arph->ar_pro);

	strcpy(data->pktType,"ARP");
	npacket->n_arp++;
	return 1;
}

/*分析网络层：IP*/
int analyze_ip(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
	int i;
	struct iphdr *iph = (struct iphdr*)pkt;
	data->iph = (struct iphdr*)malloc(sizeof(struct iphdr));

	if(NULL == data->iph)
		return -1;
	data->iph->check = iph->check;
	npacket->n_ip++;

	/*for(i = 0;i<4;i++)
	{
		data->iph->daddr[i] = iph->daddr[i];
		data->iph->saddr[i] = iph->saddr[i];
	}*/
	data->iph->saddr = iph->saddr;
	data->iph->daddr = iph->daddr;

	data->iph->frag_off = iph->frag_off;
	data->iph->id = iph->id;
	data->iph->proto = iph->proto;
	data->iph->tlen = ntohs(iph->tlen);
	data->iph->tos = iph->tos;
	data->iph->ttl = iph->ttl;
	data->iph->ihl = iph->ihl;
	data->iph->version = iph->version;
	//data->iph->ver_ihl= iph->ver_ihl;
	data->iph->op_pad = iph->op_pad;

	int iplen = iph->ihl*4;							//ip头长度
	switch(iph->proto)
	{
		case PROTO_ICMP:
			return analyze_icmp((u_char*)iph+iplen,data,npacket);
			break;
		case PROTO_TCP:
			return analyze_tcp((u_char*)iph+iplen,data,npacket);
			break;
		case PROTO_UDP:
			return analyze_udp((u_char*)iph+iplen,data,npacket);
			break;
		default :
			return-1;
			break;
	}
	return 1;
}

/*分析网络层：IPV6*/
int analyze_ip6(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
	int i;
	struct iphdr6 *iph6 = (struct iphdr6*)pkt;
	data->iph6 = (struct iphdr6*)malloc(sizeof(struct iphdr6));

	if(NULL == data->iph6)
		return -1;

	npacket->n_ip6++;

	data->iph6->version = iph6->version;
	data->iph6->flowtype = iph6->flowtype;
	data->iph6->flowid = iph6->flowid;
	data->iph6->plen = ntohs(iph6->plen);
	data->iph6->nh = iph6->nh;
	data->iph6->hlim =iph6->hlim;

	for(i=0;i<16;i++)
	{
		data->iph6->saddr[i] = iph6->saddr[i];
		data->iph6->daddr[i] = iph6->daddr[i];
	}

	switch(iph6->nh)
	{
		case 0x3a:
			return analyze_icmp6((u_char*)iph6+40,data,npacket);
			break;
		case 0x06:
			return analyze_tcp((u_char*)iph6+40,data,npacket);
			break;
		case 0x11:
			return analyze_udp((u_char*)iph6+40,data,npacket);
			break;
		default :
			return-1;
			break;
	}
	//npacket->n_ip6++;
	//strcpy(data->pktType,"IPV6");
	return 1;
}

/*分析传输层：ICMP*/
int analyze_icmp(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
	struct icmphdr* icmph = (struct icmphdr*)pkt;
	data->icmph = (struct icmphdr*)malloc(sizeof(struct icmphdr));

	if(NULL == data->icmph)
		return -1;

	data->icmph->chksum = icmph->chksum;
	data->icmph->code = icmph->code;
	data->icmph->seq =icmph->seq;
	data->icmph->type = icmph->type;
	strcpy(data->pktType,"ICMP");
	npacket->n_icmp++;
	return 1;
}

/*分析传输层：ICMPv6*/
int analyze_icmp6(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
	int i;
	struct icmphdr6* icmph6 = (struct icmphdr6*)pkt;
	data->icmph6 = (struct icmphdr6*)malloc(sizeof(struct icmphdr6));

	if(NULL == data->icmph6)
		return -1;

	data->icmph6->chksum = icmph6->chksum;
	data->icmph6->code = icmph6->code;
	data->icmph6->seq =icmph6->seq;
	data->icmph6->type = icmph6->type;
	data->icmph6->op_len = icmph6->op_len;
	data->icmph6->op_type = icmph6->op_type;
	for(i=0;i<6;i++)
	{
		data->icmph6->op_ethaddr[i] = icmph6->op_ethaddr[i];
	}
	strcpy(data->pktType,"ICMPv6");
	npacket->n_icmp6++;
	return 1;
}

/*分析传输层：TCP*/
int analyze_tcp(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
	struct tcphdr *tcph = (struct tcphdr*)pkt;
	data->tcph = (struct tcphdr*)malloc(sizeof(struct tcphdr));
	if(NULL == data->tcph)
		return -1;

	data->tcph->ack_seq = tcph->ack_seq;
	data->tcph->check = tcph->check;

	data->tcph->doff = tcph->doff;
	data->tcph->res1 = tcph->res1;
	data->tcph->cwr = tcph->cwr;
	data->tcph->ece = tcph->ece;
	data->tcph->urg = tcph->urg;
	data->tcph->ack = tcph->ack;
	data->tcph->psh = tcph->psh;
	data->tcph->rst = tcph->rst;
	data->tcph->syn = tcph->syn;
	data->tcph->fin = tcph->fin;
	//data->tcph->doff_flag = tcph->doff_flag;

	data->tcph->dport = ntohs(tcph->dport);
	data->tcph->seq = tcph->seq;
	data->tcph->sport = ntohs(tcph->sport);
	data->tcph->urg_ptr = tcph->urg_ptr;
	data->tcph->window= tcph->window;
	data->tcph->opt = tcph->opt;

	/////////////////////*不要忘记http分支*/////////////////////////
	if(ntohs(tcph->dport) == 80 || ntohs(tcph->sport)==80)
	{
		npacket->n_http++;
		strcpy(data->pktType,"HTTP");
	}
	else{
		npacket->n_tcp++;
		strcpy(data->pktType,"TCP");
	}
	return 1;
}

/*分析传输层：UDP*/
int analyze_udp(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
	struct udphdr* udph = (struct udphdr*)pkt;
	data->udph = (struct udphdr*)malloc(sizeof(struct udphdr));
	if(NULL == data->udph )
		return -1;

	data->udph->check = udph->check;
	data->udph->dport = ntohs(udph->dport);
	data->udph->len = ntohs(udph->len);
	data->udph->sport = ntohs(udph->sport);

	strcpy(data->pktType,"UDP");
	npacket->n_udp++;
	return 1;
}

//将数据包以十六进制方式打印出来
void print_packet_hex(const u_char* pkt,int size_pkt,CString *buf)
{
	int i=0,j = 0,rowcount;
	 u_char ch;

	 char tempbuf[256];
	 memset(tempbuf,0,256);

	for(i = 0;i<size_pkt;i+=16)
	{
		buf->AppendFormat(_T("%04x:  "),(u_int)i);
		rowcount = (size_pkt-i) > 16 ? 16 : (size_pkt-i);

		for (j = 0; j < rowcount; j++)
			buf->AppendFormat(_T("%02x  "),(u_int)pkt[i+j]);

		//不足16，用空格补足
		if(rowcount <16)
			for(j=rowcount;j<16;j++)
					buf->AppendFormat(_T("    "));


		for (j = 0; j < rowcount; j++)
		{
             ch = pkt[i+j];
             ch = isprint(ch) ? ch : '.';
			 buf->AppendFormat(_T("%c"),ch);
		}

		buf->Append(_T("\r\n"));

		if(rowcount<16)
			return;
	}
}


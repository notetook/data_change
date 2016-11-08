#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

int main ()
{
	HANDLE handle, console;
	char *filter = "(outbound and tcp.DstPort == 80) or (inbound and tcp.SrcPort == 80)";
	char *changed = "GodJong";

	unsigned char packet[0xFFFF];
	WINDIVERT_ADDRESS recv_addr;
	UINT packet_len;

	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	PVOID payload;
	UINT payload_len;

	bool flag;

	console = GetStdHandle ( STD_OUTPUT_HANDLE );

	handle = WinDivertOpen ( filter, WINDIVERT_LAYER_NETWORK, 0, 0 );
	if ( handle == INVALID_HANDLE_VALUE ){
		printf("error %d: failed to open handle\n", GetLastError());
		exit ( EXIT_FAILURE );
	}

	for(;;){
		if ( !WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len) ){
			printf("error %d: failed to read packet\n", GetLastError());
			exit ( EXIT_FAILURE );
		}

		flag = false;

		WinDivertHelperParsePacket ( packet, packet_len, &ip_header, &ipv6_header, &icmp_header, &icmpv6_header,
									&tcp_header, &udp_header, &payload, &payload_len );

		if ( recv_addr.Direction == WINDIVERT_DIRECTION_OUTBOUND && payload_len >= 4 ){
			for(int i=0; i<=payload_len-4; i++){
				if ( strncmp((const char*)payload+i, "gzip", 4) == 0 ){
					memset ( (unsigned char*)payload+i, 0x20, 4 );
					flag = true;
				}
			}
		}
		if ( flag ){
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;

			SetConsoleTextAttribute(console, FOREGROUND_RED);
			printf("Replace outbound packet   ");
			SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			printf("Packet Length : %4d / IP.DstAddr : %3u.%3u.%3u.%3u / IP.SrcAddr : %3u.%3u.%3u.%3u\n", packet_len,
					src_addr[0], src_addr[1], src_addr[2], src_addr[3],
					dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			flag = false;
		}

		if ( recv_addr.Direction == WINDIVERT_DIRECTION_INBOUND && payload_len >= 7 ){
			for(int i=0; i<=payload_len-7; i++){
				if ( strncmp((const char*)payload+i, "Michael", 7) == 0 ){
					memcpy ( (unsigned char*)payload+i, changed, 7 );
					flag = true;
				}
			}
		}
		if ( flag ){
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;

			SetConsoleTextAttribute(console, FOREGROUND_RED);
			printf("Replace  inbound packet   ");
			SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			printf("Packet Length : %4d / IP.DstAddr : %3u.%3u.%3u.%3u / IP.SrcAddr : %3u.%3u.%3u.%3u\n", packet_len,
					src_addr[0], src_addr[1], src_addr[2], src_addr[3],
					dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			flag = false;
		}

		WinDivertHelperCalcChecksums ( packet, packet_len, 0 );
		WinDivertSend ( handle, packet, packet_len, &recv_addr, &payload_len );
	}

	return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

//이더넷 헤더 구조체 정의
struct ethhdr {
    u_char dst_mac[6]; //목적지 MAC 주소
    u_char src_mac[6]; //출발지 MAC 주소
    u_short ether_type; //이더넷 타입
};

//IP 헤더 구조체 정의
struct iphdr {
    u_char ihl_ver; //버전 및 헤더 길이
    u_char tos; //서비스 유형
    u_short tot_len; //전체 길이
    u_short id; //식별자
    u_short frag_off; //단편화 정보
    u_char ttl; //Time to live
    u_char protocol; //프로토콜
    u_short check; //체크섬
    struct in_addr src_ip; //출발지 IP 주소
    struct in_addr dst_ip; //목적지 IP 주소
};

//헤더 구조체 정의
struct tcphdr {
    u_short src_port; //출발지 포트
    u_short dst_port; //목적지 포트
    u_int seq; // 시퀀스 번호
    u_int ack_seq; //확인 번호
    u_char doff_reserved; //데이터 오프셋 및 예약 필드
};

//패킷 처리 함수 정의
void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main() {
    pcap_t* handle; //패킷 캡처 핸들러
    char errbuf[PCAP_ERRBUF_SIZE]; //오류 버퍼

    // 네트워크 장치 선택 
    char* dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    // 패킷 캡처 핸들러 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // 패킷 캡처 및 처리
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}

void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ethhdr* eth_header = (struct ethhdr*)packet;
    struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));

    // IP 헤더의 길이를 4 비트로 표현된 IHL 필드에서 추출
    int ip_header_len = (ip_header->ihl_ver & 0x0F) * 4;

    // TCP 헤더 시작 위치 계산
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header_len);

    // TCP 프로토콜인지 확인
    if (ip_header->protocol != IPPROTO_TCP) {
        return; // TCP가 아니면 무시
    }

    // 출력
    printf("Ethernet Header: src mac - ");
    for (int i = 0; i < 6; ++i) {
        printf("%02X ", eth_header->src_mac[i]);
    }
    printf(", dst mac - ");
    for (int i = 0; i < 6; ++i) {
        printf("%02X ", eth_header->dst_mac[i]);
    }
    printf("\n");

    printf("IP Header: src ip - %s, dst ip - %s\n", inet_ntoa(ip_header->src_ip), inet_ntoa(ip_header->dst_ip));
    printf("TCP Header: src port - %d, dst port - %d\n", ntohs(tcp_header->src_port), ntohs(tcp_header->dst_port));

   
    int payload_len = pkthdr->len - (sizeof(struct ethhdr) + ip_header_len + tcp_header->doff_reserved * 4);
    int max_message_len = payload_len < 100 ? payload_len : 100;
    printf("Message: ");
    for (int i = 0; i < max_message_len; ++i) {
        printf("%02X ", packet[sizeof(struct ethhdr) + ip_header_len + tcp_header->doff_reserved * 4 + i]);
    }
    printf("\n");
}


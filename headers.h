typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;
typedef u_int16_t u_short;
typedef u_int32_t u_int32;
typedef u_int16_t u_int16;
typedef u_int8_t u_int8;

typedef struct ieee80211_radiotap_header {
        u_int8        version;     /* set to 0 */
        u_int8        pad;
        u_int16       len;         /* entire length */
        u_int32       present;     /* fields present */
} ieee80211_radiotap_header;

// typedef struct LLC_header {
//         u_int8_t        version;     /* set to 0 */
//         u_int8_t        pad;
//         u_int16_t       len;         /* entire length */
//         u_int32_t       present;     /* fields present */
// } LLC_header;


// IP层数据包格式
typedef struct
{
     int header_len:4;
     int version:4;
     u_char tos:8;
     int total_len:16;
     int ident:16;
     int flags:16;
     u_char ttl:8;
     u_char proto:8;
     int checksum:16;
     u_char sourceIP[4];
     u_char destIP[4];
} IPHEADER;

//pacp文件头结构体
// struct pcap_file_header
// {
//     bpf_u_int32 magic;       /* 0xa1b2c3d4 */
//     u_short version_major;   /* magjor Version 2 */
//     u_short version_minor;   /* magjor Version 4 */
//     bpf_int32 thiszone;      /* gmt to local correction */
//     bpf_u_int32 sigfigs;     /* accuracy of timestamps */
//     bpf_u_int32 snaplen;     /* max length saved portion of each pkt */
//     bpf_u_int32 linktype;    /* data link type (LINKTYPE_*) */
// };
//
// //时间戳
// struct time_val
// {
//     int tv_sec;         /* seconds 含义同 time_t 对象的值 */
//     int tv_usec;        /* and microseconds */
// };
//
// //pcap数据包头结构体
// struct pcap_pkthdr
// {
//     struct time_val ts;  /* time stamp */
//     bpf_u_int32 caplen; /* length of portion present */
//     bpf_u_int32 len;    /* length this packet (off wire) */
// };


//数据帧头 14字节
typedef struct FramHeader_t
{ //Pcap捕获的数据帧头
    u_int8 DstMAC[6]; //目的MAC地址
    u_int8 SrcMAC[6]; //源MAC地址
    u_short FrameType;    //帧类型
} FramHeader_t;


typedef struct IPv4_Addr {
  u_int8 addr0;
  u_int8 addr1;
  u_int8 addr2;
  u_int8 addr3;
} IPv4_Addr;

// IPv4数据报头
typedef struct IPHeader_t
{ //IP数据报头
    u_int8 Ver_HLen;       //版本+报头长度
    u_int8 TOS;            //服务类型
    u_int16 TotalLen;       //总长度
    u_int16 ID; //标识
    u_int16 Flag_Segment;   //标志+片偏移
    u_int8 TTL;            //生存周期
    u_int8 Protocol;       //协议类型
    u_int16 Checksum;       //头部校验和
    // u_int32 SrcIP; //源IP地址
    IPv4_Addr SrcIP;
    IPv4_Addr DstIP;
    // u_int32 DstIP; //目的IP地址
} IPHeader_t;

//TCP数据报头
typedef struct TCPHeader_t
{ //TCP数据报头
    u_int16 SrcPort;//源端口
    u_int16 DstPort;//目的端口
    u_int32 SeqNO;//序号
    u_int32 AckNO; //确认号
    u_int8 HeaderLen; //数据报头的长度(4 bit) + 保留(4 bit)
    u_int8 Flags; //标识TCP不同的控制消息
    u_int16 Window; //窗口大小
    u_int16 Checksum; //校验和
    u_int16 UrgentPointer;  //紧急指针
}TCPHeader_t;

//UDP数据
typedef struct UDPHeader_s
{
    u_int16 SrcPort;     // 源端口号16bit
    u_int16 DstPort;    // 目的端口号16bit
    u_int16 len;        // 数据包长度16bit
    u_int16 checkSum;   // 校验和16bit
}UDPHeader_t;

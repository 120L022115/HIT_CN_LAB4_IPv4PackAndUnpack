/*
* THIS FILE IS FOR IP TEST
*/
// system support
#include "sysInclude.h"

extern void ip_DiscardPkt(char* pBuffer, int type);

extern void ip_SendtoLower(char*pBuffer, int length);
extern void ip_SendtoUp(char *pBuffer, int length);

extern unsigned int getIpv4Address();

// implemented by students

unsigned getCheckSum(unsigned short* pBuffer, unsigned headLen) {
    unsigned sum = 0;
    int i = 0;
    headLen = headLen / 2;
    while (headLen > i) {
        sum += (unsigned)pBuffer[i];
        i++;
    }
    if (sum & 0xffff != sum) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return sum;
}
int stud_ip_recv(char *pBuffer, unsigned short length)
{
    printf("##### �յ�IPV4���ݰ�");
    //���汾��
    unsigned version = (pBuffer[0]) >> 4;
    printf("##### �汾�ţ� %x\n", version);
    if (version != 4) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
        return 1;
    }
    //���ͷ������
    unsigned headLen = (unsigned)(pBuffer[0]) & 0xf;
    headLen *= 4;
    if (headLen < 20) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
    }
    //�������ʱ��
    unsigned ttl = (unsigned)(pBuffer[8]);
    printf("##### ����ʱ�䣺 %d\n", ttl);
    if (ttl <= 0) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
        return 1;
    }
    //���У���
    if (getCheckSum((unsigned short*)pBuffer, headLen) != 0xffff) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
        return 1;
    }
    //�����ܵ�ַ
    unsigned localAddr = getIpv4Address();
    unsigned recvAddr = ((unsigned*)pBuffer)[4];
    recvAddr = ntohl(recvAddr);
    printf("##### Դ��ַ��%d\n##### Ŀ���ַ��%d\n", localAddr, recvAddr);
    if (localAddr != recvAddr || recvAddr == 0xffffffff) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_DESTINATION_ERROR);
        return 1;
    }
    //����
    printf("##### ���հ�");
    pBuffer += headLen;
    ip_SendtoUp(pBuffer, length - headLen);
    return 0;
}
int stud_ip_Upsend(char *pBuffer, unsigned short len, unsigned int srcAddr,
    unsigned int dstAddr, byte protocol, byte ttl)
{
    printf("##### ����IPv4����\n");
    char* buffer = (char*)malloc(len + 20);
    memcpy(buffer + 20, pBuffer, len);
    //version��headLen��ServiceType��
    buffer[0] = 0x45;
    buffer[1] = 0x0;
    //totalLen
    unsigned short totalLen = len + 20;
    buffer[3] = totalLen & 0xff;
    buffer[2] = totalLen >> 8;
    printf("##### �ܳ���Ϊ %x\n", len + 20);
    //identification
    ((unsigned short*)buffer)[2] = 0;
    //flags fragment offset
    ((unsigned short*)buffer)[3] = 0;
    //ttl
    buffer[8] = ttl;
    printf("##### ������Ϊ %x\n", ttl);
    //protocol
	buffer[9] = protocol;
    printf("##### �ϲ�Э��Ϊ %x\n", protocol);
    //init header checksum
    ((unsigned short*)buffer)[5] = 0;
    //source ip
    ((unsigned*)buffer)[3] = htonl(srcAddr);
    //des ip
    ((unsigned*)buffer)[4] = htonl(dstAddr);
    printf("##### Դ��ַ��%x\n##### Ŀ�ĵ�ַ��%x\n", srcAddr, dstAddr);
    //update checkSUm
    unsigned short checkSum = ~getCheckSum((unsigned short*)buffer, 20);
    ((unsigned short*)buffer)[5] = checkSum;
    printf("##### У���Ϊ %x\n", checkSum);
    //send
    ip_SendtoLower(buffer, len + 20);
    return 0;
}



typedef unsigned short uint16;
typedef unsigned char uint8;
typedef unsigned int uint32;

typedef struct _PacketHdr
{
	uint16 UnZipLen;  //未压缩前的长度
	uint16 ZipLen; //压缩后的长度
    uint32 Seq;//包的编号 
}PacketHdr;

typedef void (CALLBACK *pf_callback)(uint8 * pData,uint32 uSize);

class CpacketHandler
{
public:
	CpacketHandler(pf_callback func)
	{

	}
	~CpacketHandler()
	{

	}

	BOOL ProcessPacket(PacketHdr *hdr);

private:


};

//.,.... 尼玛  有时间再搞了  受不了了。。。。



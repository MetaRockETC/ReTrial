#include <stdlib.h>
#include <stdio.h>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include "TcpReassembly.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
// #include "PlatformSpecificUtils.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "PacketUtils.h"
#include "LRUList.h"
#include <getopt.h>
#include "SSLLayer.h"
#include <vector>
#include "string"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <iostream>
#include <string.h>
#include <string>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <list>
#include <algorithm>  
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "UdpLayer.h"
#include "IpAddress.h"
#include <set>
#include <numeric>
#include <math.h>
#include <algorithm>
#include <sstream>

using namespace pcpp;

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)


#define varName(x) #x
#define printExp(exp) cout<<#exp<<"为:\t\t"<<(exp)<<endl
#define printExpToString(exp) cout<<(string(#exp)+"为:\t\t")<<(exp).toString()<<endl //注意exp加括号更安全

#if defined(WIN32) || defined(WINx64)
#define SEPARATOR '\\'
#else
#define SEPARATOR '/'
#endif


// unless the user chooses otherwise - default number of concurrent used file descriptors is 500
#define DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES 500

#define MAX_RECORD_LAYER_SIZE_SEQ_INDEX 20
#define MAX_PACKET_SIZE_SEQ_INDEX 20
#define MAX_ARRIVE_TIME_SEQ_INDEX 50
#define TOTAL_CIPHER_SUITES 361 + 1
#define TOTAL_EXTENSIONS 28
#define MAX_RECORD_LAYER_LEN 16408
#define MAX_SSL_VERSION 4
#define MAX_FLOW_BYTES 3000

static struct option GetFeatureOptions[] =
{
	{"input-dir",  required_argument, 0, 'r'},
	{"output-file", required_argument, 0, 'o'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};


float dropRate;


/**
 * A singleton class containing the configuration as requested by the user. This singleton is used throughout the application
 */
class GlobalConfig
{
private:

	/**
	 * A private c'tor (as this is a singleton)
	 */
	GlobalConfig() { 
		reopen = false;
		CipherSuiteIDToIndexMap = createCipherSuiteIDToIndexMap();
		SSLExtensionTypeToIndexMap = createSSLExtensionTypeToIndexMap();
		SSLVersionToIndexMap = createSSLVersionToIndexMap();
	}

public:

	// the directory to write files to (default is current directory)
	std::string outputFile;

	// whether to reopen
	bool reopen;

	// a label to stand for the attribution of a pcap file
	// int label;
		
	std::map<uint16_t, int> CipherSuiteIDToIndexMap;
	std::map<uint32_t, int> SSL2CipherSuiteIDToIndexMap;
	std::map<SSLExtensionType, int> SSLExtensionTypeToIndexMap;
	std::map<uint16_t, int> SSLVersionToIndexMap;
	// file to write
	std::ostream* fileStream;

	// pcap file
	std::string pcap_file;

	/**
	 * Open a file stream. Inputs are the filename to open and a flag indicating whether to append to an existing file or overwrite it.
	 * Return value is a pointer to the new file stream
	 */	
	void openFileStream()
	{

		// open the file on the disk (with append or overwrite mode)
		if (reopen)
			fileStream = new std::ofstream(outputFile.c_str(), std::ios_base::binary | std::ios_base::app);
		else
			fileStream = new std::ofstream(outputFile.c_str(), std::ios_base::binary);
	}
	/**
	 * Close a file stream
	 */
	void closeFileSteam()
	{

		// close the file stream
		std::ofstream* fstream = (std::ofstream*)fileStream;
		fstream->close();

		// free the memory of the file stream
		delete fstream;
	}

	/**
	 * get a pcap file label
	 */
	// void getLabel(std::string fileName){
	// 	if((fileName.find("botnet") != fileName.npos) || (fileName.find("black") != fileName.npos) || (fileName.find("ctu-13") != fileName.npos)){
	// 		label = 1;
	// 	} else if((fileName.find("normal") != fileName.npos) || (fileName.find("white") != fileName.npos)  || (fileName.find("benign") != fileName.npos)){
	// 		label = 0;
	// 	}
	// }

	std::vector<std::string> split(const char *s, const char *delim)
	{
		std::vector<std::string> result;
		if (s && strlen(s))
		{
			int len = strlen(s);
			char *src = new char[len + 1];
			strcpy(src, s);
			src[len] = '\0';
			char *tokenptr = strtok(src, delim);
			while (tokenptr != NULL)
			{
				std::string tk = tokenptr;
				result.push_back(tk);
				tokenptr = strtok(NULL, delim);
			}
		}
		return result;
	}

	static std::map<uint16_t, int> createCipherSuiteIDToIndexMap()
	{
		std::map<uint16_t, int> result;

		result[0x0000] = 0;
		result[0x0001] = 1;
		result[0x0002] = 2;
		result[0x0003] = 3;
		result[0x0004] = 4;
		result[0x0005] = 5;
		result[0x0006] = 6;
		result[0x0007] = 7;
		result[0x0008] = 8;
		result[0x0009] = 9;
		result[0x000A] = 10;
		result[0x000B] = 11;
		result[0x000C] = 12;
		result[0x000D] = 13;
		result[0x000E] = 14;
		result[0x000F] = 15;
		result[0x0010] = 16;
		result[0x0011] = 17;
		result[0x0012] = 18;
		result[0x0013] = 19;
		result[0x0014] = 20;
		result[0x0015] = 21;
		result[0x0016] = 22;
		result[0x0017] = 23;
		result[0x0018] = 24;
		result[0x0019] = 25;
		result[0x001A] = 26;
		result[0x001B] = 27;
		result[0x001E] = 28;
		result[0x001F] = 29;
		result[0x0020] = 30;
		result[0x0021] = 31;
		result[0x0022] = 32;
		result[0x0023] = 33;
		result[0x0024] = 34;
		result[0x0025] = 35;
		result[0x0026] = 36;
		result[0x0027] = 37;
		result[0x0028] = 38;
		result[0x0029] = 39;
		result[0x002A] = 40;
		result[0x002B] = 41;
		result[0x002C] = 42;
		result[0x002D] = 43;
		result[0x002E] = 44;
		result[0x002F] = 45;
		result[0x0030] = 46;
		result[0x0031] = 47;
		result[0x0032] = 48;
		result[0x0033] = 49;
		result[0x0034] = 50;
		result[0x0035] = 51;
		result[0x0036] = 52;
		result[0x0037] = 53;
		result[0x0038] = 54;
		result[0x0039] = 55;
		result[0x003A] = 56;
		result[0x003B] = 57;
		result[0x003C] = 58;
		result[0x003D] = 59;
		result[0x003E] = 60;
		result[0x003F] = 61;
		result[0x0040] = 62;
		result[0x0041] = 63;
		result[0x0042] = 64;
		result[0x0043] = 65;
		result[0x0044] = 66;
		result[0x0045] = 67;
		result[0x0046] = 68;
		result[0x0067] = 69;
		result[0x0068] = 70;
		result[0x0069] = 71;
		result[0x006A] = 72;
		result[0x006B] = 73;
		result[0x006C] = 74;
		result[0x006D] = 75;
		result[0x0084] = 76;
		result[0x0085] = 77;
		result[0x0086] = 78;
		result[0x0087] = 79;
		result[0x0088] = 80;
		result[0x0089] = 81;
		result[0x008A] = 82;
		result[0x008B] = 83;
		result[0x008C] = 84;
		result[0x008D] = 85;
		result[0x008E] = 86;
		result[0x008F] = 87;
		result[0x0090] = 88;
		result[0x0091] = 89;
		result[0x0092] = 90;
		result[0x0093] = 91;
		result[0x0094] = 92;
		result[0x0095] = 93;
		result[0x0096] = 94;
		result[0x0097] = 95;
		result[0x0098] = 96;
		result[0x0099] = 97;
		result[0x009A] = 98;
		result[0x009B] = 99;
		result[0x009C] = 100;
		result[0x009D] = 101;
		result[0x009E] = 102;
		result[0x009F] = 103;
		result[0x00A0] = 104;
		result[0x00A1] = 105;
		result[0x00A2] = 106;
		result[0x00A3] = 107;
		result[0x00A4] = 108;
		result[0x00A5] = 109;
		result[0x00A6] = 110;
		result[0x00A7] = 111;
		result[0x00A8] = 112;
		result[0x00A9] = 113;
		result[0x00AA] = 114;
		result[0x00AB] = 115;
		result[0x00AC] = 116;
		result[0x00AD] = 117;
		result[0x00AE] = 118;
		result[0x00AF] = 119;
		result[0x00B0] = 120;
		result[0x00B1] = 121;
		result[0x00B2] = 122;
		result[0x00B3] = 123;
		result[0x00B4] = 124;
		result[0x00B5] = 125;
		result[0x00B6] = 126;
		result[0x00B7] = 127;
		result[0x00B8] = 128;
		result[0x00B9] = 129;
		result[0x00BA] = 130;
		result[0x00BB] = 131;
		result[0x00BC] = 132;
		result[0x00BD] = 133;
		result[0x00BE] = 134;
		result[0x00BF] = 135;
		result[0x00C0] = 136;
		result[0x00C1] = 137;
		result[0x00C2] = 138;
		result[0x00C3] = 139;
		result[0x00C4] = 140;
		result[0x00C5] = 141;
		result[0xC001] = 142;
		result[0xC002] = 143;
		result[0xC003] = 144;
		result[0xC004] = 145;
		result[0xC005] = 146;
		result[0xC006] = 147;
		result[0xC007] = 148;
		result[0xC008] = 149;
		result[0xC009] = 150;
		result[0xC00A] = 151;
		result[0xC00B] = 152;
		result[0xC00C] = 153;
		result[0xC00D] = 154;
		result[0xC00E] = 155;
		result[0xC00F] = 156;
		result[0xC010] = 157;
		result[0xC011] = 158;
		result[0xC012] = 159;
		result[0xC013] = 160;
		result[0xC014] = 161;
		result[0xC015] = 162;
		result[0xC016] = 163;
		result[0xC017] = 164;
		result[0xC018] = 165;
		result[0xC019] = 166;
		result[0xC01A] = 167;
		result[0xC01B] = 168;
		result[0xC01C] = 169;
		result[0xC01D] = 170;
		result[0xC01E] = 171;
		result[0xC01F] = 172;
		result[0xC020] = 173;
		result[0xC021] = 174;
		result[0xC022] = 175;
		result[0xC023] = 176;
		result[0xC024] = 177;
		result[0xC025] = 178;
		result[0xC026] = 179;
		result[0xC027] = 180;
		result[0xC028] = 181;
		result[0xC029] = 182;
		result[0xC02A] = 183;
		result[0xC02B] = 184;
		result[0xC02C] = 185;
		result[0xC02D] = 186;
		result[0xC02E] = 187;
		result[0xC02F] = 188;
		result[0xC030] = 189;
		result[0xC031] = 190;
		result[0xC032] = 191;
		result[0xC033] = 192;
		result[0xC034] = 193;
		result[0xC035] = 194;
		result[0xC036] = 195;
		result[0xC037] = 196;
		result[0xC038] = 197;
		result[0xC039] = 198;
		result[0xC03A] = 199;
		result[0xC03B] = 200;
		result[0xC03C] = 201;
		result[0xC03D] = 202;
		result[0xC03E] = 203;
		result[0xC03F] = 204;
		result[0xC040] = 205;
		result[0xC041] = 206;
		result[0xC042] = 207;
		result[0xC043] = 208;
		result[0xC044] = 209;
		result[0xC045] = 210;
		result[0xC046] = 211;
		result[0xC047] = 212;
		result[0xC048] = 213;
		result[0xC049] = 214;
		result[0xC04A] = 215;
		result[0xC04B] = 216;
		result[0xC04C] = 217;
		result[0xC04D] = 218;
		result[0xC04E] = 219;
		result[0xC04F] = 220;
		result[0xC050] = 221;
		result[0xC051] = 222;
		result[0xC052] = 223;
		result[0xC053] = 224;
		result[0xC054] = 225;
		result[0xC055] = 226;
		result[0xC056] = 227;
		result[0xC057] = 228;
		result[0xC058] = 229;
		result[0xC059] = 230;
		result[0xC05A] = 231;
		result[0xC05B] = 232;
		result[0xC05C] = 233;
		result[0xC05D] = 234;
		result[0xC05E] = 235;
		result[0xC05F] = 236;
		result[0xC060] = 237;
		result[0xC061] = 238;
		result[0xC062] = 239;
		result[0xC063] = 240;
		result[0xC064] = 241;
		result[0xC065] = 242;
		result[0xC066] = 243;
		result[0xC067] = 244;
		result[0xC068] = 245;
		result[0xC069] = 246;
		result[0xC06A] = 247;
		result[0xC06B] = 248;
		result[0xC06C] = 249;
		result[0xC06D] = 250;
		result[0xC06E] = 251;
		result[0xC06F] = 252;
		result[0xC070] = 253;
		result[0xC071] = 254;
		result[0xC072] = 255;
		result[0xC073] = 256;
		result[0xC074] = 257;
		result[0xC075] = 258;
		result[0xC076] = 259;
		result[0xC077] = 260;
		result[0xC078] = 261;
		result[0xC079] = 262;
		result[0xC07A] = 263;
		result[0xC07B] = 264;
		result[0xC07C] = 265;
		result[0xC07D] = 266;
		result[0xC07E] = 267;
		result[0xC07F] = 268;
		result[0xC080] = 269;
		result[0xC081] = 270;
		result[0xC082] = 271;
		result[0xC083] = 272;
		result[0xC084] = 273;
		result[0xC085] = 274;
		result[0xC086] = 275;
		result[0xC087] = 276;
		result[0xC088] = 277;
		result[0xC089] = 278;
		result[0xC08A] = 279;
		result[0xC08B] = 280;
		result[0xC08C] = 281;
		result[0xC08D] = 282;
		result[0xC08E] = 283;
		result[0xC08F] = 284;
		result[0xC090] = 285;
		result[0xC091] = 286;
		result[0xC092] = 287;
		result[0xC093] = 288;
		result[0xC094] = 289;
		result[0xC095] = 290;
		result[0xC096] = 291;
		result[0xC097] = 292;
		result[0xC098] = 293;
		result[0xC099] = 294;
		result[0xC09A] = 295;
		result[0xC09B] = 296;
		result[0xC09C] = 297;
		result[0xC09D] = 298;
		result[0xC09E] = 299;
		result[0xC09F] = 300;
		result[0xC0A0] = 301;
		result[0xC0A1] = 302;
		result[0xC0A2] = 303;
		result[0xC0A3] = 304;
		result[0xC0A4] = 305;
		result[0xC0A5] = 306;
		result[0xC0A6] = 307;
		result[0xC0A7] = 308;
		result[0xC0A8] = 309;
		result[0xC0A9] = 310;
		result[0xC0AA] = 311;
		result[0xC0AB] = 312;
		result[0xC0AC] = 313;
		result[0xC0AD] = 314;
		result[0xC0AE] = 315;
		result[0xC0AF] = 316;
		result[0xCCA8] = 317;
		result[0xCCA9] = 318;
		result[0xCCAA] = 319;
		result[0xCCAB] = 320;
		result[0xCCAC] = 321;
		result[0xCCAD] = 322;
		result[0xCCAE] = 323;

		return result;
	}

	
	static std::map<SSLExtensionType, int> createSSLExtensionTypeToIndexMap(){
		std::map<SSLExtensionType, int> result;
		/** Server Name Indication extension */
		result[SSL_EXT_SERVER_NAME] = 0,
		/** Maximum Fragment Length Negotiation extension */
		result[SSL_EXT_MAX_FRAGMENT_LENGTH] = 1,
		/** Client Certificate URLs extension */
		result[SSL_EXT_CLIENT_CERTIFICATE_URL] = 2,
		/** Trusted CA Indication extension */
		result[SSL_EXT_TRUSTED_CA_KEYS] = 3,
		/** Truncated HMAC extension */
		result[SSL_EXT_TRUNCATED_HMAC] = 4,
		/** Certificate Status Request extension */
		result[SSL_EXT_STATUS_REQUEST] = 5,
		/** TLS User Mapping extension */
		result[SSL_EXT_USER_MAPPING] = 6,
		/** Client Authorization  extension */
		result[SSL_EXT_CLIENT_AUTHZ] = 7,
		/** Server Authorization extension */
		result[SSL_EXT_SERVER_AUTHZ] = 8,
		/** Certificate Type extension */
		result[SSL_EXT_CERT_TYPE] = 9,
		/** Supported Elliptic Curves extension */
		result[SSL_EXT_SUPPORTED_GROUPS] = 10,
		/** Elliptic Curves Point Format extension */
		result[SSL_EXT_EC_POINT_FORMATS] = 11,
		/** Secure Remote Password extension */
		result[SSL_EXT_SRP] = 12,
		/** Signature Algorithms extension */
		result[SSL_EXT_SIGNATURE_ALGORITHMS] = 13,
		/** Use Secure Real-time Transport Protocol extension */
		result[SSL_EXT_USE_SRTP] = 14,
		/** TLS Heartbit extension */
		result[SSL_EXT_HEARTBEAT] = 15,
		/** Application Layer Protocol Negotiation (ALPN) extension */
		result[SSL_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION]= 16,
		/** Status Request extension */
		result[SSL_EXT_STATUS_REQUEST_V2] = 17,
		/** Signed Certificate Timestamp extension */
		result[SSL_EXT_SIGNED_CERTIFICATE_TIMESTAMP] = 18,
		/** Client Certificate Type extension */
		result[SSL_EXT_CLIENT_CERTIFICATE_TYPE] = 19,
		/** Server Certificate Type extension */
		result[SSL_EXT_SERVER_CERTIFICATE_TYPE] = 20,
		/** ClientHello Padding extension */
		result[SSL_EXT_PADDING] = 21,
		/** Encrypt-then-MAC extension */
		result[SSL_EXT_ENCRYPT_THEN_MAC] = 22,
		/** Extended Master Secret extension */
		result[SSL_EXT_EXTENDED_MASTER_SECRET] = 23,
		/** Token Binding extension */
		result[SSL_EXT_TOKEN_BINDING] = 24,
		/** SessionTicket TLS extension */
		result[SSL_EXT_SESSIONTICKET_TLS] = 25,
		/** Renegotiation Indication extension */
		result[SSL_EXT_RENEGOTIATION_INFO] = 26,
		/** Unknown extension */
		result[SSL_EXT_Unknown] = 27;

		return result;
	}

	static std::map<uint16_t, int> createSSLVersionToIndexMap(){
		std::map<uint16_t, int> result;

		result[SSLVersion::SSL3] = 0;
		result[SSLVersion::TLS1_0] = 1;
		result[SSLVersion::TLS1_1] = 2;
		result[SSLVersion::TLS1_2] = 3;
		return result;
	}

	/**
	 * The singleton implementation of this class
	 */
	static GlobalConfig& getInstance()
	{
		static GlobalConfig instance;
		return instance;
	}
	
	/**
	 * d'tor
	 */
	~GlobalConfig(){}
};

struct reassemmbledTcpPayloadCookie{
	// whether client hello appear
	bool getClientHello;
	// whether server hello appear
	bool getServerHello;
	// whether certificate message appear
	bool getCertificate;
	// whether server hello done appear
	bool getServerHelloDone;
	// whether client change cipher Sepc appear
	bool clientChangeCipher;
	// whether server change cipher Sepc appear
	bool serverChangeCipher;
    // whether client encrypted handshake message appear
	bool clientEncryptedHandshakeMessage;
    // whether server encrypted handshake message appear
	bool serverEncryptedHandshakeMessage;
	// whether handshake succeed
	bool handshakeSuccess;
	// whether have application data
	bool appData;
	// current ssl record layer total length
	int recordLayerLen;
	// current ssl record layer data length
	int dataLen;
	// last side direction
	int lastSideIndex;	
	// last packet remain segmentation length
	int lastRemainSegSize;	
	// certificate data remain length
	int certificateCurrentSize;
	// certificate data total length
	int certificateTotalSize;
	// last packet arrive time
	timeval lastArriveTime;
	// last packet remain segmentation
	uint8_t lastRemainSeg[1500];
	// collect certificate data
	uint8_t certificateData[MAX_RECORD_LAYER_LEN];

	void clear(){
		getClientHello = false;
		getServerHello = false;
		getCertificate = false;
		getServerHelloDone = false;
		clientChangeCipher = false;
		serverChangeCipher = false;
		clientEncryptedHandshakeMessage = false;
		serverEncryptedHandshakeMessage = false;
		handshakeSuccess = false;
		appData = false;
		recordLayerLen = 0;
		dataLen = 0;
		lastSideIndex = -1;
		lastRemainSegSize = 0;
		certificateCurrentSize = 0;
		certificateTotalSize = 0;	
		lastArriveTime.tv_sec = 0;
		lastArriveTime.tv_usec = 0;			
		memset(lastRemainSeg, 0, sizeof(lastRemainSeg));
		memset(certificateData, 0, sizeof(certificateData));		
	}
	reassemmbledTcpPayloadCookie() {
		clear();
	} 
};

/**
 * A struct to contain all data save on a specific connection. It contains the file streams to write to and also stats data on the connection
 */
struct SSLStreamFeatures
{
	std::string srcIP;
	std::string dstIP;
	int srcPort;
	int dstPort;

	// label
	// int label;
	
	// tool(统计单流时使用，如标记index，不作为特征)
	int rawBytesIndex;
	int recordLayerSizeSequenceIndex;
	int packetSizeSequenceIndex;
	int clientCipherSuitesIndex;
	int clientExtensionsIndex;
	int serverCipherSuitesIndex;
	int serverExtensionsIndex;

	uint16_t clientCipherSuites[TOTAL_CIPHER_SUITES];
	uint16_t serverCipherSuites[TOTAL_CIPHER_SUITES];
	SSLExtensionType clientExtensions[TOTAL_EXTENSIONS];
	SSLExtensionType serverExtensions[TOTAL_EXTENSIONS];
	uint16_t clientHelloSSLVersion; // client hello 使用的ssl版本
	uint16_t latestSupportedSSLVersion;
    uint16_t serverHelloSSLVersion; // server hello 使用的ssl版本

	// raw data
	int rawBytes[MAX_FLOW_BYTES]; // gather two-direction flows

	// features
	// 是否是443端口
	bool useCommonPort;

	// 密码/扩展独热编码
	int cipherSuitesOneHot[TOTAL_CIPHER_SUITES];
	int extensionsOneHot[TOTAL_EXTENSIONS];
	// 包/字节方向计数
	int numOfDataPackets[2];
	int bytesFromSide[2];
	// 握手后包/字节计数
	int numOfPacketsAfterHandshake[2];
	int bytesFromSideAfterHandshake[2]; 
	
	//Session ID判断
	bool isResumption; // 是否是重传

	// Hostname
	bool hasHostName;
	bool isHostNameIP;
	bool isHostNameDstIP;
	bool isHostNameDomain;

	// ja3
	std::string JA3;
	std::string JA3S;


	//Certificate
	int certificateNum;
	//流持续时间
	__suseconds_t duringTime;
	// record layer size序列
	int recordLayerSizeSequence[MAX_RECORD_LAYER_SIZE_SEQ_INDEX];

	// packet size sequence
	int packetSizeSequence[MAX_PACKET_SIZE_SEQ_INDEX];
	
	int SSLVersionOneHot[MAX_SSL_VERSION];

	char hostName[256];	// 从SNI扩展提取的host name
	reassemmbledTcpPayloadCookie cookie;
	/**
	 * the default c'tor
	 */
	SSLStreamFeatures() {
		clear();
	}

	void clear(){
		srcIP = "";
		dstIP = "";
		srcPort = 0;
		dstPort = 0;
		// label = 0;

		rawBytesIndex = 0;
		recordLayerSizeSequenceIndex = 0;
		packetSizeSequenceIndex = 0;
		clientCipherSuitesIndex = 0;
		clientExtensionsIndex = 0;
		serverCipherSuitesIndex = 0;
		serverExtensionsIndex = 0;


		memset(rawBytes, 0, sizeof(rawBytes));	
		useCommonPort = true;
		numOfDataPackets[0] = 0; numOfDataPackets[1] = 0;
		bytesFromSide[0] = 0; bytesFromSide[1] = 0;
	 	numOfPacketsAfterHandshake[0] = 0; numOfPacketsAfterHandshake[1] = 0;
		bytesFromSideAfterHandshake[0] = 0; bytesFromSideAfterHandshake[1] = 0;


		memset(clientCipherSuites, 0, sizeof(clientCipherSuites));
		memset(serverCipherSuites, 0, sizeof(serverCipherSuites));
		memset(cipherSuitesOneHot, 0, sizeof(cipherSuitesOneHot));

		memset(clientExtensions, 0, sizeof(clientExtensions));
		memset(serverExtensions, 0, sizeof(serverExtensions));
		memset(extensionsOneHot, 0, sizeof(extensionsOneHot));

		memset(SSLVersionOneHot, 0, sizeof(SSLVersionOneHot));

		isResumption = false; // 是否是重传
        hasHostName = false;
		isHostNameIP = false;
		isHostNameDstIP = false;
		isHostNameDomain = false;
		certificateNum = 0;
		duringTime = 0; // 流持续时间

		memset(recordLayerSizeSequence, 0, sizeof(recordLayerSizeSequence));
		recordLayerSizeSequenceIndex = 0;	

		memset(packetSizeSequence, 0, sizeof(packetSizeSequence));
		packetSizeSequenceIndex = 0;	

		clientHelloSSLVersion = SSLVersion::SSL3;
		latestSupportedSSLVersion = SSLVersion::SSL3;
		serverHelloSSLVersion = SSLVersion::SSL3;
		memset(SSLVersionOneHot, 0, sizeof(SSLVersionOneHot));
		memset(hostName, 0, sizeof(hostName));
		cookie.clear();
	}

	/**
	 * The default d'tor
	 */
	~SSLStreamFeatures(){}
};


typedef std::map<uint32_t, SSLStreamFeatures> TcpReassemblyConnMgr;
typedef std::map<uint32_t, SSLStreamFeatures>::iterator TcpReassemblyConnMgrIter;


TcpReassemblyConnMgr *globalConnMgr = new TcpReassemblyConnMgr();


void printUsage()
{
	printf("\nUsage:\n"
			"------\n"
			"%s [-hvlcms] [-r input_file] [-i interface] [-o output_file] [-e bpf_filter] [-f max_files]\n"
			"\nOptions:\n\n"
			"    -r input_file : Input pcap/pcapng file to analyze. Required argument for reading from file\n"
			"    -o output_file : Specify output file (default is '.')\n"
			"    -d drop_rate    : Drop packets randomly with the specific rate"
			"    -h            : Display this help message and exit\n\n", AppName::get().c_str());
	exit(0);
}

/**
 * travel through the given dir, return a file name list.
 */
std::list<std::string> walkDir(std::string dirName){  
	
	char* dir_name = (char*)dirName.data();
    std::list<std::string> pcapList;

    if(!strcmp(dir_name, "")) return pcapList;
      
    struct dirent * filename;
    DIR * dir;
    dir = opendir(dir_name);  

    if(NULL == dir)  
    {  
        return pcapList;  
    }  

    while((filename = readdir(dir)) != NULL)  
    {  
        char wholePath[256] = {0};
		std::string d_name = filename->d_name;
		if((d_name == ".") || (d_name == "..")) continue;
        sprintf(wholePath, "%s/%s", dir_name, filename->d_name);

		struct stat s;  
		lstat(wholePath , &s);  
		if(S_ISDIR(s.st_mode))  
		{
			std::cout << wholePath << " is a directory." << std::endl;
			std::list<std::string> subDir_pcapList = walkDir(wholePath);
			pcapList.insert(pcapList.end(), subDir_pcapList.begin(), subDir_pcapList.end());
		} else if(S_ISREG(s.st_mode)){
			if(int(d_name.find(".pcap")) == -1)
				continue;
			pcapList.push_back(wholePath);				
		} 
    }
    return pcapList;
}

/**
 * The callback being called by the TCP reassembly module whenever new data arrives on a certain connection
 */
static void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const TcpStreamData& tcpData, void* userCookie)
{		

	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*) userCookie;			
	TcpReassemblyConnMgrIter iter = connMgr->find(tcpData.getConnectionData().flowKey);

	if(iter == connMgr->end()){
		SSLStreamFeatures sslStreamFeatures = SSLStreamFeatures();
		connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, sslStreamFeatures));
		iter = connMgr->find(tcpData.getConnectionData().flowKey);
	} 

	SSLStreamFeatures* sslStreamFeatures = &(iter->second);
	
	// 统计不同方向的包和字节(包括握手前握手后)
	sslStreamFeatures->numOfDataPackets[sideIndex]++;
	sslStreamFeatures->bytesFromSide[sideIndex] += (int)tcpData.getDataLength();			
	if(sslStreamFeatures->cookie.handshakeSuccess == true){
		sslStreamFeatures->numOfPacketsAfterHandshake[sideIndex]++;
		sslStreamFeatures->bytesFromSideAfterHandshake[sideIndex] += (int)tcpData.getDataLength();		
	}

	uint8_t* dataPtr;
	int dataLen;

	dataPtr = const_cast<uint8_t*>(tcpData.getData());
	dataLen = tcpData.getDataLength();		

	int packetSizeSequenceIndex = sslStreamFeatures->packetSizeSequenceIndex;

	if(packetSizeSequenceIndex < MAX_RECORD_LAYER_SIZE_SEQ_INDEX){
		sslStreamFeatures->packetSizeSequence[packetSizeSequenceIndex] = (int)(dataLen)*(sideIndex - 0.5)*2;
		sslStreamFeatures->packetSizeSequenceIndex++;
	}

	while(true){
		if (SSLLayer::IsSSLMessage(0, 0, dataPtr, dataLen, true)){
			// std::cout <<"Is SSL Message." << std::endl;
			SSLLayer* curLayer = SSLLayer::createSSLMessage(dataPtr, dataLen, NULL, NULL);		
			// first handle the record layer entirely allocated in one packet
			while (curLayer != NULL)
			{	
				float p = (float)(rand()/(float)RAND_MAX);
	
				if (p < dropRate)
				{
					return;
				}
				switch (curLayer->getRecordLayer()->recordType)
				{
					case SSL_HANDSHAKE:
					{						
						SSLHandshakeLayer* sslHandshakeLayer = dynamic_cast<SSLHandshakeLayer*> (curLayer);

						// Client Hello
						if(sslHandshakeLayer->getHandshakeMessageOfType<SSLClientHelloMessage>() != NULL && sideIndex == 0 && sslStreamFeatures->cookie.getClientHello == false) {
							sslStreamFeatures->cookie.getClientHello = true;
							sslStreamFeatures->clientHelloSSLVersion = curLayer->getRecordVersion().asEnum(true);
							SSLClientHelloMessage* sslClientHelloMessage = sslHandshakeLayer->getHandshakeMessageOfType<SSLClientHelloMessage>();
							// client hello 当前使用SSL/TLS版本
							sslStreamFeatures->clientHelloSSLVersion = curLayer->getRecordVersion().asEnum(true);
							sslStreamFeatures->SSLVersionOneHot[GlobalConfig::getInstance().SSLVersionToIndexMap[curLayer->getRecordVersion().asEnum(true)]]++;
							// client hello 支持的最高tls版本
							sslStreamFeatures->latestSupportedSSLVersion = sslClientHelloMessage->getHandshakeVersion().asEnum(true);
							sslStreamFeatures->SSLVersionOneHot[GlobalConfig::getInstance().SSLVersionToIndexMap[sslClientHelloMessage->getHandshakeVersion().asEnum(true)]]++;

							// ja3
							pcpp::SSLClientHelloMessage::ClientHelloTLSFingerprint tlsFingerprint = sslClientHelloMessage->generateTLSFingerprint();
							std::pair<std::string, std::string> tlsFingerprintStringAndMD5 = tlsFingerprint.toStringAndMD5();
							// printf("ClientHello (JA3) TLS fingerprint: '%s'; MD5: '%s'\n", tlsFingerprintStringAndMD5.first.c_str(), tlsFingerprintStringAndMD5.second.c_str());
						
							sslStreamFeatures->JA3 = tlsFingerprintStringAndMD5.second;

							// 收集握手字节流
							int sessionIDLen = sslClientHelloMessage->getSessionIDLength();
							sslStreamFeatures->isResumption = (sessionIDLen > 0)? true: false;

							// 加密套件
							for(int i = 0; i < sslClientHelloMessage->getCipherSuiteCount(); i++){
								SSLCipherSuite* sslCipherSuite = sslClientHelloMessage->getCipherSuite(i);
								if(sslCipherSuite == NULL){
									sslStreamFeatures->clientCipherSuites[sslStreamFeatures->clientCipherSuitesIndex] = TOTAL_CIPHER_SUITES - 1;
									sslStreamFeatures->clientCipherSuitesIndex++;
									sslStreamFeatures->cipherSuitesOneHot[TOTAL_CIPHER_SUITES - 1]++;
									continue;
								}
								sslStreamFeatures->clientCipherSuites[sslStreamFeatures->clientCipherSuitesIndex] = sslCipherSuite->getID();
								sslStreamFeatures->clientCipherSuitesIndex++;
								sslStreamFeatures->cipherSuitesOneHot[GlobalConfig::getInstance().CipherSuiteIDToIndexMap[sslCipherSuite->getID()]]++;
							}
							// 统计扩展
							for(int i = 0; i < sslClientHelloMessage->getExtensionCount(); i++){
								SSLExtension* sslExtension = sslClientHelloMessage->getExtension(i);
								SSLExtensionType sslExtensionType = sslExtension->getType();
								sslStreamFeatures->clientExtensions[sslStreamFeatures->clientExtensionsIndex] = sslExtensionType;
								sslStreamFeatures->clientExtensionsIndex++;
								sslStreamFeatures->extensionsOneHot[GlobalConfig::getInstance().SSLExtensionTypeToIndexMap[sslExtensionType]]++;
							}
							//收集Server Name Indication extension
							if(sslClientHelloMessage->getExtensionOfType(SSL_EXT_SERVER_NAME) != NULL){ 
								SSLServerNameIndicationExtension* sslServerNameIndicationExtension = dynamic_cast<SSLServerNameIndicationExtension*>(sslClientHelloMessage->getExtensionOfType(SSL_EXT_SERVER_NAME));
								std::string hostName = sslServerNameIndicationExtension->getHostName();
								strncpy(sslStreamFeatures->hostName, hostName.c_str(), hostName.length() + 1);
								sslStreamFeatures->hasHostName = true;

								if(IPAddress(hostName).isValid()){
									sslStreamFeatures->isHostNameIP = true;
									if(hostName.compare(tcpData.getConnectionData().dstIP.toString()) == 0){
										sslStreamFeatures->isHostNameDstIP = true;
									}
								} 
								else {
									sslStreamFeatures->isHostNameDomain = true;
								} 
							}	
						}

						// 判断Client Hello 是否收到
						if(sslStreamFeatures->cookie.getClientHello == false) return;	

						// Server Hello
						if(sslHandshakeLayer->getHandshakeMessageOfType<SSLServerHelloMessage>() != NULL && sideIndex == 1 && sslStreamFeatures->cookie.getServerHello == false) {
							sslStreamFeatures->cookie.getServerHello = true;
							sslStreamFeatures->serverHelloSSLVersion = curLayer->getRecordVersion().asEnum(true);
							sslStreamFeatures->SSLVersionOneHot[GlobalConfig::getInstance().SSLVersionToIndexMap[curLayer->getRecordVersion().asEnum(true)]]++;
							SSLServerHelloMessage* sslServerHelloMessage = sslHandshakeLayer->getHandshakeMessageOfType<SSLServerHelloMessage>();
							// uint8_t* msg_Data = sslServerHelloMessage->getPayloadPointer();
							// int msg_DataLen = sslServerHelloMessage->getMessageLength();
							// int remain = MAX_FLOW_BYTES - sslStreamFeatures->rawBytesIndex;
							// for(int i = 0; i < std::min(msg_DataLen, remain); i++, sslStreamFeatures->rawBytesIndex++){
							// 	sslStreamFeatures->rawBytes[sslStreamFeatures->rawBytesIndex] = *(msg_Data + i);
							// }									
							// 统计加密套件
							SSLCipherSuite* sslCipherSuite = sslServerHelloMessage->getCipherSuite();
							if(sslCipherSuite == NULL){
								sslStreamFeatures->serverCipherSuites[sslStreamFeatures->serverCipherSuitesIndex] = TOTAL_CIPHER_SUITES - 1;
								sslStreamFeatures->serverCipherSuitesIndex++;
								sslStreamFeatures->cipherSuitesOneHot[TOTAL_CIPHER_SUITES - 1]++;
							} else {
								sslStreamFeatures->serverCipherSuites[sslStreamFeatures->serverCipherSuitesIndex] = sslCipherSuite->getID();
								sslStreamFeatures->serverCipherSuitesIndex++;
								sslStreamFeatures->cipherSuitesOneHot[GlobalConfig::getInstance().CipherSuiteIDToIndexMap[sslCipherSuite->getID()]]++;								
							}
							// 统计扩展
							for(int i = 0; i < sslServerHelloMessage->getExtensionCount(); i++){
								SSLExtension* sslExtension = sslServerHelloMessage->getExtension(i);
								SSLExtensionType sslExtensionType = sslExtension->getType();
								sslStreamFeatures->serverExtensions[sslStreamFeatures->serverExtensionsIndex] = sslExtensionType;
								sslStreamFeatures->serverExtensionsIndex++;
								sslStreamFeatures->extensionsOneHot[GlobalConfig::getInstance().SSLExtensionTypeToIndexMap[sslExtensionType]]++;
							}

							// ja3s
							pcpp::SSLServerHelloMessage::ServerHelloTLSFingerprint tlsFingerprint = sslServerHelloMessage->generateTLSFingerprint();
							std::pair<std::string, std::string> tlsFingerprintStringAndMD5 = tlsFingerprint.toStringAndMD5();
							// printf("ServerHello (JA3S) TLS fingerprint: '%s'; MD5: '%s'\n", tlsFingerprintStringAndMD5.first.c_str(), tlsFingerprintStringAndMD5.second.c_str());
						
							sslStreamFeatures->JA3S = tlsFingerprintStringAndMD5.second;
						}
						
						// 判断Server Hello 是否收到
						if(sslStreamFeatures->cookie.getServerHello == false) return;	

						// Server Certificate						
						if(sslHandshakeLayer->getHandshakeMessageOfType<SSLCertificateMessage>() != NULL && sideIndex == 1 && sslStreamFeatures->cookie.getCertificate == false && sslStreamFeatures->cookie.clientChangeCipher == false && sslStreamFeatures->cookie.serverChangeCipher == false ) {
							sslStreamFeatures->cookie.getCertificate = true;
							SSLCertificateMessage* sslCertificateMessage = sslHandshakeLayer->getHandshakeMessageOfType<SSLCertificateMessage>();
							ssl_tls_handshake_layer* handshakeLayer = (ssl_tls_handshake_layer*)(curLayer->getData() + sizeof(ssl_tls_record_layer));

							if(sslCertificateMessage->isMessageComplete()){
								// 证书完整
								sslStreamFeatures->certificateNum = sslCertificateMessage->getNumOfCertificates();
								// uint8_t* msg_Data = sslCertificateMessage->getPayloadPointer();
								// int msg_DataLen = sslCertificateMessage->getMessageLength();
								// int remain = MAX_FLOW_BYTES - sslStreamFeatures->rawBytesIndex;
								// for(int i = 0; i < std::min(msg_DataLen, remain); i++, sslStreamFeatures->rawBytesIndex++){
								// 	sslStreamFeatures->rawBytes[sslStreamFeatures->rawBytesIndex] = *(msg_Data + i);
								// }									
							}
							else{
								// 证书不完整
								size_t totalLen = sizeof(ssl_tls_handshake_layer) + be16toh(handshakeLayer->length2);
								size_t dataLen = sslCertificateMessage->getMessageLength();
								sslStreamFeatures->cookie.certificateCurrentSize = dataLen;
								sslStreamFeatures->cookie.certificateTotalSize = totalLen;
								uint8_t* p1 = sslStreamFeatures->cookie.certificateData;
								uint8_t* p2 = curLayer->getData() + sizeof(ssl_tls_record_layer);
								for(int i = 0; i < int(dataLen); i++)
									*p1++ = *p2++;
								*p1 = '\0';
							}
						}

						// Server Hello Done
						if((sslHandshakeLayer->getHandshakeMessageOfType<SSLServerHelloDoneMessage>() != NULL)&&(sideIndex == 1)&&(sslStreamFeatures->cookie.getServerHelloDone == false)) {
							sslStreamFeatures->cookie.getServerHelloDone = true;								
						}

						// Client Encrypted Handshake Message
						if((sideIndex == 0)&&(sslStreamFeatures->cookie.clientChangeCipher == true)&&(sslStreamFeatures->cookie.clientEncryptedHandshakeMessage == false)) {
							sslStreamFeatures->cookie.clientEncryptedHandshakeMessage = true;
						}	
						// Server Encrypted Handshake Message
						if((sideIndex == 1)&&(sslStreamFeatures->cookie.serverChangeCipher == true)&&(sslStreamFeatures->cookie.serverEncryptedHandshakeMessage == false)) {
							sslStreamFeatures->cookie.serverEncryptedHandshakeMessage = true;
						}		
						// 握手是否成功
						if((sslStreamFeatures->cookie.clientEncryptedHandshakeMessage == true)&&(sslStreamFeatures->cookie.serverEncryptedHandshakeMessage == true)){
							sslStreamFeatures->cookie.handshakeSuccess = true;
						}
						break;
					}		

					case SSL_APPLICATION_DATA:
					{
						if(sslStreamFeatures->cookie.getClientHello == false) return;
						sslStreamFeatures->cookie.handshakeSuccess = true;
						sslStreamFeatures->cookie.appData = true;
						int recordLayerSizeSequenceIndex = sslStreamFeatures->recordLayerSizeSequenceIndex;
						if(recordLayerSizeSequenceIndex < MAX_RECORD_LAYER_SIZE_SEQ_INDEX){
							sslStreamFeatures->recordLayerSizeSequence[recordLayerSizeSequenceIndex] = (int)((be16toh(curLayer->getRecordLayer()->length))*(sideIndex - 0.5)*2);
							sslStreamFeatures->recordLayerSizeSequenceIndex++;	
						}
						break;
					}

					case SSL_ALERT:
					{						
						if(sslStreamFeatures->cookie.getClientHello == false) return;
						break;
					}

					case SSL_CHANGE_CIPHER_SPEC:
					{
						if(sslStreamFeatures->cookie.getClientHello == false) return;
						if(sideIndex == 0)
							sslStreamFeatures->cookie.clientChangeCipher = true;
						else if(sideIndex == 1)
							sslStreamFeatures->cookie.serverChangeCipher = true;
						break;						
					}

				}
				// 本tcp包中下一个record layer不完整
				if(curLayer->getDataLen() < be16toh(curLayer->getRecordLayer()->length) + sizeof(ssl_tls_record_layer))
					break;
				// 本tcp包中余下数据刚刚好包含最后一个record layer
				if(curLayer->getDataLen() == be16toh(curLayer->getRecordLayer()->length) + sizeof(ssl_tls_record_layer))
					break;
				// 本tcp包中余下的数据不足以解析下一个record layer的头
				if(curLayer->getDataLen() < be16toh(curLayer->getRecordLayer()->length) + 2*sizeof(ssl_tls_record_layer))
					break;

				curLayer->parseNextLayer();
				// std::cout << "解析下一层" << std::endl;
				if(curLayer->getNextLayer() != NULL){
					// std::cout << "有下一层" << std::endl;
					curLayer = dynamic_cast<SSLLayer*> (curLayer->getNextLayer());
				}	
				else{
					break;
				}	
			}
			
			// judge whether the last record layer is integrated
			if(curLayer->getDataLen() < be16toh(curLayer->getRecordLayer()->length) + sizeof(ssl_tls_record_layer)){
				sslStreamFeatures->cookie.recordLayerLen = be16toh(curLayer->getRecordLayer()->length) + sizeof(ssl_tls_record_layer);
				sslStreamFeatures->cookie.dataLen = curLayer->getDataLen();	
			} 
			else if(curLayer->getDataLen() == be16toh(curLayer->getRecordLayer()->length) + sizeof(ssl_tls_record_layer));
			else if(curLayer->getDataLen() < be16toh(curLayer->getRecordLayer()->length) + 2*sizeof(ssl_tls_record_layer)){
				dataPtr = curLayer->getData() + curLayer->getHeaderLen();
				dataLen = curLayer->getDataLen() - curLayer->getHeaderLen();				
					
				sslStreamFeatures->cookie.lastRemainSegSize = dataLen;
				uint8_t* p1 = sslStreamFeatures->cookie.lastRemainSeg;
				uint8_t* p2 = dataPtr;
				for(int i = 0; i < int(dataLen); i++)
					*p1++ = *p2++;
				*p1 = '\0';
			}
			break;
		} 
		else {
			// std::cout << "不是SSL" << std::endl;
			if(sslStreamFeatures->cookie.getClientHello == false) return;
			if(sslStreamFeatures->cookie.lastRemainSegSize > 0){
				uint8_t* p1 = sslStreamFeatures->cookie.lastRemainSeg + sslStreamFeatures->cookie.lastRemainSegSize;
				uint8_t* p2 = const_cast<uint8_t*>(tcpData.getData());;

				for(int i = 0; i < int(tcpData.getDataLength()); i++)
					*p1++ = *p2++;
				*p1 = '\0';
				dataPtr = sslStreamFeatures->cookie.lastRemainSeg;
				dataLen = tcpData.getDataLength() + sslStreamFeatures->cookie.lastRemainSegSize;
				sslStreamFeatures->cookie.lastRemainSegSize = 0;
				continue;
			}
			// 说明是非SSL/TLS协议,例如SMTP
			if(sslStreamFeatures->cookie.recordLayerLen == 0) return; 
			// 判断证书是否收集完整
			if(sslStreamFeatures->cookie.certificateCurrentSize < sslStreamFeatures->cookie.certificateTotalSize){
				// 证书的分段信息和tcp分段信息分开处理
				uint8_t* p1 = sslStreamFeatures->cookie.certificateData + sslStreamFeatures->cookie.certificateCurrentSize;
				uint8_t* p2 = const_cast<uint8_t*>(tcpData.getData());;
				size_t certificateRemainLen = sslStreamFeatures->cookie.certificateTotalSize - sslStreamFeatures->cookie.certificateCurrentSize;
				size_t copyLen = 0;
				if(certificateRemainLen > tcpData.getDataLength()){
					copyLen = tcpData.getDataLength();
					sslStreamFeatures->cookie.certificateCurrentSize += tcpData.getDataLength();
				}	
				else{
					copyLen = certificateRemainLen;
					sslStreamFeatures->cookie.certificateCurrentSize = sslStreamFeatures->cookie.certificateTotalSize;
				}					
				for(int i = 0; i < int(copyLen); i++)
					*p1++ = *p2++;
				*p1 = '\0';
				// 证书获取完整 
				if(sslStreamFeatures->cookie.certificateCurrentSize == sslStreamFeatures->cookie.certificateTotalSize){
					SSLCertificateMessage sslCertificateMessage = SSLCertificateMessage(sslStreamFeatures->cookie.certificateData, sslStreamFeatures->cookie.certificateTotalSize, NULL);
					sslStreamFeatures->certificateNum = sslCertificateMessage.getNumOfCertificates();

					// uint8_t* msg_Data = sslCertificateMessage.getPayloadPointer();
					// int msg_DataLen = sslCertificateMessage.getMessageLength();
					// int remain = MAX_FLOW_BYTES - sslStreamFeatures->rawBytesIndex;
					// for(int i = 0; i < std::min(msg_DataLen, remain); i++, sslStreamFeatures->rawBytesIndex++){
					// 	sslStreamFeatures->rawBytes[sslStreamFeatures->rawBytesIndex] = *(msg_Data + i);
					// }						
				}
				// std::cout << "证书收集齐了" << std::endl;
			}

			// 分段都到齐了
			if(int(sslStreamFeatures->cookie.dataLen) + int(tcpData.getDataLength()) > int(sslStreamFeatures->cookie.recordLayerLen)){
				// std::cout << "分段都到齐了" << std::endl;
				dataPtr = const_cast<uint8_t*>(tcpData.getData()) + sslStreamFeatures->cookie.recordLayerLen - sslStreamFeatures->cookie.dataLen;
				dataLen = tcpData.getDataLength() + sslStreamFeatures->cookie.dataLen - sslStreamFeatures->cookie.recordLayerLen;
				
				sslStreamFeatures->cookie.recordLayerLen = 0;
				sslStreamFeatures->cookie.dataLen = 0;		
				if(dataLen > int(sizeof(ssl_tls_record_layer)))		
					continue;
				else{
					sslStreamFeatures->cookie.lastRemainSegSize = dataLen;
					uint8_t* p1 = sslStreamFeatures->cookie.lastRemainSeg;
					uint8_t* p2 = dataPtr;
					for(int i = 0; i < dataLen; i++)
						*p1++ = *p2++;
					*p1 = '\0';
					break;
				}
			}
			else if(int(sslStreamFeatures->cookie.dataLen) + int(tcpData.getDataLength()) == int(sslStreamFeatures->cookie.recordLayerLen)){
				sslStreamFeatures->cookie.recordLayerLen = 0;
				sslStreamFeatures->cookie.dataLen = 0;
				break;
			}
			else{
				sslStreamFeatures->cookie.dataLen += tcpData.getDataLength();
				break;
			}
		}
	}
} 


/**
 * The callback being called by the TCP reassembly module whenever a new connection is found. This method adds the connection to the connection manager
 */
static void tcpReassemblyConnectionStartCallback(const ConnectionData& connectionData, void* userCookie)
{
	// get a pointer to the connection manager
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

	// look for the connection in the connection manager
	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

	// assuming it's a new connection
	if (iter == connMgr->end())
	{
		SSLStreamFeatures sslStreamFeatures = SSLStreamFeatures();
		connMgr->insert(std::make_pair(connectionData.flowKey, sslStreamFeatures));
	}
}


/**
 * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the connection from the connection manager and writes the metadata file if requested
 * by the user
 */
static void tcpReassemblyConnectionEndCallback(const ConnectionData& connectionData, TcpReassembly::ConnectionEndReason reason, void* userCookie)
{
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*) userCookie;
	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);
	SSLStreamFeatures* sslStreamFeatures = &(iter->second);

	sslStreamFeatures->duringTime = 1000000*(connectionData.endTime.tv_sec - connectionData.startTime.tv_sec) + (connectionData.endTime.tv_usec - connectionData.startTime.tv_usec);
	sslStreamFeatures->useCommonPort = SSLLayer::isSSLPort(connectionData.dstPort);
	
	std::ostream*  output = GlobalConfig::getInstance().fileStream;
	std::string fileName = GlobalConfig::getInstance().pcap_file;
	if (sslStreamFeatures->cookie.handshakeSuccess == true)
	{
		*output << fileName << "," << connectionData.flowKey;
		*output << "," << connectionData.srcIP.toString() << "," << connectionData.srcPort << "," << connectionData.dstIP.toString() << "," <<connectionData.dstPort;

		// *output << "," << GlobalConfig::getInstance().label;

		*output << "," << sslStreamFeatures->hostName; 
		*output << "," << sslStreamFeatures->certificateNum;
		*output << "," << sslStreamFeatures->duringTime;
		*output << "," << sslStreamFeatures->useCommonPort;
		*output << "," << sslStreamFeatures->isResumption;			
		*output << "," << sslStreamFeatures->isHostNameDomain;
		*output << "," << sslStreamFeatures->isHostNameIP;
		*output << "," << sslStreamFeatures->isHostNameDstIP;
		*output << "," << sslStreamFeatures->JA3.c_str();
		*output << "," << sslStreamFeatures->JA3S.c_str();

		for(int i = 0; i < TOTAL_CIPHER_SUITES; i++){
			*output << "," << sslStreamFeatures->cipherSuitesOneHot[i];
		}

		// *output << "Record layer sequence " << std::endl;
		for(int i = 0; i < TOTAL_EXTENSIONS; i++){
			*output << "," << sslStreamFeatures->extensionsOneHot[i];
		}

		for(int i = 0; i < MAX_SSL_VERSION; i++){
			*output << "," << sslStreamFeatures->SSLVersionOneHot[i];
		}

		*output << "," << sslStreamFeatures->numOfDataPackets[0]; 
		*output << "," << sslStreamFeatures->numOfDataPackets[1]; 
		*output << "," << sslStreamFeatures->bytesFromSide[0]; 
		*output << "," << sslStreamFeatures->bytesFromSide[1]; 
		*output << "," << sslStreamFeatures->numOfPacketsAfterHandshake[0]; 
		*output << "," << sslStreamFeatures->numOfPacketsAfterHandshake[1]; 
		*output << "," << sslStreamFeatures->bytesFromSideAfterHandshake[0]; 
		*output << "," << sslStreamFeatures->bytesFromSideAfterHandshake[1];

		// for(int i = 0; i < MAX_RECORD_LAYER_SIZE_SEQ_INDEX; i++){
		// 	*output << "," << sslStreamFeatures->recordLayerSizeSequence[i]; 
		// }
		for(int i = 0; i < MAX_PACKET_SIZE_SEQ_INDEX; i++){
			*output << "," << sslStreamFeatures->packetSizeSequence[i]; 
		}
		// for(int i = 0; i < MAX_FLOW_BYTES; i++){
		// 	*output << "," << sslStreamFeatures->rawBytes[i]; 
		// }
		
		*output << std::endl;
	}
	
	sslStreamFeatures->clear();
	connMgr->erase(iter);
}

/**
 * The method responsible for TCP reassembly on pcap/pcapng files
 */
void doTcpReassemblyOnPcapFile(std::string fileName, TcpReassembly& tcpReassembly)
{
	GlobalConfig::getInstance().pcap_file = fileName;
	// GlobalConfig::getInstance().getLabel(fileName);
	// open input file (pcap or pcapng file)
	IFileReaderDevice* reader = IFileReaderDevice::getReader(fileName.c_str());

	// try to open the file device
	if (!reader->open())
		EXIT_WITH_ERROR("Cannot open pcap/pcapng file");


	printf("Starting reading '%s'...\n", fileName.c_str());

	// run in a loop that reads one packet from the file in each iteration and feeds it to the TCP reassembly instance
	RawPacket rawPacket;
	int order = 0;
	while (reader->getNextPacket(rawPacket))
	{
		order++;
		// if((order > 171734)&&(order <= 172000))
		// 	std::cout << "NO." << order << std::endl;
		pcpp::Packet parsedPacket(&rawPacket);
		tcpReassembly.reassemblePacket(parsedPacket);
	}

	// extract number of connections before closing all of them
	size_t numOfConnectionsProcessed = tcpReassembly.getConnectionInformation().size();

	// after all packets have been read - close the connections which are still opened
	tcpReassembly.closeAllConnections();

	// close the reader and free its memory
	reader->close();
	delete reader;
	printf("Done! processed %d connections\n", (int)numOfConnectionsProcessed);
}


/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	std::string inputDir;
	std::string outputFile;
	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "r:o:d:h", GetFeatureOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'r':
				inputDir = optarg;
				break;
			case 'o':
				outputFile = optarg;
				break;
			case 'd':
				dropRate = std::stof(optarg);
				break;
			case 'h':
				printUsage();
				break;
			default:
				printUsage();
				exit(-1);
		}
	}
	// set global config singleton with input configuration
	GlobalConfig::getInstance().outputFile = outputFile;
	GlobalConfig::getInstance().openFileStream();

	std::ostream* output = GlobalConfig::getInstance().fileStream;

	*output << "fileName" << "," << "flowKey";
	*output << "," << "srcIP" << "," << "srcPort" << "," << "dstIP" << "," << "dstPort";
	// *output << "," << "label";
	*output << "," << "hostName";	
	
	*output << "," << "certificateNum";
	*output << "," << "duringTime";
	*output << "," << "useCommonPort";
	*output << "," << "isResumption";
	*output << "," << "isHostNameDomain";
	*output << "," << "isHostNameIP";
	*output << "," << "isHostNameDstIP"; 
	*output << "," << "JA3"; 
	*output << "," << "JA3S"; 

	for(int i = 0; i < TOTAL_CIPHER_SUITES; i++){
		*output << "," << "cipherSuites_" << i;
	}
	for(int i = 0; i < TOTAL_EXTENSIONS; i++){
		*output << "," << "extensions_" << i;
	}
	for(int i = 0; i < MAX_SSL_VERSION; i++){
		*output << "," << "SSLVersion_" << i;
	}

	*output << "," << "FromPackets";
	*output << "," << "ToPackets";
	*output << "," << "FromBytes";
	*output << "," << "ToBytes";
	*output << "," << "FromPacketsAfter";
	*output << "," << "ToPacketsAfter";
	*output << "," << "FromBytesAfter";
	*output << "," << "ToBytesAfter";
	
	
	for(int i = 0; i < MAX_PACKET_SIZE_SEQ_INDEX; i++){
		*output << "," << "packetSize_" << i;
	}

	// for(int i = 0; i < MAX_FLOW_BYTES; i++){
	// 	*output << "," << "rawBytes_" << i;
	// }
	*output << std::endl;

	int count = 0;
	std::list<std::string> pcapList = walkDir(inputDir);
	for(std::list<std::string>::iterator iter = pcapList.begin(); iter != pcapList.end() ;iter++){
		count++;
		std::cout << count << " ";
		std::string inputPcapFileName = *iter;
		std::cout << inputPcapFileName << std::endl;
		globalConnMgr->clear();
		// create the TCP reassembly instance
		TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, globalConnMgr, tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback);
		// // analyze in pcap file mode
		doTcpReassemblyOnPcapFile(inputPcapFileName, tcpReassembly);
	}
	
	GlobalConfig::getInstance().closeFileSteam();
}

#include <windows.h>
#include "des.h"

void XOR(const BYTE in1[8], const BYTE in2[8], BYTE out[8]); 
LPBYTE Bin2ASCII(const BYTE byte[64], BYTE bit[8]); 
LPBYTE ASCII2Bin(const BYTE bit[8], BYTE byte[64]); 
void GenSubKey(const BYTE oldkey[8], BYTE newkey[16][8]); 
void endes(const BYTE m_bit[8], const BYTE k_bit[8], BYTE e_bit[8]); 
void undes(const BYTE m_bit[8], const BYTE k_bit[8], BYTE e_bit[8]); 
void SReplace(BYTE s_bit[8]); 


/* 
*   CDesEnter 函数说明： 
*     des加密/解密入口 
*   返回： 
*     1则成功,0失败 
*   参数： 
*     in 需要加密或解密的数据  
*         注意：in缓冲区的大小必须和datalen相同. 
*     out 加密后或解密后输出。 
*         注意：out缓冲区大小必须是8的倍数而且比datalen大或者相等。 
*         如datalen=7，out缓冲区的大小应该是8，datalen=8,out缓冲区的大小应该是8, 
*         datalen=9,out缓冲区的大小应该是16，依此类推。 
*     datalen 数据长度(字节)。  
*         注意:datalen 必须是8的倍数。 
*     key 8个字节的加密或解密的密码。 
*     type 是对数据进行加密还是解密 
*         0 表示加密 1 表示解密 
by: sincoder 函数成功 返回 输出缓冲区中的字节数
*/ 
int DesEnter(LPCBYTE in, LPBYTE out, int datalen, const BYTE key[8], BOOL type) 
{ 
    int output_len  = 0;
    //判断输入参数是否正确，失败的情况为： 
    //!in： in指针（输入缓冲）无效 
    //!out： out指针（输出缓冲）无效 
    //datalen<1： 数据长度不正确 
    //!key： 加/解密密码无效 
    //type && ((datalen % 8) !=0：选择解密方式但是输入密文不为8的倍数 
    if((!in) || (!out) || (datalen<1) || (!key) || (type && ((datalen % 8) !=0))) 
        return 0; 

    if(type==0) //选择的模式是加密 
    { 
        // 用于存储待加密字串最后的若干字节 
        // DES算法是以8个字节为单位进行加密，如果待加密字串以8为单位分段加密时，最后一段不足 
        //8字节，则在后面补0，使其最后一段的长度为8字节 
        // te8bit是作为存储待加密字串最后一段（不足8字节）的变量 
        BYTE te8bit[8]={0,0,0,0,0,0,0,0}; 

        // 这是待加密字串的调整长度 
        // 如果原始长度是8的整数倍，则调整长度的值和原来的长度一样 
        // 如果原始长度不是8的整数倍，则调整长度的值是能被8整除且不大于原来长度的最大整数。 
        //也就是不需要补齐的块的总长度。 
        int te_fixlen = datalen - (datalen % 8); 

        int i;
        // 将待加密密文以8为单位分段，把最后长度不足8的一段存储到te8bit中。 
        for( i = 0; i < (datalen % 8); i++) 
            te8bit[i] = in[te_fixlen + i]; 

        // 将待加密字串分以8字节为单位分段加密 
        for(i = 0; i < te_fixlen; i += 8) 
            endes(in + i, key, out + i); 

        // 如果待加密字串不是8的整数倍，则将最后一段补齐（补0）后加密 
        if(datalen % 8 != 0) 
            endes(te8bit, key, out + datalen / 8 * 8); 
    } 
    else   //选择的模式是解密 
    { 
        int i;
        // 将密文以8字节为单位分段解密 
        for(i = 0; i < datalen; i += 8) 
            undes(in + i, key, out + i); 
    } 
    output_len =  datalen / 8 * 8;
    return output_len; 
} 

/* 
*   CDesMAC 函数说明： 
*     DESMAC 数据验校 
*   返回： 
*     1则成功,0失败 
*   参数： 
*     mac_data MAC验校数据 
*         注意：Mac_data缓冲区的大小(16字节以上)必须和datalen相同,而且应是8的倍数。 
*     out_mac MAC验校输出(8字节) 
*     dadalen 数据长度(字节)。  
*         注意:datalen 必须是16以上而且是8的倍数。 
*     key 8个字节的验校密码。      
*/ 
BOOL DesMac(LPCBYTE mac_data, LPBYTE mac_code, int datalen, const BYTE key[8]) 
{ 
    //判断输入参数是否正确，失败的情况为： 
    //!mac_data： mac_data指针（输入缓冲）无效 
    //!mac_code： mac_code指针（输出缓冲）无效 
    //datalen<16： 数据长度不正确 
    //datalen % 8 != 0： 数据长度不为8的整数倍 
    //!key：密码不符合要求 
    int i;
    if((!mac_data) || (!mac_code) || (datalen < 16) || (datalen % 8 != 0) || (!key)) 
        return FALSE; 
    endes(mac_data, key, mac_code); 
    for( i = 8; i < datalen; i += 8) 
    { 
        XOR(mac_code, mac_data + i, mac_code); 
        endes(mac_code, key, mac_code); 
    } 
    return TRUE; 
} 

/* 
*   XOR 函数说明： 
*     将输入的两个8字节字符串异或 
*   返回： 
*     无 
*   参数： 
*     const BYTE in1[8] 输入字符串1 
*     const BYTE in2[8] 输入字符串2 
*     BYTE out[8] 输出的结果字符串      
*/ 
void XOR(const BYTE in1[8], const BYTE in2[8], BYTE out[8]) 
{ 
    int i;
    for( i = 0; i < 8; i++) 
        out[i] = in1[i] ^ in2[i];  
} 

/* 
*   Bin2ASCII 函数说明： 
*     将64字节的01字符串转换成对应的8个字节 
*   返回： 
*     转换后结果的指针 
*   参数： 
*     const BYTE byte[64] 输入字符串 
*     BYTE bit[8] 输出的转换结果      
*/ 
LPBYTE Bin2ASCII(const BYTE byte[64], BYTE bit[8]) 
{ 
    int i;
    for( i = 0; i < 8; i++) 
    { 
        bit[i] = byte[i * 8] * 128 + byte[i * 8 + 1] * 64 +  
            byte[i * 8 + 2] * 32 + byte[i * 8 + 3] * 16 +  
            byte[i * 8 + 4] * 8 + byte[i * 8 + 5] * 4 +  
            byte[i * 8 + 6] * 2 + byte[i * 8 + 7];  
    } 
    return bit; 
} 

/* 
*   ASCII2Bin 函数说明： 
*     将8个字节输入转换成对应的64字节的01字符串 
*   返回： 
*     转换后结果的指针 
*   参数： 
*     const BYTE bit[8] 输入字符串 
*     BYTE byte[64] 输出的转换结果      
*/ 
LPBYTE ASCII2Bin(const BYTE bit[8], BYTE byte[64]) 
{ 
    int i,j;
    for( i=0; i < 8; i++) 
        for(j = 0; j < 8; j++) 
            byte[i * 8 + j] = ( bit[i] >> (7 - j) ) & 0x01; 
    return byte; 
} 

/* 
*   GenSubKey 函数说明： 
*     由输入的密钥得到16个子密钥 
*   返回： 
*     无 
*   参数： 
*     const BYTE oldkey[8] 输入密钥 
*     BYTE newkey[16][8] 输出的子密钥      
*/ 
void GenSubKey(const BYTE oldkey[8], BYTE newkey[16][8]) 
{ 
    int i, k, rol = 0; 

    //缩小换位表1 
    int pc_1[56] = {57,49,41,33,25,17,9, 
        1,58,50,42,34,26,18, 
        10,2,59,51,43,35,27, 
        19,11,3,60,52,44,36, 
        63,55,47,39,31,23,15, 
        7,62,54,46,38,30,22, 
        14,6,61,53,45,37,29, 
        21,13,5,28,20,12,4}; 
    //缩小换位表2 
    int pc_2[48] = {14,17,11,24,1,5, 
        3,28,15,6,21,10, 
        23,19,12,4,26,8, 
        16,7,27,20,13,2, 
        41,52,31,37,47,55, 
        30,40,51,45,33,48, 
        44,49,39,56,34,53, 
        46,42,50,36,29,32}; 
    //16次循环左移对应的左移位数 
    int ccmovebit[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1}; 

    BYTE oldkey_byte[64]; 
    BYTE oldkey_byte1[64]; 
    BYTE oldkey_byte2[64]; 
    BYTE oldkey_c[56]; 
    BYTE oldkey_d[56]; 
    BYTE newkey_byte[16][64]; 

    ASCII2Bin(oldkey, oldkey_byte); 

    //位变换 
    for(i = 0; i < 56; i++) 
        oldkey_byte1[i] = oldkey_byte[pc_1[i] - 1]; 
    //分为左右两部分，复制一遍以便于循环左移 
    for(i = 0; i < 28; i++) 
        oldkey_c[i] = oldkey_byte1[i], oldkey_c[i + 28] = oldkey_byte1[i], 
        oldkey_d[i] = oldkey_byte1[i + 28], oldkey_d[i + 28] = oldkey_byte1[i + 28]; 

    //分别生成16个子密钥 
    for(i = 0; i < 16; i++) 
    { 
        //循环左移 
        rol += ccmovebit[i]; 
        //合并左移后的结果 
        for(k = 0; k < 28; k++)  
            oldkey_byte2[k] = oldkey_c[k + rol], oldkey_byte2[k + 28] = oldkey_d[k + rol]; 
        //位变换 
        for(k = 0; k < 48; k++) 
            newkey_byte[i][k] = oldkey_byte2[pc_2[k] - 1]; 

    } 
    //生成最终结果 
    for(i = 0; i < 16; i++) 
        Bin2ASCII(newkey_byte[i], newkey[i]); 
} 

/* 
*   endes 函数说明： 
*     DES加密 
*   返回： 
*     无 
*   参数： 
*     const BYTE m_bit[8] 输入的原文 
*     const BYTE k_bit[8] 输入的密钥 
*     BYTE e_bit[8] 输出的密文 
*/ 
void endes(const BYTE m_bit[8], const BYTE k_bit[8], BYTE e_bit[8]) 
{ 
    //换位表IP 
    int ip[64] = { 
        58,50,42,34,26,18,10,2, 
        60,52,44,36,28,20,12,4, 
        62,54,46,38,30,22,14,6, 
        64,56,48,40,32,24,16,8, 
        57,49,41,33,25,17,9,1, 
        59,51,43,35,27,19,11,3, 
        61,53,45,37,29,21,13,5, 
        63,55,47,39,31,23,15,7 
    }; 
    //换位表IP_1 
    int ip_1[64] = { 
        40,8,48,16,56,24,64,32, 
        39,7,47,15,55,23,63,31, 
        38,6,46,14,54,22,62,30, 
        37,5,45,13,53,21,61,29, 
        36,4,44,12,52,20,60,28, 
        35,3,43,11,51,19,59,27, 
        34,2,42,10,50,18,58,26, 
        33,1,41,9,49,17,57,25 
    }; 
    //放大换位表 
    int e[48] = { 
        32,1, 2, 3, 4, 5, 
        4, 5, 6, 7, 8, 9, 
        8, 9, 10,11,12,13, 
        12,13,14,15,16,17, 
        16,17,18,19,20,21, 
        20,21,22,23,24,25, 
        24,25,26,27,28,29, 
        28,29,30,31,32,1 
    }; 
    BYTE m_bit1[8] = {0}; 
    BYTE m_byte[64] = {0}; 
    BYTE m_byte1[64] = {0}; 
    BYTE key_n[16][8] = {0}; 
    BYTE l_bit[17][8] = {0}; 
    BYTE r_bit[17][8] = {0}; 
    BYTE e_byte[64] = {0}; 
    BYTE e_byte1[64] = {0}; 
    BYTE r_byte[64] = {0}; 
    BYTE r_byte1[64] = {0}; 
    int i, j; 

    //根据密钥生成16个子密钥 
    GenSubKey(k_bit, key_n); 
    //将待加密字串变换成01串 
    ASCII2Bin(m_bit, m_byte); 
    //按照ip表对待加密字串进行位变换 
    for(i = 0; i < 64; i++) 
        m_byte1[i] = m_byte[ip[i] - 1]; 
    //位变换后的待加密字串 
    Bin2ASCII(m_byte1, m_bit1); 
    //将位变换后的待加密字串分成两组，分别为前4字节L和后4字节R，作为迭代的基础（第0次迭代） 
    for(i = 0; i < 4; i++) 
        l_bit[0][i] = m_bit1[i], r_bit[0][i] = m_bit1[i + 4]; 

    //16次迭代运算 
    for(i = 1; i <= 16; i++) 
    { 
        //R的上一次的迭代结果作为L的当前次迭代结果 
        for(j = 0; j < 4; j++) 
            l_bit[i][j] = r_bit[i-1][j]; 

        ASCII2Bin(r_bit[i-1], r_byte); 
        //将R的上一次迭代结果按E表进行位扩展得到48位中间结果 
        for(j = 0; j < 48; j++) 
            r_byte1[j] = r_byte[e[j] - 1]; 
        Bin2ASCII(r_byte1, r_bit[i-1]); 

        //与第I-1个子密钥进行异或运算 
        for(j = 0; j < 6; j++) 
            r_bit[i-1][j] = r_bit[i-1][j] ^ key_n[i-1][j]; 

        //进行S选择，得到32位中间结果 
        SReplace(r_bit[i - 1]); 

        //结果与L的上次迭代结果异或得到R的此次迭代结果 
        for(j = 0; j < 4; j++) 
        { 
            r_bit[i][j] = l_bit[i-1][j] ^ r_bit[i-1][j]; 
        } 
    } 
    //组合最终迭代结果 
    for(i = 0; i < 4; i++) 
        e_bit[i] = r_bit[16][i], e_bit[i + 4] = l_bit[16][i]; 

    ASCII2Bin(e_bit, e_byte); 
    //按照表IP-1进行位变换 
    for(i = 0; i < 64; i++) 
        e_byte1[i] = e_byte[ip_1[i] - 1]; 
    //得到最后的加密结果 
    Bin2ASCII(e_byte1, e_bit); 
} 

/* 
*   undes 函数说明： 
*     DES解密，与加密步骤完全相同，只是迭代顺序是从16到1 
*   返回： 
*     无 
*   参数： 
*     const BYTE m_bit[8] 输入的密文 
*     const BYTE k_bit[8] 输入的密钥 
*     BYTE e_bit[8] 输出解密后的原文 
*/ 
void undes(const BYTE m_bit[8], const BYTE k_bit[8], BYTE e_bit[8]) 
{ 
    //换位表IP 
    int ip[64] = { 
        58,50,42,34,26,18,10,2, 
        60,52,44,36,28,20,12,4, 
        62,54,46,38,30,22,14,6, 
        64,56,48,40,32,24,16,8, 
        57,49,41,33,25,17,9,1, 
        59,51,43,35,27,19,11,3, 
        61,53,45,37,29,21,13,5, 
        63,55,47,39,31,23,15,7 
    }; 
    //换位表IP_1 
    int ip_1[64] = { 
        40,8,48,16,56,24,64,32, 
        39,7,47,15,55,23,63,31, 
        38,6,46,14,54,22,62,30, 
        37,5,45,13,53,21,61,29, 
        36,4,44,12,52,20,60,28, 
        35,3,43,11,51,19,59,27, 
        34,2,42,10,50,18,58,26, 
        33,1,41,9,49,17,57,25 
    }; 
    //放大换位表 
    int e[48] = { 
        32,1, 2, 3, 4, 5, 
        4, 5, 6, 7, 8, 9, 
        8, 9, 10,11,12,13, 
        12,13,14,15,16,17, 
        16,17,18,19,20,21, 
        20,21,22,23,24,25, 
        24,25,26,27,28,29, 
        28,29,30,31,32,1 
    }; 
    BYTE m_bit1[8] = {0}; 
    BYTE m_byte[64] = {0}; 
    BYTE m_byte1[64] = {0}; 
    BYTE key_n[16][8] = {0}; 
    BYTE l_bit[17][8] = {0}; 
    BYTE r_bit[17][8] = {0}; 
    BYTE e_byte[64] = {0}; 
    BYTE e_byte1[64] = {0}; 
    BYTE l_byte[64] = {0}; 
    BYTE l_byte1[64] = {0}; 
    int i = 0, j = 0; 

    //根据密钥生成16个子密钥 
    GenSubKey(k_bit, key_n); 
    //将待加密字串变换成01串 
    ASCII2Bin(m_bit, m_byte); 
    //按照ip表对待加密字串进行位变换 
    for(i = 0; i < 64; i++) 
        m_byte1[i] = m_byte[ip[i] - 1]; 
    //位变换后的待加密字串 
    Bin2ASCII(m_byte1, m_bit1); 
    //将位变换后的待加密字串分成两组，分别为前4字节R和后4字节L，作为迭代的基础（第16次迭代） 
    for(i = 0; i < 4; i++) 
        r_bit[16][i] = m_bit1[i], l_bit[16][i] = m_bit1[i + 4]; 

    //16次迭代运算 
    for(i = 16; i > 0; i--) 
    { 
        //L的上一次的迭代结果作为R的当前次迭代结果 
        for(j = 0; j < 4; j++) 
            r_bit[i-1][j] = l_bit[i][j]; 

        ASCII2Bin(l_bit[i], l_byte); 
        //将L的上一次迭代结果按E表进行位扩展得到48位中间结果 
        for(j = 0; j < 48; j++) 
            l_byte1[j] = l_byte[e[j] - 1]; 
        Bin2ASCII(l_byte1, l_bit[i]); 

        //与第I-1个子密钥进行异或运算 
        for(j = 0; j < 6; j++) 
            l_bit[i][j] = l_bit[i][j] ^ key_n[i-1][j]; 

        //进行S选择，得到32位中间结果 
        SReplace(l_bit[i]); 

        //结果与R的上次迭代结果异或得到L的此次迭代结果 
        for(j = 0; j < 4; j++) 
        { 
            l_bit[i-1][j] = r_bit[i][j] ^ l_bit[i][j]; 
        } 
    } 
    //组合最终迭代结果 
    for(i = 0; i < 4; i++) 
        e_bit[i] = l_bit[0][i], e_bit[i + 4] = r_bit[0][i]; 

    ASCII2Bin(e_bit, e_byte); 
    //按照表IP-1进行位变换 
    for(i = 0; i < 64; i++) 
        e_byte1[i] = e_byte[ip_1[i] - 1]; 
    //得到最后的结果 
    Bin2ASCII(e_byte1, e_bit); 
} 

/* 
*   SReplace 函数说明： 
*     S选择 
*   返回： 
*     无 
*   参数： 
*     BYTE s_bit[8] 输入暨选择后的输出 
*/ 
void SReplace(BYTE s_bit[8]) 
{ 
    int p[32] = { 
        16,7,20,21, 
        29,12,28,17, 
        1,15,23,26, 
        5,18,31,10, 
        2,8,24,14, 
        32,27,3,9, 
        19,13,30,6, 
        22,11,4,25 
    }; 
    BYTE s[][4][16] ={  
        { 
            14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 
                0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 
                4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 
                15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 
        }, 
        { 
            15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 
                3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 
                0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 
                13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 
            }, 
            { 
                10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 
                    13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 
                    13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 
                    1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 
            }, 
            { 
                7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 
                    13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 
                    10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 
                    3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 
                }, 
                { 
                    2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 
                        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 
                        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 
                        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3, 
                }, 
                { 
                    12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 
                        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 
                        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 
                        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 
                    }, 
                    { 
                        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 
                            13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 
                            1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 
                            6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 
                    }, 
                    { 
                        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 
                            1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 
                            7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 
                            2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 
                        } 
    }; 
    BYTE s_byte[64] = {0}; 
    BYTE s_byte1[64] = {0}; 
    BYTE row = 0, col = 0; 
    BYTE s_out_bit[8] = {0}; 

    int i;
    //转成二进制字符串处理 
    ASCII2Bin(s_bit, s_byte); 
    for( i = 0; i < 8; i++) 
    { 
        //0、5位为row，1、2、3、4位为col，在S表中选择一个八位的数 
        row = s_byte[i * 6] * 2 + s_byte[i * 6 + 5]; 
        col = s_byte[i * 6 + 1] * 8 + s_byte[i * 6 + 2] * 4 + s_byte[i * 6 + 3] * 2 + s_byte[i * 6 + 4]; 
        s_out_bit[i] = s[i][row][col]; 
    } 
    //将八个选择的八位数据压缩表示 
    s_out_bit[0] = (s_out_bit[0] << 4) + s_out_bit[1]; 
    s_out_bit[1] = (s_out_bit[2] << 4) + s_out_bit[3]; 
    s_out_bit[2] = (s_out_bit[4] << 4) + s_out_bit[5]; 
    s_out_bit[3] = (s_out_bit[6] << 4) + s_out_bit[7]; 
    //转成二进制字符串处理 
    ASCII2Bin(s_out_bit, s_byte); 
    //换位 
    for(i = 0; i < 32; i++) 
        s_byte1[i] = s_byte[p[i] - 1]; 
    //生成最后结果 
    Bin2ASCII(s_byte1, s_bit); 
} 

#include <stdio.h>
#include "CBase64Code.h"
#include "esb_des.h"
#include <string.h>
#include <string>
using namespace std;



int main()
{
    // 24位数字
    std::string strKeys = "15259596173285910721062";
    std::string strEncryptPasswordTemp = "lP+3e5l8LCZBnL9RZLlZQziLW1lThSaX+hFZTRZn7tPEnmCD0kLAzefHkXIbPJmfHSGpMgCyesCTV0WUyHEE8Q==";
    char DstOut[1024] = { 0 };
    memset(DstOut, 0x0, sizeof(DstOut));
    size_t encryptSize = Base64_Decode(DstOut, strEncryptPasswordTemp.c_str(), strEncryptPasswordTemp.length());
    printf("encrypt clear text: %s\n", strEncryptPasswordTemp.c_str());

    char ByteDst[1024] = { 0 };
    long tlen = 0;
    decrypt3des(ByteDst, &tlen, DstOut, encryptSize, strKeys.c_str());
    printf("decrypt 3des: %s\n", ByteDst);
    return 0;
}



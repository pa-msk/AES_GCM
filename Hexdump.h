#pragma once

#include <iostream>

void HexDump(const unsigned char* buf, size_t buf_len)
{
    for(size_t pos = 0; pos < buf_len; pos += 16)
    {
        printf("%.4zu: ", pos);
        
        for(size_t cur = pos; cur < pos + 16; ++cur)
        {
            if(cur < buf_len)
                printf("%02x ", buf[cur]);
            else
                printf("   ");
        }
        
        printf(" ");
        
        for(size_t cur = pos; cur < pos + 16; ++cur)
        {
            if(cur < buf_len)
            {
                if(isascii(buf[cur]) && isprint(buf[cur]))
                    printf("%c", buf[cur]);
                else
                    printf(".");
            }
        }
        
        printf("\n");
    }
}

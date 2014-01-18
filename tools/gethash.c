//-------------------------------------------------------------------------
// Calculate the hash of the API name.
//
// C:\CSC\tools> gethash.exe WinExec
// #define HASH_WinExec                        0x25e6b913
//
// tombkeeper@gmail.com
// 2008.05
//-------------------------------------------------------------------------


#include <windows.h>

DWORD HashKey(char *key)
{
    DWORD nHash = 0;
    while (*key)
    {
        nHash = (nHash<<5) + nHash + *key++;
    }
    return nHash;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf ( "Usage: %s <API Name>\n", argv[0] );
    }else
    {
        printf ( "#define HASH_%-30s %0#.8x\n", argv[1], HashKey(argv[1]) );
    }
    return 0;
}

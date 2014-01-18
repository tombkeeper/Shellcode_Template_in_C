//-------------------------------------------------------------------------
// Converting string to an integer array.
//
// C:\CSC\tools> str2intarr.exe AAAABBBB
// DWORD sz_String[] = { 0x41414141, 0x42424242, 0x00000000 };
//
// tombkeeper@gmail.com
// 2008.05
//-------------------------------------------------------------------------


#include<Windows.h>

int main( int argc, char * argv[] )
{

    if ( argc != 2 )
    {
        printf("Usage: %s <String>", argv[0] );
        exit(0);
    }else
    {
        DWORD Num, i, Len, *IntBlock;

        Len = strlen(argv[1]);
        Num = Len/sizeof(DWORD)+1; 
        IntBlock = calloc( Num, sizeof(DWORD) );

        if ( IntBlock==NULL )
        {
            printf( "Can't allocate memory\n" );
            exit(0);
        }
        else 
        {
            strncpy( (char *)IntBlock, argv[1], Num*sizeof(DWORD) );
            
            if (Num > 4)
            {
                printf( "DWORD sz_String[] =\n{" );
                for( i=0; i<Num; i++)
                {
                    if ( !(i%6) )
                    {
                        printf("\n    ");
                    }
                    printf( "0x%.8x", IntBlock[i] );
                    if ( i != Num-1 )
                    {
                        printf(", ");
                    }
    
                }
                printf( "\n};" );
            }
            else
            {
                printf( "DWORD sz_String[] = { " );
                for( i=0; i<Num; i++)
                {
                    printf( "0x%.8x", IntBlock[i] );
                    if ( i != Num-1 )   printf(", ");
                }
                printf( " };\n" );
            }

            free(IntBlock);
        }
    }
}

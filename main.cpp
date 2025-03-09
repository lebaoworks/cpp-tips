#include <nstd/nstd.hpp>
#include <iostream>

int main(int argc, char** argv)
{
    int i=0;
    
    defer { printf("Defer: i = %d\n", i); };
    
    printf("i = %d\n", i);
    i += 1;

    return 0;
}
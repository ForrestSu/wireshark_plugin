#include <cstdio>
#include <string>
#include "libparse_pb.h"

int main()
{
    int a = 10;
    int b = 100;
    auto c = Add(a, b);

    std::string str = "hello world!";
    GoString go_str{str.c_str(), (long)str.length()};

    Logs(go_str);

    printf("c == %lld!\n", c);
    return 0;
}
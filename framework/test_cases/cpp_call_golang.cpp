#include <cstdio>
#include <cstdlib>
#include <string>
#include "libparser.h"

int main()
{
    std::string name = "pb";
    std::string msg = "hello world!";
    // params
    GoString goName{name.c_str(), (long)name.length()};
    GoString goMsg{msg.c_str(), (long)msg.length()};
    // call
    struct Parser_return ret = Parser(goName, goMsg);
    if (ret.r0 != nullptr)
    {
        std::string decoded = std::string(ret.r0, ret.r1);
        printf("return decode msg == [%s]\n", decoded.c_str());
    }
    return 0;
}
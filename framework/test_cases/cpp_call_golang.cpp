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
    const char *cgo_ptr = Parser(goName, goMsg);
    std::string decoded;
    if (cgo_ptr != nullptr)
    {
        decoded = std::string(cgo_ptr);
        free((void*)cgo_ptr); // 释放 golang 返回的C字符串
    }
    printf("return decode msg == [%s]\n", decoded.c_str());
    return 0;
}
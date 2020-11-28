// go_caller.c is a golang caller, write by c.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

// lua5.2 new api: luaL_newlib()
#if LUA_VERSION_NUM < 502
#ifndef luaL_newlib /* not LuaJIT 2.1 */
#define luaL_newlib(L, l) (lua_newtable(L), luaL_register(L, NULL, l))
#endif
#endif

// parser.h
#include "parser.h"


static int go_caller_parser(lua_State *L)
{
    double op1 = luaL_checknumber(L, 1);
    double op2 = luaL_checknumber(L, 2);

    // 从 lua 获取字符串, 然后传递给
    const char* name = "pb";
    const char* msg = "hello world!";

    const char* decoded = call_cgo_parser(name, strlen(name), msg, strlen(msg));
    if (decoded != NULL) {
        printf("line = %d, decoded = %s\n", __LINE__, decoded);
        free((void*)decoded);
    }
    lua_pushnumber(L, op1 - op2);
    return 1;
}

// open wgo library
LUALIB_API int luaopen_go_caller(lua_State *L)
{
    luaL_Reg export_libs[] = {
        {"parser", go_caller_parser},
        {NULL, NULL},
    };
    luaL_newlib(L, export_libs);
    return 1;
}
// wgo.c

#include <stdio.h>
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

// #define EXPORT_API extern

//EXPORT_API int wgo_add(lua_State *L);
//EXPORT_API int wgo_sub(lua_State *L);

LUALIB_API int wgo_add(lua_State *L)
{
    double op1 = luaL_checknumber(L, 1);
    double op2 = luaL_checknumber(L, 2);
    lua_pushnumber(L, op1 + op2);
    return 1;
}

LUALIB_API int wgo_sub(lua_State *L)
{
    double op1 = luaL_checknumber(L, 1);
    double op2 = luaL_checknumber(L, 2);
    lua_pushnumber(L, op1 - op2);
    return 1;
}

// open wgo library
LUALIB_API int luaopen_wgo(lua_State *L)
{
    luaL_Reg export_libs[] = {
        {"add", wgo_add},
        {"sub", wgo_sub},
        {NULL, NULL},
    };
    luaL_newlib(L, export_libs);
    return 1;
}
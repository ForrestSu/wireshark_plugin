// go_caller.c is a golang caller, write by c.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

// parser.h
#include "go_caller.h"
#include "parser.h"

// lua5.2 new api: luaL_newlib()
#if LUA_VERSION_NUM < 502
#ifndef luaL_newlib /* not LuaJIT 2.1 */
#define luaL_newlib(L, l) (lua_newtable(L), luaL_register(L, NULL, l))
#endif
#endif

/* Lua util routines */

#define PB_STATE     "pb.State"
#define PB_BUFFER    "pb.Buffer"
#define PB_SLICE     "pb.Slice"

#define check_buffer(L,idx) ((pb_Buffer*)luaL_checkudata(L,idx,PB_BUFFER))
#define test_buffer(L,idx)  ((pb_Buffer*)luaL_testudata(L,idx,PB_BUFFER))
#define check_slice(L,idx)  ((pb_Slice*)luaL_checkudata(L,idx,PB_SLICE))
#define test_slice(L,idx)   ((pb_Slice*)luaL_testudata(L,idx,PB_SLICE))
#define push_slice(L,s)     lua_pushlstring((L), (s).p, pb_len((s)))
#define return_self(L) { lua_settop(L, 1); return 1; }


/// tools
static int typeerror(lua_State *L, int idx, const char *type) {
    lua_pushfstring(L, "%s expected, got %s", type, luaL_typename(L, idx));
    return luaL_argerror(L, idx, lua_tostring(L, -1));
}

static pb_Slice lpb_toslice(lua_State *L, int idx) {
    int type = lua_type(L, idx);
    if (type == LUA_TSTRING) {
        size_t len;
        const char *s = lua_tolstring(L, idx, &len);
        printf("line = %d, is lua string.\n", __LINE__);
        return pb_lslice(s, len);
    } else if (type == LUA_TUSERDATA) {
        pb_Buffer *buffer;
        pb_Slice *s;
        if ((buffer = test_buffer(L, idx)) != NULL)
            return pb_result(buffer);
        else if ((s = test_slice(L, idx)) != NULL)
            return *s;
    }
    return pb_slice(NULL);
}

static pb_Slice lpb_checkslice(lua_State *L, int idx) {
    pb_Slice ret = lpb_toslice(L, idx);
    if (ret.p == NULL) typeerror(L, idx, "string/buffer/slice");
    return ret;
}
/*
static int Lgo_demo(lua_State *L)
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
*/

static int do_parser(lua_State *L, pb_Slice msg, int start) {
    
     // 从 lua 获取name,msg, 然后传给 cgo
    pb_Slice name = lpb_checkslice(L, 1);
    CSlice input_name;
    input_name.data = name.start;
    input_name.len = pb_len(name);

    CSlice input_msg;
    input_msg.data = msg.start;
    input_msg.len = pb_len(msg);
    
    CSlice decoded = call_cgo_parser(input_name, input_msg);
    lua_pushlstring(L, decoded.data, decoded.len);
    // free goString
    call_cgo_free_GoString(decoded);
    return 1;
}

static int Lgo_caller_parser(lua_State *L){
    return do_parser(L, lua_isnoneornil(L, 2) ?
        pb_lslice(NULL, 0) :
        lpb_checkslice(L, 2), 3);
}

// open wgo library
LUALIB_API int luaopen_go_caller(lua_State *L)
{
    luaL_Reg export_libs[] = {
        {"parser", Lgo_caller_parser},
        {NULL, NULL},
    };
    luaL_newlib(L, export_libs);
    return 1;
}
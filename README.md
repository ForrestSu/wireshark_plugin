# wireshark_plugin

This is a simple, extensible wireshark universal plug-in solution.

## 介绍

一般来说简单的协议使用 lua 实现即可

## 第三方依赖库 3rdparty

- [lua-protobuf](https://github.com/starwing/lua-protobuf)  
  纯 C 实现的 protobuf (prot2、proto3) lua 库，兼容lua5.1、lua5.2、lua5.3,
  可在lua中进行 pb 协议的codec.

- [json.lua](https://github.com/rxi/json.lua)  
  官方介绍： Implemented in pure Lua: works with 5.1, 5.2, 5.3 and JIT.
  lua json codec库。

## lua_plugins

存放简单的 lua 插件，可供参考学习。

## 运行环境说明

- 支持 MacOS

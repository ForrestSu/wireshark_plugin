# wireshark_plugin

This is a simple, extensible wireshark universal plug-in solution.

## 本仓库的目标

- 1 当业务遇到一种业务的字节协议时，可快速在 wireshark 中解析，展示；  
- 2 支持使用 go 实现；  
- 3 对解析要求不高(800条/s即可)，但是要准确解析；

## 前言

一般来说简单的协议使用 lua 实现即可，但是遇到 pb/thrift 等 tlv 类型的协议就比较麻烦了；  
比较友好的是，目前有lua-protobuf 这样的库，可以在lua中解析PB协议, 只需要提供proto即可；  
但是对于内部的 tlv 协议，由于本人不太会使用lua去封装c库；

突然萌生了一个想法，能不能用 golang 来开发 ws 插件？
于是尝试使用 lua5.2 直接调用cgo，没有成功；(PS: luajit借助于ffi是可以比较方便的调用cgo的)

于是想到了这个方案 `lua -> c -> go`, 初步来看这个方案是可行的，于是开始尝试。


## 第三方依赖库 3rdparty

- [lua-protobuf](https://github.com/starwing/lua-protobuf)  
  纯 C 实现的 protobuf (prot2、proto3) lua 库，兼容lua5.1、lua5.2、lua5.3,
  可在lua中进行 pb 协议的codec.

- [json.lua](https://github.com/rxi/json.lua)  
  官方介绍： Implemented in pure Lua: works with 5.1, 5.2, 5.3 and JIT.
  lua json codec库。

## lua_plugins

一些简单的 lua 插件，可供参考学习。

## QA

- 支持 MacOS

- Q 为什么要基于 lua5.2 开发？

A 前提是在 wireshark 中运行，而 wireshark 提供的是 lua5.2。  
当然也可以自动动手编译 wireshark+luaJit的版本， 但是我更想上手即用。  

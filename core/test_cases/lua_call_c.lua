local wgo = require "go_caller"

-- print(wgo.add(1.0, 2.0))
local str = "hello world Lua!"
print(wgo.parser("pb"))
print(wgo.parser("pb", str))

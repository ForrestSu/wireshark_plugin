
# MacOs
# build on lua5.2

git clone https://github.com/starwing/lua-protobuf.git 

set -x

cd lua-protobuf

include_dir=/usr/local/include/lua

gcc -O1 -Wall  -shared -I${include_dir} -undefined dynamic_lookup pb.c -o pb.so

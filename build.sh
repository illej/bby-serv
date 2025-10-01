#!/bin/bash

set -x
set -e

if [ ! -d include ]; then
    mkdir include
fi

if [ ! -d mdns ]; then
    git clone https://github.com/mjansson/mdns.git
    cp mdns/mdns.h include
fi

if [ ! -d nanopb ]; then
    git clone https://github.com/nanopb/nanopb.git
    cp nanopb/pb.h include
    cp nanopb/pb_encode.h include
    cp nanopb/pb_decode.h include
    cp nanopb/pb_common.h include

    cp nanopb/pb_encode.c .
    cp nanopb/pb_decode.c .
    cp nanopb/pb_common.c .
fi

if [ ! -e cast_channel.pb.c ]; then
    python nanopb/generator/nanopb_generator.py cast_channel.proto
fi

if [ ! -e tiny-json ]; then
    git clone https://github.com/rafagafe/tiny-json.git
    cp tiny-json/tiny-json.h include
    cp tiny-json/tiny-json.c .
fi

gcc -Wall -Werror main.c cast_channel.pb.c pb_encode.c pb_decode.c pb_common.c tiny-json.c -I include -o app -lssl -lcrypto

ctags -R .

exit 0

#!/bin/bash

mkdir /etc/miniature/
cp serverconfig.yaml /etc/miniature/config.yml
./server run -config=/etc/miniature/config.yml
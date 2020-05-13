#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 [domain] [mode] [log directory]"
  exit 1
fi

export LD_LIBRARY_PATH=../lib

for i in {1..100}
do
  echo "./client -h $1 -p 5555 -l $i -m $2 -d $3"
  ./client -h $1 -p 5555 -l $i -m $2 -d $3
  sleep 1
done

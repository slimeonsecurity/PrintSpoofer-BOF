#!/bin/bash

i686-w64-mingw32-gcc -c printspoofer.c -o printspoofer.x86.o
x86_64-w64-mingw32-gcc -c printspoofer.c -o printspoofer.x64.o

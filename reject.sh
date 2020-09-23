#!/bin/sh

#gcc codeinjector.c -L/home/main/binutils-2.22/bfd -l bfd -l /home/main/binutils-2.22/libiberty/libiberty.a -l z -o codeinjector
gcc -g main.c supported_ecus.c -l bfd -l dl -o codeinjector

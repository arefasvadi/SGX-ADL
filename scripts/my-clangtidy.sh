#!/usr/bin/env bash
CURDIR=$( cd .. && pwd )
# echo ${CURDIR}
check_files=$( find ${CURDIR} -maxdepth 3 -type f \( -iname \*.c -o -iname \*.cpp -o -iname \*.hpp -o -iname \*.cc -iname \*.h \) )
/usr/bin/clang-tidy-6.0 ${check_files} -header-filter='.*' -p='./' -checks='-*,modernize-*,bugprone-*,cert-*,cppcoreguildelines-*,performance-*,portability-*,readability-*,misc-*,clang-analyzer-*,clang-diagnostic-*,boost-*' &>clangtidy-log.txt

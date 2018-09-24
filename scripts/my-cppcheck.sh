#!/usr/bin/env bash
/usr/local/bin/cppcheck --enable=all --project=../compile_commands.json --verbose &>cppcheck-log.txt

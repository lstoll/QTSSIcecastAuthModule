#!/bin/bash
cd ../../dss/CommonUtilitiesLib/
export CPLUS=gcc
export CCOMP=gcc
export LINKER=gcc
export MAKE='make -j8 '
export COMPILER_FLAGS="-D_REENTRANT -D__USE_POSIX -D__linux__ -pipe"
export INCLUDE_FLAG="-include"
export CORE_LINK_LIBS="-lpthread -ldl -lstdc++ -lm -lcrypt"
export SHARED=-shared
export MODULE_LIBS=
cd ../APIStubLib
if [ ! -f libAPIStubLib.a ]; then
    echo 'FILE NOT EXIST!'
    pwd
    ./BuildAPIStubLib
fi
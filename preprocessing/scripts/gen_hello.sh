#!/bin/bash
MSP=0 # min sampling period used when generating tracepoint outputs
LOG_DIR=logs # log output directory
APP_DIR=apps # app directory
JAVA=jdk/bin/java # custom java binary
JAVAC=jdk/bin/javac # custom javac binary
TRACEFORMAT=jdk/bin/traceformat # custom traceformat binary
cd ..
mkdir "${LOG_DIR}"
chmod +x ./jdk/bin/*
cd "${APP_DIR}"
"../$JAVAC" HelloWorld.java
ITERS=$1
for I in $(seq 1 $ITERS)
do
    echo "../${LOG_DIR}/hello_trace_msp${MSP}_${I}.trc"
    # log tracepoint data to file
    "../${JAVA}" "-Xtrace:none,maximal=j9jit.93-95,buffers=50m,output=../${LOG_DIR}/hello_trace_msp${MSP}_${I}.trc" "-Xjit:minSamplingPeriod=${MSP}" HelloWorld
    "../${TRACEFORMAT}" "../${LOG_DIR}/hello_trace_msp${MSP}_${I}.trc"
    cd ..
    # generate the json data based on the tracepoint outputs
    python log2json.py -i "${LOG_DIR}/hello_trace_msp${MSP}_${I}.trc.fmt"
    cd ${APP_DIR}
done
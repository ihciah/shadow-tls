#!/bin/sh
tp=""
if [ ! -z "$THREADS" ]
then
    tp="--threads $THREADS"
fi
shadow-tls $tp $MODE $LISTEN $SERVER $TLS
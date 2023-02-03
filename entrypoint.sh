#!/bin/sh
parameter=""
if [ ! -z "$THREADS" ]
then
    parameter="$parameter --threads $THREADS"
fi

if [ ! -z "$DISABLE_NODELAY" ]
then
    parameter="$parameter --disable-nodelay"
fi

if [ "$MODE" = "server" ]
then
    parameter="$parameter $MODE"

    if [ ! -z "$TLS" ]
    then
        parameter="$parameter --tls $TLS"
    fi
fi

if [ "$MODE" = "client" ]
then
    parameter="$parameter $MODE"

    if [ ! -z "$TLS" ]
    then
        parameter="$parameter --sni $TLS"
    fi

    if [ ! -z "$ALPN" ]
    then
        parameter="$parameter --alpn $ALPN"
    fi
fi

if [ ! -z "$SERVER" ]
then
    parameter="$parameter --server $SERVER"
fi

if [ ! -z "$LISTEN" ]
then
    parameter="$parameter --listen $LISTEN"
fi

if [ ! -z "$PASSWORD" ]
then
    parameter="$parameter --password $PASSWORD"
fi

exec shadow-tls $parameter
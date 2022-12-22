#!/bin/sh
parameter=""
if [ ! -z "$THREADS" ]
then
    parameter="$parameter --threads $THREADS"
fi

if [ ! -z "$NODELAY" ]
then
    parameter="$parameter --nodelay"
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

shadow-tls $parameter
#!/bin/bash
export CHIA_ROOT=~/.chia/simulator/main
chia dev sim stop
chia dev sim start -r
sleep 2
chia dev sim revert -rfd
rm ~/.chia/simulator/main/wallet/db/*
chia start -r wallet
chia dev sim farm

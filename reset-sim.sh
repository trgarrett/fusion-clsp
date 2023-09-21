#!/bin/bash
chia dev sim start -r
echo "y\n" | chia dev sim revert -rf
chia dev sim farm
rm ~/.chia/simulator/main/wallet/db/*
chia start -r wallet

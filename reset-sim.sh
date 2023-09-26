#!/bin/bash
chia dev sim stop
chia dev sim start -r
chia dev sim revert -rfd
rm ~/.chia/simulator/main/wallet/db/*
chia start -r wallet
chia dev sim farm

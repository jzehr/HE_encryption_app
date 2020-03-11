#!/bin/bash

cd bin/

printf "\n~~Encrypting site A~~\n"
./site_a

printf "\n~~Encrypting site B~~\n"
./site_b

printf "\n~~Comparing Sites A and B~~\n"
./compare_a_b

printf "\n~~Results of run: \n"
./read_hamming

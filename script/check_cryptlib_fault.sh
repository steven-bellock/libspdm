#!/bin/bash

# Checks that the crypto fault injection layer in unit_test/cryptlib_fault matches the crypto
# backend API headers, by generating it again.

set -e

# Change directory to top of repository.
cd `dirname $0`
cd ../

python3 script/generate_cryptlib_fault.py
git diff --exit-code unit_test/cryptlib_fault

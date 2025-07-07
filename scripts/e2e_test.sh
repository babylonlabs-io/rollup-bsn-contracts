#!/bin/bash

set -e  # Exit immediately if any command fails

cd e2e
go test -count=1 -v ./...
cd -

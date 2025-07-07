#!/bin/bash

cd e2e
go test -count=1 -v ./...
cd -

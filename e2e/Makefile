#!/usr/bin/make -f

BUILD_DIR = ./build

all: test

test:
	go test -mod=readonly -race ./...

build:
	CGO_ENABLED=1 go test -c -mod=readonly -o $(BUILD_DIR)/babylon-sdk.e2e.test

build-linux:
	CGO_ENABLED=1  GOOS=linux go test -c -mod=readonly -o $(BUILD_DIR)/babylon-sdk.e2e.test

lint:
	golangci-lint run --tests=false ./...

.PHONY: all build build-linux test format lint

BINARY=unifi-minimal-exporter

$(BINARY): $(shell find . -name '*.go') go.sum
	CGO_ENABLED=0 go build \
		-ldflags "-X main.version=$(shell git describe --long --tags --dirty --always)"  \
		-o $@

go.sum: go.mod
	go mod tidy

.PHONY: clean
clean:
	@rm $(BINARY) || true

BIN := ocellus
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build release test race lint clean e2e e2e-up e2e-down

build:
	go build -o $(BIN) .

release:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) .

test:
	go test ./...

race:
	go test -race ./...

lint:
	go vet ./...

clean:
	rm -f $(BIN)

e2e-up:
	./test/e2e/setup.sh up

e2e-down:
	./test/e2e/setup.sh down

e2e: build e2e-up
	go test -tags e2e -v -count=1 ./test/e2e/...; status=$$?; \
	$(MAKE) e2e-down; \
	exit $$status

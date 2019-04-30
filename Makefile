BUILD_DATE := $(shell date -u '+%Y%m%d.%H%M%S')
VERSION := $(shell git describe --tags)
FLAGS := -X main.builddate=$(BUILD_DATE) -X main.version=$(VERSION)
STATIC := -a -ldflags "-extldflags '-static' $(FLAGS)"

all: dev

vars:
	echo $(BUILD_DATE)
	echo $(FLAGS)

dev:
	go build -o phpsecscan -ldflags "$(FLAGS)" cmd/phpsecscan.go

linux:
	CGO_ENABLED=0 GOOS=linux go build -o phpsecscan-linux $(STATIC) cmd/phpsecscan.go

windows:
	CGO_ENABLED=0 GOOS=windows go build -o phpsecscan-win.exe -a $(STATIC) cmd/phpsecscan.go

clean:
	@rm -f phpsecscan phpsecscan-linux phpsecscan-win.exe phpsecscan-darwin 2> /dev/null


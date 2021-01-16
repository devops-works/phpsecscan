BUILD_DATE := $(shell date -u '+%Y%m%d.%H%M%S')
VERSION := $(shell git describe --tags --always --dirty --match=v* 2> /dev/null || \
			cat $(CURDIR)/.version 2> /dev/null || echo v0)
FLAGS := -X main.buildDate=$(BUILD_DATE) -X main.version=$(VERSION)
STATIC := -a -ldflags "-extldflags '-static' $(FLAGS)"

IMAGE_NAME = devopsworks/phpsecscan:${VERSION}

PROJECT=cloudrun-test-239609

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

deploy:
	docker push gcr.io/cloudrun-test-239609/${IMAGE_NAME}
	gcloud --project=${PROJECT} beta run deploy --image gcr.io/cloudrun-test-239609/${IMAGE_NAME}

docker:
	docker build . -t ${IMAGE_NAME} -t gcr.io/cloudrun-test-239609/${IMAGE_NAME}

clean:
	@rm -f phpsecscan phpsecscan-linux phpsecscan-win.exe phpsecscan-darwin 2> /dev/null


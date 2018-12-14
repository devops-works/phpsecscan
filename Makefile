
linux:
	CGO_ENABLED=0 GOOS=linux go build -o phpsecscan-linux -a -ldflags '-extldflags "-static"' cmd/phpsecscan.go

windows:
	CGO_ENABLED=0 GOOS=windows go build -o phpsecscan-win32.exe -a -ldflags '-extldflags "-static"' cmd/phpsecscan.go

clean:
	-rm -f phpsecscan phpsecscan-linux phpsecscan.exe phpsecscan-darwin 2> /dev/null


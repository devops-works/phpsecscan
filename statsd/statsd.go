package statsd

import (
	"fmt"
	"io"
	"net"
	"time"
)

var queue = make(chan string, 100)
var isopen = false

func Open(r string) {
  isopen = true
	go statsdSender(r)
}

func logmetric(metric string) {
  if isopen {
    queue <- metric
  }
}

func Count(metric string, value int) {
	logmetric(fmt.Sprintf("%s:%d|c", metric, value))
}

func Time(metric string, took time.Duration) {
	logmetric(fmt.Sprintf("%s:%d|ms", metric, took/1e6))
}

func Gauge(metric string, value int) {
	logmetric(fmt.Sprintf("%s:%d|g", metric, value))
}

func statsdSender(remote string) {
	for s := range queue {
		if conn, err := net.Dial("udp", remote); err == nil {
			io.WriteString(conn, s)
			conn.Close()
		}
	}
}

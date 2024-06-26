// Copyright 2018 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

// Package main contains the test driver for testing xDS manually.
package main

import (
	"bufio"
	"context"
//	cryptotls "crypto/tls"
	"flag"
	"fmt"
//	"io/ioutil"
//	"net/http"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/pkg/cache"
	"github.com/envoyproxy/go-control-plane/pkg/server"

	xds "github.com/jingnanzhou/sidecar-operator/pkg/xds"
	 resource "github.com/jingnanzhou/sidecar-operator/pkg/xds/resource"
)

var (
	debug bool

	port         uint
	gatewayPort  uint
	upstreamPort uint
	basePort     uint
	alsPort      uint

	delay    time.Duration
	requests int
	updates  int

	mode          string
	clusters      int
	httpListeners int
	tcpListeners  int
	tls           bool

	nodeID string
)

func init() {
	flag.BoolVar(&debug, "debug", true, "Use debug logging")
	flag.UintVar(&port, "port", 18000, "Management server port")
	flag.UintVar(&gatewayPort, "gateway", 18001, "Management server port for HTTP gateway")
	flag.UintVar(&upstreamPort, "upstream", 18080, "Upstream HTTP/1.1 port")
	flag.UintVar(&basePort, "base", 9000, "Listener port")
	flag.UintVar(&alsPort, "als", 18090, "Accesslog server port")
	flag.DurationVar(&delay, "delay", 500*time.Millisecond, "Interval between request batch retries")
	flag.IntVar(&requests, "r", 5, "Number of requests between snapshot updates")
	flag.IntVar(&updates, "u", 3, "Number of snapshot updates")
	flag.StringVar(&mode, "xds", resource.Ads, "Management server type (ads, xds, rest)")
	flag.IntVar(&clusters, "clusters", 4, "Number of clusters")
	flag.IntVar(&httpListeners, "http", 2, "Number of HTTP listeners (and RDS configs)")
	flag.IntVar(&tcpListeners, "tcp", 2, "Number of TCP pass-through listeners")
	flag.StringVar(&nodeID, "nodeID", "test-id", "Node ID")
	flag.BoolVar(&tls, "tls", false, "Enable TLS on all listeners and use SDS for secret delivery")
}

// main returns code 1 if any of the batches failed to pass all requests
func main() {
	flag.Parse()
	if debug {
		log.SetLevel(log.DebugLevel)
	}
	ctx := context.Background()

	// start upstream
	go xds.RunHTTP(ctx, upstreamPort)

	// create a cache
	signal := make(chan struct{})
	cb := &callbacks{signal: signal}
	config := cache.NewSnapshotCache(mode == resource.Ads, xds.Hasher{}, logger{})
	srv := server.NewServer(config, cb)
	als := &xds.AccessLogService{}

	version := fmt.Sprintf("v%d", 0)
	// create a test snapshot
	snapshots := resource.TestSnapshot{
		Xds:              mode,
		UpstreamPort:     uint32(upstreamPort),
		BasePort:         uint32(basePort),
		NumClusters:      clusters,
		NumHTTPListeners: httpListeners,
		NumTCPListeners:  tcpListeners,
		TLS:              tls,
		Version:					version,
	}

	// start the xDS server
	go xds.RunAccessLogServer(ctx, als, alsPort)
	go xds.RunManagementServer(ctx, srv, port)
	go xds.RunManagementGateway(ctx, srv, gatewayPort)

	log.Infof("waiting for the first request...")
	<-signal
	log.Infof("initial snapshot %+v", snapshots)
	log.WithFields(log.Fields{"updates": updates, "requests": requests}).Info("executing sequence")


		als.Dump(func(s string) { log.Debug(s) })
		cb.Report()

   for {
		reader := bufio.NewReader(os.Stdin)
		 switch line, _,_  := reader.ReadLine(); string(line) {

		 case "12001":
			 log.Debugf(" processing 12001 \n")

			 snapshot := resource.CreateEmbedConfig(
				 "google_cluster",
	 		 		"www.google.com",
	 		 		uint32(443),
	 		 		"0.0.0.0",
	 		 		uint32(12001),
	 		  	"v0",
					)


//			 snapshot := snapshots.Create()
 		 //	snapshot := snapshots.Build()
			 	if err := snapshot.Consistent(); err != nil {
			 			log.Errorf("snapshot inconsistency: %+v", snapshot)
			 	}
			 	err := config.SetSnapshot(nodeID, snapshot)
			 		if err != nil {
			 			log.Errorf("snapshot error %q for %+v", err, snapshot)
			 			os.Exit(1)
			 }

		 case "9000":
			 log.Debugf( " processing 9000 \n")
			 snapshot := resource.CreateXdsConfig(
			 	"xds",
				"xds_cluster",
				"cluster_name",
				"192.168.65.2",

			 	uint32(18080),
				"0.0.0.0",
				uint32(9000),
				"v1",
			 	)

		//	snapshot := snapshots.Create()
// 		 	snapshot := snapshots.Build()
			 	if err := snapshot.Consistent(); err != nil {
			 			log.Errorf("snapshot inconsistency: %+v", snapshot)
			 	}
			 	err := config.SetSnapshot(nodeID, snapshot)
			 		if err != nil {
			 			log.Errorf("snapshot error %q for %+v", err, snapshot)
			 			os.Exit(1)
			 }
		 default:
			 log.Debugf(" You type %s is not in the list \n", line)
		 }
	 }
}

type logger struct{}

func (logger logger) Infof(format string, args ...interface{}) {
	log.Debugf(format, args...)
}
func (logger logger) Errorf(format string, args ...interface{}) {
	log.Errorf(format, args...)
}

type callbacks struct {
	signal   chan struct{}
	fetches  int
	requests int
	mu       sync.Mutex
}

func (cb *callbacks) Report() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	log.WithFields(log.Fields{"fetches": cb.fetches, "requests": cb.requests}).Info("server callbacks")
}
func (cb *callbacks) OnStreamOpen(_ context.Context, id int64, typ string) error {
	log.Debugf("stream %d open for %s", id, typ)
	return nil
}
func (cb *callbacks) OnStreamClosed(id int64) {
	log.Debugf("stream %d closed", id)
}
func (cb *callbacks) OnStreamRequest(int64, *v2.DiscoveryRequest) error {
	log.Debugf("OnStreamRequest called")

	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.requests++
	if cb.signal != nil {
		close(cb.signal)
		cb.signal = nil
	}
	return nil
}
func (cb *callbacks) OnStreamResponse(int64, *v2.DiscoveryRequest, *v2.DiscoveryResponse) {}
func (cb *callbacks) OnFetchRequest(_ context.Context, req *v2.DiscoveryRequest) error {
	log.Debugf("OnFetchRequest called")

	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.fetches++
	if cb.signal != nil {
		close(cb.signal)
		cb.signal = nil
	}
	return nil
}
func (cb *callbacks) OnFetchResponse(*v2.DiscoveryRequest, *v2.DiscoveryResponse) {


}

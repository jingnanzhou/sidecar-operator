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

// Package resource creates test xDS resources
package resource

import (
	"fmt"
	"time"
"regexp"
	"github.com/gogo/protobuf/types"

	v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/endpoint"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	als "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v2"
	alf "github.com/envoyproxy/go-control-plane/envoy/config/filter/accesslog/v2"
	hcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	tcp "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/tcp_proxy/v2"
	"github.com/envoyproxy/go-control-plane/pkg/cache"
	"github.com/envoyproxy/go-control-plane/pkg/util"
)

const (
	localhost = "0.0.0.0"

	// XdsCluster is the cluster name for the control server (used by non-ADS set-up)
	XdsCluster = "xds_cluster"

	// Ads mode for resources: one aggregated xDS service
	Ads = "ads"

	// Xds mode for resources: individual xDS services
	Xds = "xds"

	// Rest mode for resources: polling using Fetch
	Rest = "rest"
)

var (
	// RefreshDelay for the polling config source
	RefreshDelay = 500 * time.Millisecond
)

// MakeEndpoint creates a localhost endpoint on a given port.
func MakeEndpoint(clusterName string, address string, port uint32) *v2.ClusterLoadAssignment {
	return &v2.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []endpoint.LocalityLbEndpoints{{
			LbEndpoints: []endpoint.LbEndpoint{{
				HostIdentifier: &endpoint.LbEndpoint_Endpoint{
					Endpoint: &endpoint.Endpoint{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Protocol: core.TCP,
									Address:  address,
									PortSpecifier: &core.SocketAddress_PortValue{
										PortValue: port,
									},
								},
							},
						},
					},
				},
			}},
		}},
	}
}

// CreateEdsCluster creates a cluster using either ADS or EDS.
func CreateEdsCluster(mode string, xdsCluster string, clusterName string) *v2.Cluster {
	edsSource := configSource(mode, xdsCluster,RefreshDelay)

	return &v2.Cluster{
		Name:                 clusterName,
		ConnectTimeout:       5 * time.Second,

		ClusterDiscoveryType: &v2.Cluster_Type{Type: v2.Cluster_EDS},
		EdsClusterConfig: &v2.Cluster_EdsClusterConfig{
			EdsConfig: edsSource,
		},
	}
}
// CreateEPCluster creates a cluster using either ADS or EDS.
func CreateEPCluster(address string, port uint32, clusterName string) *v2.Cluster {
		eps := MakeEndpoint(clusterName, address, port)
		sni :=address
		clusterType :=v2.Cluster_LOGICAL_DNS
		match, _ := regexp.MatchString("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}", address)
		if match {
			clusterType=v2.Cluster_STRICT_DNS
		}
		if match || port != uint32(443) {
			sni=""
		}

		cluster :=&v2.Cluster{
				Name:            clusterName,
				ConnectTimeout:  2 * time.Second,
				ClusterDiscoveryType: &v2.Cluster_Type{Type: clusterType},
				DnsLookupFamily: v2.Cluster_V4_ONLY,
				LbPolicy:        v2.Cluster_ROUND_ROBIN,
				LoadAssignment: eps,
		}

		if sni !="" {
			cluster.TlsContext=&auth.UpstreamTlsContext{
				Sni:sni,
			}
		}
		return cluster
}

// MakeRoute creates an HTTP route that routes to a given cluster.
func MakeRoute(routeName, clusterName string) *v2.RouteConfiguration {
	return &v2.RouteConfiguration{
		Name: routeName,
		VirtualHosts: []route.VirtualHost{{
			Name:    routeName,
			Domains: []string{"*"},
			Routes: []route.Route{{
				Match: route.RouteMatch{
					PathSpecifier: &route.RouteMatch_Prefix{
						Prefix: "/",
					},
				},
				Action: &route.Route_Route{
					Route: &route.RouteAction{
						ClusterSpecifier: &route.RouteAction_Cluster{
							Cluster: clusterName,
						},
					},
				},
			}},
		}},
	}
}

// data source configuration
func configSource(mode string, xdsCluster string, refreshDelay time.Duration ) *core.ConfigSource {
	source := &core.ConfigSource{}
	switch mode {
	case Ads:
		source.ConfigSourceSpecifier = &core.ConfigSource_Ads{
			Ads: &core.AggregatedConfigSource{},
		}
	case Xds:
		source.ConfigSourceSpecifier = &core.ConfigSource_ApiConfigSource{
			ApiConfigSource: &core.ApiConfigSource{
				ApiType: core.ApiConfigSource_GRPC,
				GrpcServices: []*core.GrpcService{{
					TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: xdsCluster},
					},
				}},
			},
		}
	case Rest:
		source.ConfigSourceSpecifier = &core.ConfigSource_ApiConfigSource{
			ApiConfigSource: &core.ApiConfigSource{
				ApiType:      core.ApiConfigSource_REST,
				ClusterNames: []string{XdsCluster},
				RefreshDelay: &refreshDelay,
			},
		}
	}
	return source
}

// MakeRdsHTTPListener creates a listener using either ADS or RDS for the route.
func MakeRdsHTTPListener(mode string, xdsCluster string,  listenerName string, address string, port uint32, route string) *v2.Listener {
	rdsSource := configSource(mode, xdsCluster,RefreshDelay)

	// access log service configuration
	alsConfig := &als.HttpGrpcAccessLogConfig{
		CommonConfig: &als.CommonGrpcAccessLogConfig{
			LogName: "echo",
			GrpcService: &core.GrpcService{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
						ClusterName: xdsCluster,
					},
				},
			},
		},
	}
	alsConfigPbst, err := types.MarshalAny(alsConfig)
	if err != nil {
		panic(err)
	}

	// HTTP filter configuration
	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.AUTO,
		StatPrefix: "http",
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource:    *rdsSource,
				RouteConfigName: route,
			},
		},
		HttpFilters: []*hcm.HttpFilter{{
			Name: util.Router,
		}},
		AccessLog: []*alf.AccessLog{{
			Name: util.HTTPGRPCAccessLog,
			ConfigType: &alf.AccessLog_TypedConfig{
				TypedConfig: alsConfigPbst,
			},
		}},
	}
	pbst, err := types.MarshalAny(manager)
	if err != nil {
		panic(err)
	}

	return &v2.Listener{
		Name: listenerName,
		Address: core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.TCP,
					Address:  address,
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: port,
					},
				},
			},
		},
		FilterChains: []listener.FilterChain{{
			Filters: []listener.Filter{{
				Name: util.HTTPConnectionManager,
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			}},
		}},
	}
}
// MakeHTTPListener creates a listener using either ADS or RDS for the route.

func MakeHTTPListener(listenerName string, address string, port uint32,clusterName string, virtualHostName string, routeConfigName string, clusterAddress string) *v2.Listener {

	v := route.VirtualHost{
		Name:    virtualHostName,
		Domains: []string{"*"},

		Routes: []route.Route{{
			Match: route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Prefix{
					Prefix: "/",
				},
			},
/*
			Match: route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Regex{
					Regex: "/*",
				},
			},*/

			Action: &route.Route_Route{
				Route: &route.RouteAction{

					HostRewriteSpecifier: &route.RouteAction_HostRewrite{
						HostRewrite: clusterAddress,
					},

					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: clusterName,
					},
				//	PrefixRewrite: "/robots.txt",
				},
			},
		}}}


	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.AUTO,
		StatPrefix: "ingress_http",
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: &v2.RouteConfiguration{
				Name:         routeConfigName,
				VirtualHosts: []route.VirtualHost{v},
			},
		},
		HttpFilters: []*hcm.HttpFilter{{
			Name: util.Router,
		}},
	}


	pbst, err := types.MarshalAny(manager)
	if err != nil {
		panic(err)
	}

	return &v2.Listener{
		Name: listenerName,
		Address: core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.TCP,
					Address:  address,
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: port,
					},
				},
			},
		},
		FilterChains: []listener.FilterChain{{
			Filters: []listener.Filter{{
				Name: util.HTTPConnectionManager,
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			}},
		}},
	}
}

// MakeTCPListener creates a TCP listener for a cluster.
func MakeTCPListener(listenerName string,address string,  port uint32, clusterName string) *v2.Listener {
	// TCP filter configuration
	config := &tcp.TcpProxy{
		StatPrefix: "tcp",
		ClusterSpecifier: &tcp.TcpProxy_Cluster{
			Cluster: clusterName,
		},
	}
	pbst, err := types.MarshalAny(config)
	if err != nil {
		panic(err)
	}
	return &v2.Listener{
		Name: listenerName,
		Address: core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.TCP,
					Address:  address,
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: port,
					},
				},
			},
		},
		FilterChains: []listener.FilterChain{{
			Filters: []listener.Filter{{
				Name: util.TCPProxy,
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			}},
		}},
	}
}

// TestSnapshot holds parameters for a synthetic snapshot.
type TestSnapshot struct {
	// Xds indicates snapshot mode: ads, xds, or rest
	Xds string
	// Version for the snapshot.
	Version string
	// UpstreamPort for the single endpoint on the localhost.
	UpstreamPort uint32
	// BasePort is the initial port for the listeners.
	BasePort uint32
	// NumClusters is the total number of clusters to generate.
	NumClusters int
	// NumHTTPListeners is the total number of HTTP listeners to generate.
	NumHTTPListeners int
	// NumTCPListeners is the total number of TCP listeners to generate.
	// Listeners are assigned clusters in a round-robin fashion.
	NumTCPListeners int
	// TLS enables SDS-enabled TLS mode on all listeners
	TLS bool
}

// Generate produces a snapshot from the parameters.
func (ts TestSnapshot) Generate() cache.Snapshot {
	clusters := make([]cache.Resource, ts.NumClusters+1)
	endpoints := make([]cache.Resource, ts.NumClusters)
	for i := 0; i < ts.NumClusters; i++ {
		name := fmt.Sprintf("cluster-%s-%d", ts.Version, i)
		clusters[i] = CreateEdsCluster(ts.Xds, XdsCluster, name)
		endpoints[i] = MakeEndpoint(name, "192.168.65.2", ts.UpstreamPort)
	}
	clusters[ts.NumClusters]=CreateEPCluster("www.google.com", uint32(443), "google_cluster")

	routes := make([]cache.Resource, ts.NumHTTPListeners)
	for i := 0; i < ts.NumHTTPListeners; i++ {
		name := fmt.Sprintf("route-%s-%d", ts.Version, i)
		routes[i] = MakeRoute(name, cache.GetResourceName(clusters[i%ts.NumClusters]))
	}

	total := ts.NumHTTPListeners + ts.NumTCPListeners
	listeners := make([]cache.Resource, total+1)
	for i := 0; i < total; i++ {
		port := ts.BasePort + uint32(i)
		// listener name must be same since ports are shared and previous listener is drained
		name := fmt.Sprintf("listener-%d", port)
		var listener *v2.Listener
		if i < ts.NumHTTPListeners {

			listener = MakeRdsHTTPListener(ts.Xds, XdsCluster,name, localhost,port, cache.GetResourceName(routes[i]))
		} else {
			listener = MakeTCPListener(name, localhost, port, cache.GetResourceName(clusters[i%ts.NumClusters]))
		}

		if ts.TLS {
			for i, chain := range listener.FilterChains {
				chain.TlsContext = &auth.DownstreamTlsContext{
					CommonTlsContext: &auth.CommonTlsContext{
						TlsCertificateSdsSecretConfigs: []*auth.SdsSecretConfig{{
							Name:      tlsName,
							SdsConfig: configSource(ts.Xds,XdsCluster,RefreshDelay),
						}},
						ValidationContextType: &auth.CommonTlsContext_ValidationContextSdsSecretConfig{
							ValidationContextSdsSecretConfig: &auth.SdsSecretConfig{
								Name:      rootName,
								SdsConfig: configSource(ts.Xds,XdsCluster,RefreshDelay),
							},
						},
					},
				}
				listener.FilterChains[i] = chain
			}
		}

		listeners[i] = listener
	}

	listeners[total] =MakeHTTPListener("google1", "0.0.0.0",12001, "google_cluster",  "local_service",   "local_route","www.googl;com")

	out := cache.Snapshot{
		Endpoints: cache.NewResources(ts.Version, endpoints),
		Clusters:  cache.NewResources(ts.Version, clusters),
		Routes:    cache.NewResources(ts.Version, routes),
		Listeners: cache.NewResources(ts.Version, listeners),
	}

	if ts.TLS {
		out.Secrets = cache.NewResources(ts.Version, MakeSecrets(tlsName, rootName))
	}

	return out
}




// Generate produces a snapshot from the parameters.
func  CreateXdsConfig(
	mode string,
	xdsCluster string,
	clusterName string,
	clusterAddress string,
	clusterPort uint32,
	listenerAddress string,
	listenerPort uint32,
	version string,

	) cache.Snapshot {
/*
mode :=ts.Xds
xdsCluster := XdsCluster
clusterName := "cluster_name"
address :="192.168.65.2"
port := ts.UpstreamPort
listenerAddress := localhost
listenerPort := ts.BasePort
version :=ts.Version
*/

routeName := fmt.Sprintf("%d_route",clusterName )
cluster  := CreateEdsCluster(mode, xdsCluster, clusterName)

endpoint := MakeEndpoint(clusterName, clusterAddress ,clusterPort)

listenerName := fmt.Sprintf("%d_listener",clusterName )

route  := MakeRoute(routeName, cache.GetResourceName(cluster))

listener := MakeRdsHTTPListener(mode, xdsCluster,listenerName, listenerAddress,listenerPort, cache.GetResourceName(route))
/*
		if ts.TLS {
			for i, chain := range listener.FilterChains {
				chain.TlsContext = &auth.DownstreamTlsContext{
					CommonTlsContext: &auth.CommonTlsContext{
						TlsCertificateSdsSecretConfigs: []*auth.SdsSecretConfig{{
							Name:      tlsName,
							SdsConfig: configSource(ts.Xds,XdsCluster,RefreshDelay),
						}},
						ValidationContextType: &auth.CommonTlsContext_ValidationContextSdsSecretConfig{
							ValidationContextSdsSecretConfig: &auth.SdsSecretConfig{
								Name:      rootName,
								SdsConfig: configSource(ts.Xds,XdsCluster,RefreshDelay),
							},
						},
					},
				}
				listener.FilterChains[i] = chain
			}
		}
*/
	out := cache.NewSnapshot(fmt.Sprint(version), []cache.Resource{endpoint}, []cache.Resource{cluster}, []cache.Resource{route}, []cache.Resource{listener})
	return out
}

// Generate produces a snapshot from the parameters.
//func (ts TestSnapshot) Create() cache.Snapshot {

	// Generate produces a snapshot from the parameters.
	func  CreateEmbedConfig(
		clusterName string,
		clusterAddress string,
		clusterPort uint32,
		listenerAddress string,
		listenerPort uint32,
		version string,
		) cache.Snapshot {


	/*
	clusterAddress :="www.google.com"
	clusterPort := uint32(443)
	clusterName :="google_cluster"

	listenerAddress := "0.0.0.0"
	listenerPort := uint32(12001)
  version := ts.Version
*/
	listenerName := fmt.Sprintf("%d_listener",clusterName )

	virtualHostName := fmt.Sprintf("%d_host",clusterName )

	routeConfigName := fmt.Sprintf("%d_routeConfig",clusterName )

	cluster :=CreateEPCluster(clusterAddress, clusterPort, clusterName)

	listener :=MakeHTTPListener(listenerName, listenerAddress, listenerPort, clusterName,  virtualHostName, routeConfigName,clusterAddress)

	out := cache.NewSnapshot(fmt.Sprint(version), nil, []cache.Resource{cluster}, nil, []cache.Resource{listener})

	return out
}

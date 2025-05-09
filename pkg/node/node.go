package node

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/FavorLabs/favorX/pkg/accounting"
	"github.com/FavorLabs/favorX/pkg/address"
	"github.com/FavorLabs/favorX/pkg/addressbook"
	"github.com/FavorLabs/favorX/pkg/api"
	"github.com/FavorLabs/favorX/pkg/auth"
	"github.com/FavorLabs/favorX/pkg/boson"
	"github.com/FavorLabs/favorX/pkg/chunkinfo"
	"github.com/FavorLabs/favorX/pkg/crypto"
	"github.com/FavorLabs/favorX/pkg/crypto/cert"
	"github.com/FavorLabs/favorX/pkg/debugapi"
	"github.com/FavorLabs/favorX/pkg/fileinfo"
	"github.com/FavorLabs/favorX/pkg/hive2"
	"github.com/FavorLabs/favorX/pkg/localstore"
	"github.com/FavorLabs/favorX/pkg/logging"
	"github.com/FavorLabs/favorX/pkg/multicast"
	"github.com/FavorLabs/favorX/pkg/multicast/model"
	"github.com/FavorLabs/favorX/pkg/netrelay"
	"github.com/FavorLabs/favorX/pkg/netstore"
	"github.com/FavorLabs/favorX/pkg/p2p/libp2p"
	"github.com/FavorLabs/favorX/pkg/pingpong"
	"github.com/FavorLabs/favorX/pkg/pinning"
	"github.com/FavorLabs/favorX/pkg/resolver/multiresolver"
	"github.com/FavorLabs/favorX/pkg/retrieval"
	"github.com/FavorLabs/favorX/pkg/routetab"
	"github.com/FavorLabs/favorX/pkg/rpc"
	"github.com/FavorLabs/favorX/pkg/shed"
	"github.com/FavorLabs/favorX/pkg/subscribe"
	"github.com/FavorLabs/favorX/pkg/topology/bootnode"
	"github.com/FavorLabs/favorX/pkg/topology/kademlia"
	"github.com/FavorLabs/favorX/pkg/topology/lightnode"
	"github.com/FavorLabs/favorX/pkg/tracing"
	"github.com/FavorLabs/favorX/pkg/traversal"
	"github.com/inhies/go-bytesize"
	crypto2 "github.com/libp2p/go-libp2p/core/crypto"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type Favor struct {
	p2pService       io.Closer
	p2pCancel        context.CancelFunc
	apiCloser        io.Closer
	apiServer        *http.Server
	debugAPIServer   *http.Server
	vpnServer        *http.Server
	proxyTCPServer   io.Closer
	proxyUDPServer   io.Closer
	rpcServer        io.Closer
	resolverCloser   io.Closer
	errorLogWriter   *io.PipeWriter
	tracerCloser     io.Closer
	groupCloser      io.Closer
	stateStoreCloser io.Closer
	localstoreCloser io.Closer
	topologyCloser   io.Closer
	ethClientCloser  func()
}

type Options struct {
	DataDir                string
	CacheCapacity          uint64
	DBDriver               string
	DBPath                 string
	HTTPAddr               string
	WSAddr                 string
	APIAddr                string
	DebugAPIAddr           string
	ApiBufferSizeMul       int
	NATAddr                string
	EnableWS               bool
	EnableQUIC             bool
	WelcomeMessage         string
	Bootnodes              []string
	ChainEndpoint          string
	OracleContractAddress  string
	CORSAllowedOrigins     []string
	Logger                 logging.Logger
	Standalone             bool
	IsDev                  bool
	TracingEnabled         bool
	TracingEndpoint        string
	TracingServiceName     string
	ResolverConnectionCfgs []multiresolver.ConnectionConfig
	GatewayMode            bool
	TrafficEnable          bool
	TrafficContractAddr    string
	KadBinMaxPeers         int
	LightNodeMaxPeers      int
	AllowPrivateCIDRs      bool
	Restricted             bool
	TokenEncryptionKey     string
	AdminPasswordHash      string
	RouteAlpha             int32
	Groups                 []model.ConfigNodeGroup
	EnableApiTLS           bool
	TlsCrtFile             string
	TlsKeyFile             string
	ProxyEnable            bool
	ProxyAddr              string
	ProxyNATAddr           string
	ProxyGroup             string
	TunEnable              bool
	TunCidr4               string
	TunCidr6               string
	TunMTU                 int
	TunServiceIPv4         string
	TunServiceIPv6         string
	TunGroup               string
	TunSpeedMin            uint64
	TunSpeedMax            uint64
	TunRateEveryday        string
	TunRateEnable          bool
	VpnEnable              bool
	VpnAddr                string
	Relay                  bool
}

func NewNode(nodeMode address.Model, addr string, bosonAddress boson.Address, publicKey ecdsa.PublicKey, signer crypto.Signer, networkID uint64, logger logging.Logger, libp2pPrivateKey crypto2.PrivKey, o Options) (b *Favor, err error) {
	tracer, tracerCloser, err := tracing.NewTracer(&tracing.Options{
		Enabled:     o.TracingEnabled,
		Endpoint:    o.TracingEndpoint,
		ServiceName: o.TracingServiceName,
	})
	if err != nil {
		return nil, fmt.Errorf("tracer: %w", err)
	}

	p2pCtx, p2pCancel := context.WithCancel(context.Background())
	defer func() {
		// if there's been an error on this function
		// we'd like to cancel the p2p context so that
		// incoming connections will not be possible
		if err != nil {
			p2pCancel()
		}
	}()

	b = &Favor{
		p2pCancel:      p2pCancel,
		errorLogWriter: logger.WriterLevel(logrus.ErrorLevel),
		tracerCloser:   tracerCloser,
	}

	// a struct warped publish-subscribe function
	subPub := subscribe.NewSubPub()

	var authenticator *auth.Authenticator

	if o.Restricted {
		if authenticator, err = auth.New(o.TokenEncryptionKey, o.AdminPasswordHash, logger); err != nil {
			return nil, fmt.Errorf("authenticator: %w", err)
		}
		logger.Info("starting with restricted APIs")
	}

	var debugAPIService *debugapi.Service

	if o.EnableApiTLS && o.TlsKeyFile == "" && o.TlsCrtFile == "" {
		// auto create
		crt := cert.New(o.DataDir).LoadCA().MakeCert()
		o.TlsKeyFile = crt.KeyFile
		o.TlsCrtFile = crt.CertFile
	}

	if o.DebugAPIAddr != "" {
		// set up basic debug api endpoints for debugging and /health endpoint
		debugAPIService = debugapi.New(bosonAddress, publicKey, logger, tracer, o.CORSAllowedOrigins, o.Restricted, authenticator, debugapi.Options{
			DataDir:        o.DataDir,
			NATAddr:        o.NATAddr,
			NetworkID:      networkID,
			EnableWS:       o.EnableWS,
			EnableQUIC:     o.EnableQUIC,
			NodeMode:       nodeMode,
			WelcomeMessage: o.WelcomeMessage,
			LightNodeLimit: o.LightNodeMaxPeers,
		})

		debugAPIListener, err := net.Listen("tcp", o.DebugAPIAddr)
		if err != nil {
			return nil, fmt.Errorf("debug api listener: %w", err)
		}

		debugAPIServer := &http.Server{
			IdleTimeout:       30 * time.Second,
			ReadHeaderTimeout: 3 * time.Second,
			Handler:           debugAPIService,
			ErrorLog:          log.New(b.errorLogWriter, "debugApi", 0),
		}

		go func() {
			if o.EnableApiTLS {
				logger.Infof("debug api address: https://%s", debugAPIListener.Addr())
				err = debugAPIServer.ServeTLS(debugAPIListener, o.TlsCrtFile, o.TlsKeyFile)
				if err != nil {
					logger.Errorf("debug api server enable https: %v", err)
				}
			}
			logger.Infof("debug api address: http://%s", debugAPIListener.Addr())
			err = debugAPIServer.Serve(debugAPIListener)
			if err != nil && err != http.ErrServerClosed {
				logger.Debugf("debug api server: %v", err)
				logger.Error("unable to serve debug api")
			}
		}()

		b.debugAPIServer = debugAPIServer
	}

	stateStore, err := InitStateStore(logger, o.DataDir)
	if err != nil {
		return nil, err
	}
	b.stateStoreCloser = stateStore

	err = CheckOverlayWithStore(bosonAddress, stateStore)
	if err != nil {
		return nil, err
	}

	addressBook := addressbook.New(stateStore)
	lightNodes := lightnode.NewContainer(bosonAddress)
	bootNodes := bootnode.NewContainer(bosonAddress)
	p2ps, err := libp2p.New(p2pCtx, signer, networkID, bosonAddress, addr, addressBook, stateStore, lightNodes, bootNodes, logger, tracer, libp2p.Options{
		PrivateKey:     libp2pPrivateKey,
		NATAddr:        o.NATAddr,
		EnableWS:       o.EnableWS,
		EnableQUIC:     o.EnableQUIC,
		WelcomeMessage: o.WelcomeMessage,
		NodeMode:       nodeMode,
		LightNodeLimit: o.LightNodeMaxPeers,
		KadBinMaxPeers: o.KadBinMaxPeers,
	})

	if err != nil {
		return nil, fmt.Errorf("p2p service: %w", err)
	}

	oracleChain, settlement, apiInterface, commonChain, err := InitChain(
		p2pCtx,
		logger,
		o.ChainEndpoint,
		o.OracleContractAddress,
		stateStore,
		signer,
		o.TrafficEnable,
		o.TrafficContractAddr,
		p2ps,
		subPub)
	if err != nil {
		return nil, err
	}
	b.p2pService = p2ps

	if !o.Standalone {
		if natManager := p2ps.NATManager(); natManager != nil {
			// wait for nat manager to init
			logger.Debug("initializing NAT manager")
			select {
			case <-natManager.Ready():
				// this is magic sleep to give NAT time to sync the mappings
				// this is a hack, kind of alchemy and should be improved
				time.Sleep(3 * time.Second)
				logger.Debug("NAT manager initialized")
			case <-time.After(10 * time.Second):
				logger.Warning("NAT manager init timeout")
			}
		}
	}

	// Construct protocols.
	pingPong := pingpong.New(p2ps, logger, tracer)

	if err = p2ps.AddProtocol(pingPong.Protocol()); err != nil {
		return nil, fmt.Errorf("pingpong service: %w", err)
	}

	var bootnodes []ma.Multiaddr
	if o.Standalone {
		logger.Info("Starting node in standalone mode, no p2p connections will be made or accepted")
	} else {
		for _, a := range o.Bootnodes {
			addr, err := ma.NewMultiaddr(a)
			if err != nil {
				logger.Debugf("multiaddress fail %s: %v", a, err)
				logger.Warningf("invalid bootnode address %s", a)
				continue
			}

			bootnodes = append(bootnodes, addr)
		}
	}

	paymentThreshold := new(big.Int).SetUint64(256 * 4 * 4)
	paymentTolerance := new(big.Int).Mul(paymentThreshold, new(big.Int).SetUint64(2*32))

	acc := accounting.NewAccounting(
		paymentTolerance,
		paymentThreshold,
		logger,
		stateStore,
		settlement,
	)
	settlement.SetNotifyPaymentFunc(acc.AsyncNotifyPayment)

	metricsDB, err := shed.NewDBWrap(stateStore.DB())
	if err != nil {
		return nil, fmt.Errorf("unable to create metrics storage for kademlia: %w", err)
	}

	hiveObj := hive2.New(p2ps, addressBook, networkID, logger)
	if err = p2ps.AddProtocol(hiveObj.Protocol()); err != nil {
		return nil, fmt.Errorf("hive service: %w", err)
	}

	kad, err := kademlia.New(bosonAddress, addressBook, hiveObj, p2ps, pingPong, lightNodes, bootNodes, metricsDB, logger, subPub, kademlia.Options{
		Bootnodes:   bootnodes,
		NodeMode:    nodeMode,
		BinMaxPeers: o.KadBinMaxPeers,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create kademlia: %w", err)
	}
	b.topologyCloser = kad
	hiveObj.SetAddPeersHandler(kad.AddPeers)
	hiveObj.SetConfig(hive2.Config{Kad: kad, Base: bosonAddress, AllowPrivateCIDRs: o.AllowPrivateCIDRs}) // hive2

	p2ps.SetPickyNotifier(kad)
	addrs, err := p2ps.Addresses()
	if err != nil {
		return nil, fmt.Errorf("get server addresses: %w", err)
	}

	for _, addr := range addrs {
		logger.Debugf("p2p address: %s", addr)
	}

	route := routetab.New(bosonAddress, p2pCtx, p2ps, p2ps, addressBook, networkID, lightNodes, kad, stateStore, logger, routetab.Options{Alpha: o.RouteAlpha})
	if err = p2ps.AddProtocol(route.Protocol()); err != nil {
		return nil, fmt.Errorf("routetab service: %w", err)
	}

	p2ps.ApplyRoute(bosonAddress, route, nodeMode)

	var path string

	if o.DBPath != "" {
		path = o.DBPath
	} else if o.DataDir != "" {
		path = filepath.Join(o.DataDir, "localstore")
	}
	lo := &localstore.Options{
		Capacity: o.CacheCapacity,
		Driver:   o.DBDriver,
		FullNode: nodeMode.IsFull(),
	}
	storer, err := localstore.New(path, bosonAddress.Bytes(), stateStore, lo, logger)
	if err != nil {
		return nil, fmt.Errorf("localstore: %w", err)
	}
	err = storer.Init()
	if err != nil {
		return nil, err
	}
	b.localstoreCloser = storer

	retrieve := retrieval.New(bosonAddress, p2ps, route, storer, o.Relay, nodeMode.IsFull(), logger, tracer, acc, subPub)
	if err = p2ps.AddProtocol(retrieve.Protocol()); err != nil {
		return nil, fmt.Errorf("retrieval service: %w", err)
	}

	ns := netstore.New(storer, retrieve, logger, bosonAddress)

	pinningService := pinning.NewService(storer, stateStore, traversal.New(storer))

	multiResolver := multiresolver.NewMultiResolver(
		multiresolver.WithDefaultEndpoint(o.ChainEndpoint),
		multiresolver.WithConnectionConfigs(o.ResolverConnectionCfgs),
		multiresolver.WithLogger(o.Logger),
	)
	b.resolverCloser = multiResolver

	fileInfo := fileinfo.New(bosonAddress, storer, logger, multiResolver)
	chunkInfo := chunkinfo.New(bosonAddress, p2ps, logger, storer, route, oracleChain, fileInfo, subPub)

	if err = p2ps.AddProtocol(chunkInfo.Protocol()); err != nil {
		return nil, fmt.Errorf("chunkInfo service: %w", err)
	}
	ns.SetChunkInfo(chunkInfo)
	retrieve.Config(chunkInfo)

	group := multicast.NewService(bosonAddress, nodeMode, p2ps, p2ps, kad, route, logger, subPub, multicast.Option{Dev: o.IsDev})
	group.Start()
	b.groupCloser = group
	err = p2ps.AddProtocol(group.Protocol())
	if err != nil {
		return nil, err
	}
	if len(o.Groups) > 0 {
		err = group.AddGroup(o.Groups)
		if err != nil {
			return nil, err
		}
	}

	relay := netrelay.New(p2ps, stateStore, logger, o.Groups, route, group)
	err = p2ps.AddProtocol(relay.Protocol())
	if err != nil {
		return nil, err
	}
	if o.ProxyGroup != "" {
		err = relay.SetProxyGroup(o.ProxyGroup)
		if err != nil {
			return nil, err
		}
	}
	if o.ProxyEnable {
		if o.ProxyGroup == "" {
			return nil, errors.New("please set proxy-group or disable proxy")
		}
		b.proxyTCPServer = relay.StartProxyTCP(o.ProxyAddr, o.ProxyNATAddr)
		b.proxyUDPServer = relay.StartProxyUDP(o.ProxyAddr, o.ProxyNATAddr)
	}
	if o.TunGroup != "" {
		err = relay.SetTunGroup(o.TunGroup)
		if err != nil {
			return nil, err
		}
	}
	if o.TunEnable {
		_, err = bytesize.Parse(o.TunRateEveryday)
		if err != nil {
			return nil, fmt.Errorf("tun-rate-everyday parse failed: %s", err)
		}
		relay.CreateTun(netrelay.TunConfig{
			ServerIP:     o.TunServiceIPv4,
			ServerIPv6:   o.TunServiceIPv6,
			CIDR:         o.TunCidr4,
			CIDRv6:       o.TunCidr6,
			MTU:          o.TunMTU,
			SpeedMax:     o.TunSpeedMax,
			SpeedMin:     o.TunSpeedMin,
			RateEveryday: o.TunRateEveryday,
			RateEnable:   o.TunRateEnable,
		})
	}
	if o.VpnEnable {
		vpnService := relay.NewVpnService()
		vpnServer := &http.Server{
			IdleTimeout:       30 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			Handler:           vpnService,
			ErrorLog:          log.New(b.errorLogWriter, "vpn", 0),
		}
		vpnListener, err := net.Listen("tcp", o.VpnAddr)
		if err != nil {
			return nil, fmt.Errorf("vpn listener: %w", err)
		}
		go func() {
			if o.EnableApiTLS {
				logger.Infof("vpn address: wss://%s", vpnListener.Addr())
				err = vpnServer.ServeTLS(vpnListener, o.TlsCrtFile, o.TlsKeyFile)
				if err != nil {
					logger.Errorf("vpn server enable wss: %v", err)
				}
			}
			logger.Infof("vpn address: ws://%s", vpnListener.Addr())
			err = vpnServer.Serve(vpnListener)
			if err != nil && err != http.ErrServerClosed {
				logger.Debugf("vpn server: %v", err)
				logger.Error("unable to serve vpn")
			}
		}()

		b.vpnServer = vpnServer
	}

	var apiService api.Service
	if o.APIAddr != "" {
		// API server
		apiService = api.New(ns, multiResolver, bosonAddress, chunkInfo, fileInfo, traversal.New(ns), pinningService,
			authenticator, logger, kad, tracer, apiInterface, commonChain, oracleChain, relay, group, route,
			api.Options{
				CORSAllowedOrigins: o.CORSAllowedOrigins,
				GatewayMode:        o.GatewayMode,
				WsPingPeriod:       60 * time.Second,
				BufferSizeMul:      o.ApiBufferSizeMul,
				Restricted:         o.Restricted,
				DebugApiAddr:       o.DebugAPIAddr,
				RPCWSAddr:          o.WSAddr,
			})
		err = b.StartAPI(o, apiService)
		if err != nil {
			return nil, err
		}
	}

	if debugAPIService != nil {
		// register metrics from components
		debugAPIService.MustRegisterMetrics(p2ps.Metrics()...)
		debugAPIService.MustRegisterMetrics(storer.Metrics()...)
		debugAPIService.MustRegisterMetrics(kad.Metrics()...)
		debugAPIService.MustRegisterMetrics(hiveObj.Metrics()...)
		debugAPIService.MustRegisterMetrics(chunkInfo.Metrics()...)
		debugAPIService.MustRegisterMetrics(route.Metrics()...)
		debugAPIService.MustRegisterMetrics(retrieve.Metrics()...)
		debugAPIService.MustRegisterMetrics(relay.Metrics()...)

		if apiService != nil {
			debugAPIService.MustRegisterMetrics(apiService.Metrics()...)
		}

		// inject dependencies and configure full debug api http path routes
		debugAPIService.Configure(p2ps, pingPong, group, kad, lightNodes, bootNodes, storer, route, chunkInfo, fileInfo, retrieve, addressBook, relay)
		if apiInterface != nil {
			debugAPIService.MustRegisterTraffic(apiInterface)
		}
	}

	if err = kad.Start(p2pCtx); err != nil {
		return nil, err
	}
	if !o.IsDev {
		hiveObj.Start()
	}

	stack, err := NewRPC(logger, Config{
		EnableApiTLS: o.EnableApiTLS,
		TlsCrtFile:   o.TlsCrtFile,
		TlsKeyFile:   o.TlsKeyFile,
		DebugAPIAddr: o.DebugAPIAddr,
		APIAddr:      o.APIAddr,
		//
		DataDir: o.DataDir,
		// HTTPAddr:    o.HTTPAddr,
		// HTTPCors:    o.CORSAllowedOrigins,
		// HTTPModules: []string{"debug", "api"},
		WSAddr:    o.WSAddr,
		WSOrigins: o.CORSAllowedOrigins,
		WSModules: []string{"group", "p2p", "chunkInfo", "traffic", "retrieval", "oracle"},
	})
	if err != nil {
		return nil, err
	}
	stack.RegisterAPIs([]rpc.API{
		group.API(),        // group
		kad.API(),          // p2p
		chunkInfo.API(),    // chunkInfo
		apiInterface.API(), // traffic
		retrieve.API(),     // retrieval
		oracleChain.API(),  // oracle
	})
	if err = stack.Start(); err != nil {
		return nil, err
	}

	b.rpcServer = stack
	go stack.Wait()

	if err = p2ps.Ready(); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *Favor) Shutdown(ctx context.Context) error {
	errs := new(multiError)

	if b.apiCloser != nil {
		if err := b.apiCloser.Close(); err != nil {
			errs.add(fmt.Errorf("api: %w", err))
		}
	}

	var eg errgroup.Group
	if b.apiServer != nil {
		eg.Go(func() error {
			if err := b.apiServer.Shutdown(ctx); err != nil {
				return fmt.Errorf("api server: %w", err)
			}
			return nil
		})
	}
	if b.debugAPIServer != nil {
		eg.Go(func() error {
			if err := b.debugAPIServer.Shutdown(ctx); err != nil {
				return fmt.Errorf("debug api server: %w", err)
			}
			logging.Infof("debug api shutting down")
			return nil
		})
	}

	if b.rpcServer != nil {
		eg.Go(func() error {
			if err := b.rpcServer.Close(); err != nil {
				return fmt.Errorf("rpc server: %w", err)
			}
			logging.Infof("rpc shutting down")
			return nil
		})
	}

	if b.vpnServer != nil {
		eg.Go(func() error {
			if err := b.vpnServer.Shutdown(ctx); err != nil {
				return fmt.Errorf("vpn server: %w", err)
			}
			logging.Infof("vpn shutting down")
			return nil
		})
	}
	if b.proxyTCPServer != nil {
		eg.Go(func() error {
			if err := b.proxyTCPServer.Close(); err != nil {
				return fmt.Errorf("proxy tcp server: %w", err)
			}
			logging.Infof("proxy tcp shutting down")
			return nil
		})
	}
	if b.proxyUDPServer != nil {
		eg.Go(func() error {
			if err := b.proxyUDPServer.Close(); err != nil {
				return fmt.Errorf("proxy udp server: %w", err)
			}
			logging.Infof("proxy udp shutting down")
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		errs.add(err)
	}

	b.p2pCancel()
	if err := b.p2pService.Close(); err != nil {
		errs.add(fmt.Errorf("p2p server: %w", err))
	}

	if c := b.ethClientCloser; c != nil {
		c()
	}

	if err := b.tracerCloser.Close(); err != nil {
		errs.add(fmt.Errorf("tracer: %w", err))
	}

	if err := b.stateStoreCloser.Close(); err != nil {
		errs.add(fmt.Errorf("statestore: %w", err))
	}

	if err := b.localstoreCloser.Close(); err != nil {
		errs.add(fmt.Errorf("localstore: %w", err))
	}

	if b.groupCloser != nil {
		if err := b.groupCloser.Close(); err != nil {
			errs.add(fmt.Errorf("multicast: %w", err))
		}
	}

	if err := b.topologyCloser.Close(); err != nil {
		errs.add(fmt.Errorf("topology driver: %w", err))
	}

	if err := b.errorLogWriter.Close(); err != nil {
		errs.add(fmt.Errorf("error log writer: %w", err))
	}

	// Shutdown the resolver service only if it has been initialized.
	if b.resolverCloser != nil {
		if err := b.resolverCloser.Close(); err != nil {
			errs.add(fmt.Errorf("resolver service: %w", err))
		}
	}

	if errs.hasErrors() {
		return errs
	}

	return nil
}

type multiError struct {
	errors []error
}

func (e *multiError) Error() string {
	if len(e.errors) == 0 {
		return ""
	}
	s := e.errors[0].Error()
	for _, err := range e.errors[1:] {
		s += "; " + err.Error()
	}
	return s
}

func (e *multiError) add(err error) {
	e.errors = append(e.errors, err)
}

func (e *multiError) hasErrors() bool {
	return len(e.errors) > 0
}

// StartAPI 启动 HTTP API 服务
func (b *Favor) StartAPI(o Options, apiService api.Service) error {
	if o.APIAddr == "" {
		return errors.New("APIAddr is empty")
	}
	apiListener, err := net.Listen("tcp", o.APIAddr)
	if err != nil {
		return fmt.Errorf("api listener: %w", err)
	}
	apiServer := &http.Server{
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		Handler:           apiService,
		ErrorLog:          log.New(b.errorLogWriter, "api", 0),
	}
	b.apiServer = apiServer
	b.apiCloser = apiService
	go func() {
		if o.EnableApiTLS {
			b.apiServer.ServeTLS(apiListener, o.TlsCrtFile, o.TlsKeyFile)
		} else {
			b.apiServer.Serve(apiListener)
		}
	}()
	return nil
}

// StopAPI 优雅关闭 HTTP API 服务
func (b *Favor) StopAPI(ctx context.Context) error {
	var err1, err2 error
	if b.apiCloser != nil {
		err1 = b.apiCloser.Close()
		b.apiCloser = nil
	}
	if b.apiServer != nil {
		err2 = b.apiServer.Shutdown(ctx)
		b.apiServer = nil
	}
	return multiErrorJoin(err1, err2)
}

// RestartAPI 先关闭再启动
func (b *Favor) RestartAPI(o Options, apiService api.Service) error {
	_ = b.StopAPI(context.Background())
	return b.StartAPI(o, apiService)
}

// multiErrorJoin 合并两个 error
func multiErrorJoin(err1, err2 error) error {
	if err1 == nil && err2 == nil {
		return nil
	}
	if err1 != nil && err2 != nil {
		return fmt.Errorf("%v; %v", err1, err2)
	}
	if err1 != nil {
		return err1
	}
	return err2
}

// CheckAndReconnectPeers 检查并重连当前已连接P2P节点：对每个 peer 主动 ping，ping 不通则重连
func (b *Favor) CheckAndReconnectPeers() (checked int, reconnected int, err error) {
	kad, ok := b.topologyCloser.(*kademlia.Kad)
	if !ok {
		return 0, 0, errors.New("kad not available")
	}
	p2ps, ok := b.p2pService.(*libp2p.Service)
	if !ok {
		return 0, 0, errors.New("p2pService not available")
	}
	pingpongService := p2ps.PingPong()
	if pingpongService == nil {
		return 0, 0, errors.New("pingpong service not available")
	}
	peers := p2ps.Peers()
	for _, peer := range peers {
		checked++
		ab := kad.AddressBook()
		bzzAddr, err2 := ab.Get(peer.Address)
		if err2 != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := pingpongService(ctx, bzzAddr.Underlay)
		cancel()
		if err != nil {
			// ping 不通，尝试重连
			ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel2()
			_, err2 = p2ps.Connect(ctx2, bzzAddr.Underlay)
			if err2 == nil {
				reconnected++
			}
		}
	}
	// 如果当前没有已连接的 peer，则遍历已知节点并尝试连接
	if checked == 0 {
		err = kad.EachKnownPeer(func(addr boson.Address, _ uint8) (stop, jumpToNext bool, err error) {
			ab := kad.AddressBook()
			bzzAddr, err := ab.Get(addr)
			if err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, err = p2ps.Connect(ctx, bzzAddr.Underlay)
				checked++
				if err == nil {
					reconnected++
				}
			}
			return false, false, nil
		})
	}
	return checked, reconnected, err
}

// CheckAndRestartHTTP 检查并重启HTTP服务（增强：端口+HTTP活性检测）
func (b *Favor) CheckAndRestartHTTP(apiAddr string) (healthy bool, restarted bool, err error) {
	// 1. 端口可达性检测
	conn, err := net.DialTimeout("tcp", apiAddr, 2*time.Second)
	if err != nil {
		// 端口不可达，需重启
		return b.restartHTTPServer()
	}
	conn.Close()
	// 2. HTTP 层活性检测
	url := "http://" + apiAddr + "/v1/ping"
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return b.restartHTTPServer()
	}
	resp.Body.Close()
	return true, false, nil
}

// restartHTTPServer 关闭并重启 HTTP 服务
func (b *Favor) restartHTTPServer() (healthy bool, restarted bool, err error) {
	if b.apiServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = b.apiServer.Shutdown(ctx)
	}
	if b.apiCloser != nil {
		_ = b.apiCloser.Close()
	}
	// 这里建议你将 FavorX API 服务的启动逻辑单独封装为 StartAPI 方法，然后在这里调用
	return false, true, errors.New("HTTP服务已关闭，请手动重启或补充自动重启逻辑")
}

// OnResume: 用于移动端前台恢复时的自愈入口
func (b *Favor) OnResume(apiAddr string) (peerChecked, peerReconnected int, httpHealthy, httpRestarted bool, err error) {
	peerChecked, peerReconnected, err1 := b.CheckAndReconnectPeers()
	httpHealthy, httpRestarted, err2 := b.CheckAndRestartHTTP(apiAddr)
	if err1 != nil && err2 != nil {
		err = fmt.Errorf("peer: %v; http: %v", err1, err2)
	} else if err1 != nil {
		err = err1
	} else if err2 != nil {
		err = err2
	}
	return
}

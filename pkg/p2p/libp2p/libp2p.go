package libp2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	fx "github.com/FavorLabs/favorX"
	"github.com/FavorLabs/favorX/pkg/address"
	"github.com/FavorLabs/favorX/pkg/addressbook"
	"github.com/FavorLabs/favorX/pkg/boson"
	beecrypto "github.com/FavorLabs/favorX/pkg/crypto"
	"github.com/FavorLabs/favorX/pkg/logging"
	"github.com/FavorLabs/favorX/pkg/p2p"
	"github.com/FavorLabs/favorX/pkg/p2p/libp2p/internal/blocklist"
	"github.com/FavorLabs/favorX/pkg/p2p/libp2p/internal/breaker"
	"github.com/FavorLabs/favorX/pkg/p2p/libp2p/internal/handshake"
	"github.com/FavorLabs/favorX/pkg/p2p/libp2p/internal/reacher"
	"github.com/FavorLabs/favorX/pkg/p2p/protobuf"
	"github.com/FavorLabs/favorX/pkg/routetab"
	"github.com/FavorLabs/favorX/pkg/routetab/pb"
	"github.com/FavorLabs/favorX/pkg/storage"
	"github.com/FavorLabs/favorX/pkg/topology/bootnode"
	"github.com/FavorLabs/favorX/pkg/topology/lightnode"
	"github.com/FavorLabs/favorX/pkg/tracing"
	"github.com/gogf/gf/v2/os/gtimer"
	"github.com/hashicorp/go-multierror"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	basichost "github.com/libp2p/go-libp2p/p2p/host/basic"
	"github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/net/nat"
	lp2pswarm "github.com/libp2p/go-libp2p/p2p/net/swarm"
	libp2pping "github.com/libp2p/go-libp2p/p2p/protocol/ping"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ws "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multistream"
	"go.uber.org/atomic"
)

var (
	_ p2p.Service      = (*Service)(nil)
	_ p2p.DebugService = (*Service)(nil)
)

const (
	peerUserAgentTimeout = time.Second
)

type Service struct {
	ctx               context.Context
	host              host.Host
	natManager        basichost.NATManager
	natAddrResolver   *staticAddressResolver
	pingDialer        host.Host
	libp2pPeerstore   peerstore.Peerstore
	metrics           metrics
	networkID         uint64
	handshakeService  *handshake.Service
	addressbook       addressbook.Putter
	peers             *peerRegistry
	connectionBreaker breaker.Interface
	blocklist         *blocklist.Blocklist
	protocols         []p2p.ProtocolSpec
	notifier          p2p.PickyNotifier
	logger            logging.Logger
	tracer            *tracing.Tracer
	ready             chan struct{}
	halt              chan struct{}
	lightNodes        lightnode.LightNodes
	bootNodes         bootnode.BootNodes
	lightNodeLimit    int
	protocolsmu       sync.RWMutex
	route             routetab.RelayStream
	self              boson.Address
	nodeMode          address.Model
	reacher           p2p.Reacher
	networkStatus     atomic.Int32
}

type Options struct {
	PrivateKey     crypto.PrivKey
	NATAddr        string
	EnableWS       bool
	EnableQUIC     bool
	NodeMode       address.Model
	LightNodeLimit int
	KadBinMaxPeers int
	WelcomeMessage string
	Transaction    []byte
	hostFactory    func(...libp2p.Option) (host.Host, error)
}

func New(ctx context.Context, signer beecrypto.Signer, networkID uint64, overlay boson.Address, addr string, ab addressbook.Putter, storer storage.StateStorer, lightNodes *lightnode.Container, bootNodes *bootnode.Container, logger logging.Logger, tracer *tracing.Tracer, o Options) (*Service, error) {
	hostObj, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("address: %w", err)
	}

	ip4Addr := "0.0.0.0"
	ip6Addr := "::"

	if hostObj != "" {
		ip := net.ParseIP(hostObj)
		if ip4 := ip.To4(); ip4 != nil {
			ip4Addr = ip4.String()
			ip6Addr = ""
		} else if ip6 := ip.To16(); ip6 != nil {
			ip6Addr = ip6.String()
			ip4Addr = ""
		}
	}

	var listenAddrs []string
	if ip4Addr != "" {
		listenAddrs = append(listenAddrs, fmt.Sprintf("/ip4/%s/tcp/%s", ip4Addr, port))
		if o.EnableWS {
			listenAddrs = append(listenAddrs, fmt.Sprintf("/ip4/%s/tcp/%s/ws", ip4Addr, port))
		}
		if o.EnableQUIC {
			listenAddrs = append(listenAddrs, fmt.Sprintf("/ip4/%s/udp/%s/quic", ip4Addr, port))
		}
	}

	if ip6Addr != "" {
		listenAddrs = append(listenAddrs, fmt.Sprintf("/ip6/%s/tcp/%s", ip6Addr, port))
		if o.EnableWS {
			listenAddrs = append(listenAddrs, fmt.Sprintf("/ip6/%s/tcp/%s/ws", ip6Addr, port))
		}
		if o.EnableQUIC {
			listenAddrs = append(listenAddrs, fmt.Sprintf("/ip6/%s/udp/%s/quic", ip6Addr, port))
		}
	}

	security := libp2p.DefaultSecurity
	libp2pPeerstore, err := pstoremem.NewPeerstore()
	if err != nil {
		return nil, err
	}
	var natManager basichost.NATManager

	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(listenAddrs...),
		security,
		// Use dedicated peerstore instead the global DefaultPeerstore
		libp2p.Peerstore(libp2pPeerstore),
		libp2p.UserAgent(userAgent()),
	}

	enableNAT := o.NodeMode.IsFull()

	if enableNAT && o.NATAddr == "" {
		opts = append(opts,
			libp2p.NATManager(func(n network.Network) basichost.NATManager {
				natManager = basichost.NewNATManager(n)
				return natManager
			}),
		)
	}

	if o.PrivateKey != nil {
		opts = append(opts,
			libp2p.Identity(o.PrivateKey),
		)
	}

	limit := newLimier(o)
	manager, err := rcmgr.NewResourceManager(limit)
	if err != nil {
		return nil, err
	}

	low := limit.GetSystemLimits().GetConnTotalLimit()
	high := low + 200

	connManager, err := connmgr.NewConnManager(low, high)
	if err != nil {
		return nil, err
	}

	transports := []libp2p.Option{
		libp2p.Transport(tcp.NewTCPTransport, tcp.DisableReuseport()),
		libp2p.ResourceManager(manager),
		libp2p.DisableRelay(),
		libp2p.ConnectionManager(connManager),
	}

	if o.EnableWS {
		transports = append(transports, libp2p.Transport(ws.New))
	}

	if o.EnableQUIC {
		transports = append(transports, libp2p.Transport(libp2pquic.NewTransport))
	}

	opts = append(opts, transports...)

	if o.hostFactory == nil {
		// Use the default libp2p host creation
		o.hostFactory = libp2p.New
	}

	h, err := o.hostFactory(opts...)
	if err != nil {
		return nil, err
	}

	var advertisableAddresser handshake.AdvertisableAddressResolver
	var natAddrResolver *staticAddressResolver
	if o.NATAddr == "" {
		advertisableAddresser = &UpnpAddressResolver{
			host: h,
		}
	} else {
		natAddrResolver, err = newStaticAddressResolver(o.NATAddr, net.LookupIP)
		if err != nil {
			return nil, fmt.Errorf("static nat: %w", err)
		}
		advertisableAddresser = natAddrResolver
	}

	if o.LightNodeLimit <= 0 {
		o.LightNodeLimit = lightnode.DefaultLightNodeLimit
	}

	handshakeService, err := handshake.New(signer, advertisableAddresser, overlay, networkID, o.NodeMode, o.WelcomeMessage, h.ID(), logger, lightNodes, o.LightNodeLimit)
	if err != nil {
		return nil, fmt.Errorf("handshake service: %w", err)
	}

	// Create a new dialer for libp2p ping protocol. This ensures that the protocol
	// uses a different set of keys to do ping. It prevents inconsistencies in peerstore as
	// the addresses used are not dialable and hence should be cleaned up. We should create
	// this host with the same transports and security options to be able to dial to other
	// peers.
	pingDialer, err := o.hostFactory(append(transports, security, libp2p.NoListenAddrs)...)
	if err != nil {
		return nil, err
	}

	peerRegistry := newPeerRegistry()
	s := &Service{
		ctx:               ctx,
		host:              h,
		natManager:        natManager,
		natAddrResolver:   natAddrResolver,
		pingDialer:        pingDialer,
		handshakeService:  handshakeService,
		libp2pPeerstore:   libp2pPeerstore,
		metrics:           newMetrics(),
		networkID:         networkID,
		peers:             peerRegistry,
		addressbook:       ab,
		blocklist:         blocklist.NewBlocklist(storer),
		logger:            logger,
		tracer:            tracer,
		connectionBreaker: breaker.NewBreaker(breaker.Options{}), // use default options
		ready:             make(chan struct{}),
		halt:              make(chan struct{}),
		bootNodes:         bootNodes,
		lightNodes:        lightNodes,
		lightNodeLimit:    o.LightNodeLimit,
	}

	peerRegistry.setDisconnecter(s)

	_ = h.Network().ResourceManager().ViewSystem(func(scope network.ResourceScope) error {
		gtimer.AddSingleton(ctx, time.Second, func(ctx context.Context) {
			s.metrics.NumConnsOutbound.Set(float64(scope.Stat().NumConnsOutbound))
			s.metrics.NumConnsInbound.Set(float64(scope.Stat().NumConnsInbound))
			s.metrics.NumStreamsInbound.Set(float64(scope.Stat().NumStreamsInbound))
			s.metrics.NumStreamsOutbound.Set(float64(scope.Stat().NumStreamsOutbound))
			s.metrics.NumFD.Set(float64(scope.Stat().NumFD))
			s.metrics.Memory.Set(float64(scope.Stat().Memory))
			// s.logger.Tracef("libp2p view system %v", scope.Stat())
		})
		return nil
	})

	// Construct protocols.
	id := protocol.ID(p2p.NewProtocolStreamName(handshake.ProtocolName, handshake.ProtocolVersion, handshake.StreamName))
	matcher, err := s.protocolSemverMatcher(id)
	if err != nil {
		return nil, fmt.Errorf("protocol version match %s: %w", id, err)
	}

	s.host.SetStreamHandlerMatch(id, matcher, s.handleIncoming)

	connMetricNotify := newConnMetricNotify(s.metrics)
	h.Network().Notify(peerRegistry) // update peer registry on network events
	h.Network().Notify(connMetricNotify)
	return s, nil
}

func (s *Service) ApplyRoute(self boson.Address, rt routetab.RelayStream, mode address.Model) {
	s.route = rt
	s.self = self
	s.nodeMode = mode
}

func (s *Service) handleIncoming(stream network.Stream) {
	select {
	case <-s.ready:
	case <-s.halt:
		go func() { _ = stream.Reset() }()
		return
	case <-s.ctx.Done():
		go func() { _ = stream.Reset() }()
		return
	}

	peerID := stream.Conn().RemotePeer()
	handshakeStream := NewStream(stream)
	i, err := s.handshakeService.Handle(s.ctx, handshakeStream, stream.Conn().RemoteMultiaddr(), peerID)
	if err != nil {
		s.logger.Debugf("stream handler: handshake: handle %s: %v", peerID, err)
		s.logger.Errorf("stream handler: handshake: unable to handshake with peer id %v", peerID)
		_ = handshakeStream.Reset()
		_ = s.host.Network().ClosePeer(peerID)
		return
	}

	overlay := i.Address.Overlay

	blocked, err := s.blocklist.Exists(overlay)
	if err != nil {
		s.logger.Debugf("stream handler: blocklisting: exists %s: %v", overlay, err)
		s.logger.Errorf("stream handler: internal error while connecting with peer %s", overlay)
		_ = handshakeStream.Reset()
		_ = s.host.Network().ClosePeer(peerID)
		return
	}

	if blocked {
		s.logger.Errorf("stream handler: blocked connection from blocklisted peer %s", overlay)
		_ = handshakeStream.Reset()
		_ = s.host.Network().ClosePeer(peerID)
		return
	}

	if exists := s.peers.addIfNotExists(stream.Conn(), overlay, i.NodeMode); exists {
		s.logger.Debugf("stream handler: peer %s already exists", overlay)
		if err = handshakeStream.FullClose(); err != nil {
			s.logger.Debugf("stream handler: could not close stream %s: %v", overlay, err)
			s.logger.Errorf("stream handler: unable to handshake with peer %v", overlay)
			_ = s.Disconnect(overlay, "unable to close handshake stream")
		}
		return
	}

	if err = handshakeStream.FullClose(); err != nil {
		s.logger.Debugf("stream handler: could not close stream %s: %v", overlay, err)
		s.logger.Errorf("stream handler: unable to handshake with peer %v", overlay)
		_ = s.Disconnect(overlay, "could not fully close stream on handshake")
		return
	}

	if i.NodeMode.IsFull() {
		err = s.addressbook.Put(i.Address.Overlay, *i.Address)
		if err != nil {
			s.logger.Debugf("stream handler: addressbook put error %s: %v", peerID, err)
			s.logger.Errorf("stream handler: unable to persist peer %v", peerID)
			_ = s.Disconnect(i.Address.Overlay, "unable to persist peer in addressbook")
			return
		}
	}

	peer := p2p.Peer{Address: overlay, Mode: i.NodeMode}

	s.protocolsmu.RLock()
	for _, tn := range s.protocols {
		if tn.ConnectIn != nil {
			if err := tn.ConnectIn(s.ctx, peer); err != nil {
				s.logger.Debugf("stream handler: connectIn: protocol: %s, version:%s, peer: %s: %v", tn.Name, tn.Version, overlay, err)
				_ = s.Disconnect(overlay, "failed to process inbound connection notifier")
				s.protocolsmu.RUnlock()
				return
			}
		}
	}
	s.protocolsmu.RUnlock()

	if !s.peers.Exists(overlay) {
		s.logger.Warningf("stream handler: inbound peer %s does not exist, disconnecting", overlay)
		_ = s.Disconnect(overlay, "unknown inbound peer")
		return
	}

	if s.notifier != nil {
		if !i.NodeMode.IsFull() && s.lightNodes != nil {
			s.lightNodes.Connected(s.ctx, peer)
			// light node announces explicitly
			if err := s.notifier.Announce(s.ctx, peer.Address, i.NodeMode.IsFull()); err != nil {
				s.logger.Debugf("stream handler: notifier.Announce: %s: %v", peer.Address.String(), err)
			}

			if s.lightNodes.Count() > s.lightNodeLimit {
				// kick another node to fit this one in
				p, err := s.lightNodes.RandomPeer(peer.Address)
				if err != nil {
					s.logger.Debugf("stream handler: cant find a peer slot for light node: %v", err)
					_ = s.Disconnect(peer.Address, "unable to find peer slot for light node")
					return
				} else {
					s.logger.Tracef("stream handler: kicking away light node %s to make room for %s", p.String(), peer.Address.String())
					s.metrics.KickedOutPeersCount.Inc()
					_ = s.Disconnect(p, "kicking away light node to make room for peer")
					return
				}
			}
		} else {
			if i.NodeMode.IsBootNode() && s.bootNodes != nil {
				s.bootNodes.Connected(s.ctx, peer)
			} else {
				if err = s.notifier.Connected(s.ctx, peer, false); err != nil {
					s.logger.Debugf("stream handler: notifier.Connected: peer disconnected: %s: %v", i.Address.Overlay, err)
					// note: this cannot be unit tested since the node
					// waiting on handshakeStream.FullClose() on the other side
					// might actually get a stream reset when we disconnect here
					// resulting in a flaky response from the Connect method on
					// the other side.
					// that is why the Pick method has been added to the notifier
					// interface, in addition to the possibility of deciding whether
					// a peer connection is wanted prior to adding the peer to the
					// peer registry and starting the protocols.
					_ = s.Disconnect(overlay, fmt.Sprintf("unable to signal connection notifier %s", err))
					return
				}
				// when a full node connects, we gossip about it to the
				// light nodes so that they can also have a chance at building
				// a solid topology.
				_ = s.lightNodes.EachPeer(func(addr boson.Address, _ uint8) (bool, bool, error) {
					go func(addressee, peer boson.Address, fullnode bool) {
						if err := s.notifier.AnnounceTo(s.ctx, addressee, peer, fullnode); err != nil {
							s.logger.Debugf("stream handler: notifier.Announce to light node %s %s: %v", addressee.String(), peer.String(), err)
						}
					}(addr, peer.Address, i.NodeMode.IsFull())
					return false, false, nil
				})
			}
		}
		s.notifier.NotifyPeerState(p2p.PeerInfo{
			Overlay: peer.Address,
			Mode:    peer.Mode.Bv.Bytes(),
			State:   p2p.PeerStateConnectIn,
		})
	}

	s.metrics.HandledStreamCount.Inc()

	if s.reacher != nil {
		s.reacher.Connected(overlay, i.Address.Underlay)
	}

	peerUserAgent := appendSpace(s.peerUserAgent(s.ctx, peerID))

	s.logger.Debugf("stream handler: successfully connected to peer %s%s%s (inbound)", i.Address.ShortString(), i.LightString(), peerUserAgent)
	s.logger.Infof("stream handler: successfully connected to peer %s%s%s (inbound)", i.Address.Overlay, i.LightString(), peerUserAgent)
}

func (s *Service) reachabilityWorker() error {
	sub, err := s.host.EventBus().Subscribe([]interface{}{new(event.EvtLocalReachabilityChanged)})
	if err != nil {
		return fmt.Errorf("failed subscribing to reachability event %w", err)
	}

	go func() {
		defer sub.Close()
		for {
			select {
			case <-s.ctx.Done():
				return
			case e := <-sub.Out():
				if r, ok := e.(event.EvtLocalReachabilityChanged); ok {
					select {
					case <-s.ready:
					case <-s.halt:
						return
					}
					s.logger.Debugf("reachability changed to %s", r.Reachability.String())
					s.notifier.UpdateReachability(p2p.ReachabilityStatus(r.Reachability))
				}
			}
		}
	}()
	return nil
}

func (s *Service) SetPickyNotifier(n p2p.PickyNotifier) {
	s.handshakeService.SetPicker(n)
	s.reacher = reacher.New(s, n, nil)
	s.notifier = n
}

func (s *Service) AddProtocol(p p2p.ProtocolSpec) (err error) {
	for _, ss := range p.StreamSpecs {
		ss := ss
		id := protocol.ID(p2p.NewProtocolStreamName(p.Name, p.Version, ss.Name))
		matcher, err := s.protocolSemverMatcher(id)
		if err != nil {
			return fmt.Errorf("protocol version match %s: %w", id, err)
		}

		s.host.SetStreamHandlerMatch(id, matcher, func(streamlibp2p network.Stream) {
			start := time.Now()
			peerID := streamlibp2p.Conn().RemotePeer()
			overlay, found := s.peers.overlay(peerID)
			if !found {
				_ = streamlibp2p.Reset()
				s.logger.Debugf("overlay address for peer %q not found", peerID)
				return
			}
			md, found := s.peers.mode(peerID)
			if !found {
				_ = streamlibp2p.Reset()
				s.logger.Debugf("fullnode info for peer %q not found", peerID)
				return
			}

			stream := newStream(streamlibp2p)

			// exchange headers
			if err := handleHeaders(ss.Headler, stream, overlay); err != nil {
				s.logger.Debugf("handle protocol %s/%s: stream %s: peer %s: handle headers: %v", p.Name, p.Version, ss.Name, overlay, err)
				_ = stream.Reset()
				return
			}
			s.metrics.HeadersExchangeDuration.Observe(time.Since(start).Seconds())

			ctx, cancel := context.WithCancel(s.ctx)

			s.peers.addStream(peerID, streamlibp2p, cancel)
			defer s.peers.removeStream(peerID, streamlibp2p)

			// tracing: get span tracing context and add it to the context
			// silently ignore if the peer is not providing tracing
			ctx, err := s.tracer.WithContextFromHeaders(ctx, stream.Headers())
			if err != nil && !errors.Is(err, tracing.ErrContextNotFound) {
				s.logger.Debugf("handle protocol %s/%s: stream %s: peer %s: get tracing context: %v", p.Name, p.Version, ss.Name, overlay, err)
				_ = stream.Reset()
				return
			}

			logger := tracing.NewLoggerWithTraceID(ctx, s.logger)

			s.metrics.HandledStreamCount.Inc()
			if err := ss.Handler(ctx, p2p.Peer{Address: overlay, Mode: md}, stream); err != nil {
				var de *p2p.DisconnectError
				if errors.As(err, &de) {
					logger.Tracef("libp2p handler(%s): disconnecting %s", p.Name, overlay.String())
					_ = stream.Reset()
					_ = s.Disconnect(overlay, de.Error())
					logger.Tracef("handler(%s): disconnecting %s due to disconnect error", p.Name, overlay.String())
				}

				var bpe *p2p.BlockPeerError
				if errors.As(err, &bpe) {
					_ = stream.Reset()
					if err := s.Blocklist(overlay, bpe.Duration(), bpe.Error()); err != nil {
						logger.Debugf("blocklist: could not blocklist peer %s: %v", peerID, err)
						logger.Errorf("unable to blocklist peer %v", peerID)
					}
					logger.Tracef("handler(%s): blocklisted %s", p.Name, overlay.String())
				}
				// count unexpected requests
				if errors.Is(err, p2p.ErrUnexpected) {
					s.metrics.UnexpectedProtocolReqCount.Inc()
				}
				logger.Debugf("could not handle protocol %s/%s: stream %s: peer %s: error: %v", p.Name, p.Version, ss.Name, overlay, err)
				return
			}
		})
	}

	s.protocolsmu.Lock()
	s.protocols = append(s.protocols, p)
	s.protocolsmu.Unlock()
	return nil
}

func (s *Service) Addresses() (addreses []ma.Multiaddr, err error) {
	for _, addr := range s.host.Addrs() {
		a, err := buildUnderlayAddress(addr, s.host.ID())
		if err != nil {
			return nil, err
		}

		addreses = append(addreses, a)
	}
	if s.natAddrResolver != nil && len(addreses) > 0 {
		a, err := s.natAddrResolver.Resolve(addreses[0])
		if err != nil {
			return nil, err
		}
		addreses = append(addreses, a)
	}

	return addreses, nil
}

func (s *Service) NATAddresses() (addresses []net.Addr, err error) {
	maxDepth := 5
	// only check nat address nearest the node
	var natIterFn func(natInst *nat.NAT, depth int) error
	natIterFn = func(natInst *nat.NAT, depth int) error {
		if depth == maxDepth {
			return nil
		}

		// if nat is closed, instance will be nil
		if natInst == nil {
			return nil
		}

		natMaps := natInst.Mappings()

		for _, natMap := range natMaps {
			addr, err := natMap.ExternalAddr()
			if err != nil {
				if errors.Is(err, nat.ErrNoMapping) {
					continue
				}
				return err
			}

			addresses = append(addresses, addr)

			if natMap.NAT() != natInst {
				if err := natIterFn(natMap.NAT(), depth+1); err != nil {
					return err
				}
			}
		}

		return nil
	}

	if s.natManager != nil {
		if err := natIterFn(s.natManager.NAT(), 0); err != nil {
			return nil, err
		}
	} else if s.natAddrResolver != nil {
		proto := strings.Split(s.natAddrResolver.multiProto, "/")
		addr, err := net.ResolveTCPAddr("tcp", proto[len(proto)-1]+":"+s.natAddrResolver.port)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, addr)
	}

	return addresses, nil
}

func (s *Service) NATManager() basichost.NATManager {
	return s.natManager
}

func (s *Service) BlocklistedPeers() ([]p2p.BlockPeers, error) {
	return s.blocklist.Peers()
}

func (s *Service) Blocklist(overlay boson.Address, duration time.Duration, reason string) error {
	s.logger.Tracef("libp2p blocklist: peer %s for %v reason: %s", overlay.String(), duration, reason)
	if err := s.blocklist.Add(overlay, duration); err != nil {
		s.metrics.BlocklistedPeerErrCount.Inc()
		_ = s.Disconnect(overlay, "failed blocklisting peer")
		return fmt.Errorf("blocklist peer %s: %v", overlay, err)
	}
	s.metrics.BlocklistedPeerCount.Inc()

	_ = s.Disconnect(overlay, "blocklisting peer")
	return nil
}

func (s *Service) BlocklistRemove(overlay boson.Address) error {
	return s.blocklist.Remove(overlay)
}

func buildHostAddress(peerID libp2ppeer.ID) (ma.Multiaddr, error) {
	return ma.NewMultiaddr(fmt.Sprintf("/p2p/%s", peerID.Pretty()))
}

func buildUnderlayAddress(addr ma.Multiaddr, peerID libp2ppeer.ID) (ma.Multiaddr, error) {
	// Build host multiaddress
	hostAddr, err := buildHostAddress(peerID)
	if err != nil {
		return nil, err
	}

	return addr.Encapsulate(hostAddr), nil
}

func (s *Service) Connect(ctx context.Context, addr ma.Multiaddr) (peer *p2p.Peer, err error) {
	defer func() { err = multierror.Append(err, s.determineCurrentNetworkStatus(err)).ErrorOrNil() }()

	// Extract the peer ID from the multiaddr.
	info, err := libp2ppeer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("addr from p2p: %w", err)
	}

	hostAddr, err := buildHostAddress(info.ID)
	if err != nil {
		return nil, fmt.Errorf("build host address: %w", err)
	}

	remoteAddr := addr.Decapsulate(hostAddr)

	if peer, found := s.peers.isConnected(info.ID, remoteAddr); found {
		return peer, p2p.ErrAlreadyConnected
	}

	if err := s.connectionBreaker.Execute(func() error { return s.host.Connect(ctx, *info) }); err != nil {
		if errors.Is(err, breaker.ErrClosed) {
			s.metrics.ConnectBreakerCount.Inc()
			return nil, p2p.NewConnectionBackoffError(err, s.connectionBreaker.ClosedUntil())
		}
		return nil, err
	}

	stream, err := s.newStreamForPeerID(ctx, info.ID, handshake.ProtocolName, handshake.ProtocolVersion, handshake.StreamName)
	if err != nil {
		_ = s.host.Network().ClosePeer(info.ID)
		return nil, fmt.Errorf("connect new stream: %w", err)
	}

	handshakeStream := NewStream(stream)
	i, err := s.handshakeService.Handshake(ctx, handshakeStream, stream.Conn().RemoteMultiaddr(), stream.Conn().RemotePeer())
	if err != nil {
		_ = handshakeStream.Reset()
		_ = s.host.Network().ClosePeer(info.ID)
		return nil, fmt.Errorf("handshake: %w", err)
	}

	if !i.NodeMode.IsFull() {
		_ = handshakeStream.Reset()
		_ = s.host.Network().ClosePeer(info.ID)
		return nil, p2p.ErrDialLightNode
	}

	overlay := i.Address.Overlay

	blocked, err := s.blocklist.Exists(overlay)
	if err != nil {
		s.logger.Debugf("blocklisting: exists %s: %v", info.ID, err)
		s.logger.Errorf("internal error while connecting with peer %s", info.ID)
		_ = handshakeStream.Reset()
		_ = s.host.Network().ClosePeer(info.ID)
		return nil, err
	}

	if blocked {
		s.logger.Errorf("blocked connection to blocklisted peer %s", info.ID)
		_ = handshakeStream.Reset()
		_ = s.host.Network().ClosePeer(info.ID)
		return nil, p2p.ErrPeerBlocklisted
	}

	if exists := s.peers.addIfNotExists(stream.Conn(), overlay, i.NodeMode); exists {
		if err := handshakeStream.FullClose(); err != nil {
			_ = s.Disconnect(overlay, "failed closing handshake stream after connect")
			return nil, fmt.Errorf("peer exists, full close: %w", err)
		}

		return &p2p.Peer{
			Address: overlay,
			Mode:    i.NodeMode,
		}, nil
	}

	if err := handshakeStream.FullClose(); err != nil {
		_ = s.Disconnect(overlay, "could not fully close handshake stream after connect")
		return nil, fmt.Errorf("connect full close %w", err)
	}

	if i.NodeMode.IsFull() {
		err = s.addressbook.Put(overlay, *i.Address)
		if err != nil {
			_ = s.Disconnect(overlay, "failed storing peer in addressbook")
			return nil, fmt.Errorf("storing boson address: %w", err)
		}
	}

	s.protocolsmu.RLock()
	for _, tn := range s.protocols {
		if tn.ConnectOut != nil {
			if err := tn.ConnectOut(ctx, p2p.Peer{Address: overlay, Mode: i.NodeMode}); err != nil {
				s.logger.Debugf("connectOut: protocol: %s, version:%s, peer: %s: %v", tn.Name, tn.Version, overlay, err)
				_ = s.Disconnect(overlay, fmt.Sprintf("failed to process outbound connection notifier %s", err))
				s.protocolsmu.RUnlock()
				return nil, fmt.Errorf("connectOut: protocol: %s, version:%s: %w", tn.Name, tn.Version, err)
			}
		}
	}
	s.protocolsmu.RUnlock()

	if !s.peers.Exists(overlay) {
		_ = s.Disconnect(overlay, "outbound peer does not exist")
		return nil, fmt.Errorf("libp2p connect: peer %s does not exist %w", overlay, p2p.ErrPeerNotFound)
	}

	if i.NodeMode.IsBootNode() {
		s.bootNodes.Connected(ctx, p2p.Peer{Address: overlay, Mode: i.NodeMode})
	}

	s.metrics.CreatedConnectionCount.Inc()

	if s.reacher != nil {
		s.reacher.Connected(overlay, i.Address.Underlay)
	}

	peerUserAgent := appendSpace(s.peerUserAgent(ctx, info.ID))

	s.logger.Debugf("successfully connected to peer %s%s%s (outbound)", i.Address.ShortString(), i.LightString(), peerUserAgent)
	s.logger.Infof("successfully connected to peer %s%s%s (outbound)", overlay, i.LightString(), peerUserAgent)
	return &p2p.Peer{
		Address: overlay,
		Mode:    i.NodeMode,
	}, nil
}

func (s *Service) Disconnect(overlay boson.Address, reason string) error {
	s.metrics.DisconnectCount.Inc()

	s.logger.Debugf("libp2p disconnect: disconnecting peer %s reason: %s", overlay, reason)

	found, full, peerID := s.peers.remove(overlay)
	if !found {
		s.logger.Debugf("libp2p disconnect: peer %s not found", overlay)
		return p2p.ErrPeerNotFound
	}

	_ = s.host.Network().ClosePeer(peerID)

	peer := p2p.Peer{Address: overlay, Mode: full}

	s.protocolsmu.RLock()
	for _, tn := range s.protocols {
		if tn.DisconnectOut != nil {
			if err := tn.DisconnectOut(peer); err != nil {
				s.logger.Debugf("disconnectOut: protocol: %s, version:%s, peer: %s: %v", tn.Name, tn.Version, overlay, err)
			}
		}
	}
	s.protocolsmu.RUnlock()

	if s.notifier != nil {
		s.notifier.Disconnected(peer, reason)
	}
	if s.lightNodes != nil {
		s.lightNodes.Disconnected(peer)
	}
	if s.bootNodes != nil {
		s.bootNodes.Disconnected(peer)
	}
	if s.reacher != nil {
		s.reacher.Disconnected(overlay)
	}

	return nil
}

// disconnected is a registered peer registry event
func (s *Service) disconnected(peer p2p.Peer) {
	s.protocolsmu.RLock()
	for _, tn := range s.protocols {
		if tn.DisconnectIn != nil {
			if err := tn.DisconnectIn(peer); err != nil {
				s.logger.Debugf("disconnectIn: protocol: %s, version:%s, peer: %s: %v", tn.Name, tn.Version, peer.Address.String(), err)
			}
		}
	}
	s.protocolsmu.RUnlock()

	if s.notifier != nil {
		s.notifier.Disconnected(peer, "libp2p event")
	}
	if s.lightNodes != nil {
		s.lightNodes.Disconnected(peer)
	}
	if s.bootNodes != nil {
		s.bootNodes.Disconnected(peer)
	}
	if s.reacher != nil {
		s.reacher.Disconnected(peer.Address)
	}
}

func (s *Service) Peers() []p2p.Peer {
	return s.peers.peers()
}

func (s *Service) PeerID(overlay boson.Address) (id libp2ppeer.ID, found bool) {
	return s.peers.peerID(overlay)
}

func (s *Service) ResourceManager() network.ResourceManager {
	return s.host.Network().ResourceManager()
}

func (s *Service) getProtocolHandler(protocolName, protocolVersion, streamName string) (hand *p2p.StreamSpec, err error) {
	id := protocol.ID(p2p.NewProtocolStreamName(protocolName, protocolVersion, streamName))
	matcher, err := s.protocolSemverMatcher(id)
	if err != nil {
		err = fmt.Errorf("protocol version match %s: %w", id, err)
		return
	}
	var spec p2p.StreamSpec
	for _, ss := range s.protocols {
		if ss.Name == protocolName {
			for _, v := range ss.StreamSpecs {
				if matcher(protocol.ID(p2p.NewProtocolStreamName(protocolName, ss.Version, v.Name))) {
					spec = v
					break
				}
			}
			break
		}
	}
	if spec.Handler == nil {
		err = fmt.Errorf("no handler match %s", id)
		return
	}
	return &spec, nil
}

func (s *Service) CallHandlerWithConnChain(ctx context.Context, last, src p2p.Peer, stream p2p.Stream, protocolName, protocolVersion, streamName string) (err error) {
	spec, err := s.getProtocolHandler(protocolName, protocolVersion, streamName)
	if err != nil {
		return
	}

	// tracing: get span tracing context and add it to the context
	// silently ignore if the peer is not providing tracing
	ctx, err = s.tracer.WithContextFromHeaders(ctx, stream.Headers())
	if err != nil && !errors.Is(err, tracing.ErrContextNotFound) {
		s.logger.Debugf("handle protocol %s/%s: stream %s: peer %s: get tracing context: %v", protocolName, protocolVersion, streamName, src.Address, err)
		_ = stream.Reset()
		return
	}

	_, err = stream.Write([]byte("ack"))
	if err != nil {
		return fmt.Errorf("send ack err %s", err)
	}

	logger := tracing.NewLoggerWithTraceID(ctx, s.logger)

	s.metrics.HandledStreamCount.Inc()

	err = spec.Handler(ctx, src, stream)
	if err != nil {
		var de *p2p.DisconnectError
		if errors.As(err, &de) {
			logger.Tracef("CallHandlerWithConnChain libp2p handler(%s): disconnecting last %s", streamName, last.Address)
			_ = stream.Reset()
			_ = s.Disconnect(last.Address, de.Error())
		}
		// count unexpected requests
		if errors.Is(err, p2p.ErrUnexpected) {
			s.metrics.UnexpectedProtocolReqCount.Inc()
		}
		logger.Debugf("could not call handle protocol %s/%s: realy stream %s: peer %s: error: %v", protocolName, protocolVersion, streamName, src.Address, err)
	}
	return
}

func (s *Service) NewConnChainRelayStream(ctx context.Context, target boson.Address, headers p2p.Headers, protocolName, protocolVersion, streamName string) (p2p.Stream, error) {
	next, err := s.route.GetNextHopRandomOrFind(ctx, target)
	if err != nil {
		return nil, err
	}

	peerID, found := s.peers.peerID(next)
	if !found {
		return nil, p2p.ErrPeerNotFound
	}

	streamlibp2p, err := s.newStreamForPeerID(ctx, peerID, routetab.ProtocolName, routetab.ProtocolVersion, routetab.StreamOnRelayConnChain)
	if err != nil {
		return nil, fmt.Errorf("new stream for peerid: %w", err)
	}

	st, err := s.exchangeHeaders(ctx, streamlibp2p, headers)
	if err != nil {
		return nil, err
	}

	req := &pb.RouteRelayReq{
		Src:             s.self.Bytes(),
		SrcMode:         s.nodeMode.Bv.Bytes(),
		Dest:            target.Bytes(),
		ProtocolName:    []byte(protocolName),
		ProtocolVersion: []byte(protocolVersion),
		StreamName:      []byte(streamName),
	}
	w := protobuf.NewWriter(st)
	err = w.WriteMsgWithContext(ctx, req)
	if err != nil {
		_ = st.Reset()
		return nil, fmt.Errorf("send syn err %v", err)
	}
	ack := make([]byte, 3)
	_, err = st.Read(ack)
	if err != nil {
		_ = st.Reset()
		return nil, fmt.Errorf("read ack err %v", err)
	}
	return st, nil
}

func (s *Service) CallHandler(ctx context.Context, src p2p.Peer, stream p2p.Stream) (_ *pb.RouteRelayReq, _ *p2p.WriterChan, r *p2p.ReaderChan, _ bool, err error) {
	kv := ctx.Value("req_stream").(map[string]string)
	name := kv["pName"]
	version := kv["pVersion"]
	streamName := kv["sName"]

	spec, err := s.getProtocolHandler(name, version, streamName)
	if err != nil {
		s.logger.Warningf("handle protocol %s/%s: stream %s: peer %s: %v", name, version, streamName, src.Address, err)
		err = nil
		return
	}

	// tracing: get span tracing context and add it to the context
	// silently ignore if the peer is not providing tracing
	ctx, err = s.tracer.WithContextFromHeaders(ctx, stream.Headers())
	if err != nil && !errors.Is(err, tracing.ErrContextNotFound) {
		s.logger.Debugf("handle protocol %s/%s: stream %s: peer %s: get tracing context: %v", name, version, streamName, src.Address, err)
		_ = stream.Reset()
		return
	}
	err = nil
	logger := tracing.NewLoggerWithTraceID(ctx, s.logger)

	s.metrics.HandledStreamCount.Inc()

	r = &p2p.ReaderChan{
		Err: make(chan error, 1),
	}
	go func() {
		err = spec.Handler(ctx, src, stream)
		if err != nil {
			logger.Warningf("could not call handle protocol %s/%s: realy stream %s: peer %s: error: %v", name, version, streamName, src.Address, err)
		}
		r.Err <- err
	}()
	return
}

func (s *Service) NewRelayStream(ctx context.Context, target boson.Address, headers p2p.Headers, protocolName, protocolVersion, streamName string, midCall bool) (p2p.Stream, error) {
	next, err := s.route.GetNextHopRandomOrFind(ctx, target)
	if err != nil {
		return nil, err
	}

	peerID, found := s.peers.peerID(next)
	if !found {
		return nil, p2p.ErrPeerNotFound
	}

	streamlibp2p, err := s.newStreamForPeerID(ctx, peerID, routetab.ProtocolName, routetab.ProtocolVersion, routetab.StreamOnRelay)
	if err != nil {
		return nil, fmt.Errorf("new stream for peerid: %w", err)
	}

	st, err := s.exchangeHeaders(ctx, streamlibp2p, headers)
	if err != nil {
		return nil, err
	}
	req := &pb.RouteRelayReq{
		Src:             s.self.Bytes(),
		SrcMode:         s.nodeMode.Bv.Bytes(),
		Dest:            target.Bytes(),
		ProtocolName:    []byte(protocolName),
		ProtocolVersion: []byte(protocolVersion),
		StreamName:      []byte(streamName),
		MidCall:         midCall,
	}
	w := protobuf.NewWriter(st)
	err = w.WriteMsgWithContext(ctx, req)
	if err != nil {
		_ = st.Reset()
		return nil, fmt.Errorf("send syn err %v", err)
	}
	return st, nil
}

func (s *Service) NewStream(ctx context.Context, overlay boson.Address, headers p2p.Headers, protocolName, protocolVersion, streamName string) (p2p.Stream, error) {
	peerID, found := s.peers.peerID(overlay)
	if !found {
		return nil, p2p.ErrPeerNotFound
	}

	streamlibp2p, err := s.newStreamForPeerID(ctx, peerID, protocolName, protocolVersion, streamName)
	if err != nil {
		return nil, fmt.Errorf("new stream for peerid: %w", err)
	}

	return s.exchangeHeaders(ctx, streamlibp2p, headers)
}

func (s *Service) exchangeHeaders(ctx context.Context, streamlibp2p network.Stream, headers p2p.Headers) (p2p.Stream, error) {
	st := newStream(streamlibp2p)

	// tracing: add span context header
	if headers == nil {
		headers = make(p2p.Headers)
	}
	if err := s.tracer.AddContextHeader(ctx, headers); err != nil && !errors.Is(err, tracing.ErrContextNotFound) {
		_ = st.Reset()
		return nil, fmt.Errorf("new stream add context header fail: %w", err)
	}

	// exchange headers
	if err := sendHeaders(ctx, headers, st); err != nil {
		_ = st.Reset()
		return nil, fmt.Errorf("send headers: %w", err)
	}

	return st, nil
}

func (s *Service) newStreamForPeerID(ctx context.Context, peerID libp2ppeer.ID, protocolName, protocolVersion, streamName string) (network.Stream, error) {
	pidName := p2p.NewProtocolStreamName(protocolName, protocolVersion, streamName)
	st, err := s.host.NewStream(ctx, peerID, protocol.ID(pidName))
	if err != nil {
		if st != nil {
			s.logger.Debug("stream experienced unexpected early close")
			_ = st.Close()
		}
		if err == multistream.ErrNoProtocols || err == multistream.ErrIncorrectVersion {
			return nil, p2p.NewIncompatibleStreamError(err)
		}
		return nil, fmt.Errorf("create stream %q to %q: %w", pidName, peerID, err)
	}
	s.metrics.CreatedStreamCount.Inc()
	return st, nil
}

func (s *Service) Close() error {
	if err := s.libp2pPeerstore.Close(); err != nil {
		return err
	}
	if s.natManager != nil {
		if err := s.natManager.Close(); err != nil {
			return err
		}
	}
	if err := s.pingDialer.Close(); err != nil {
		return err
	}

	return s.host.Close()
}

// SetWelcomeMessage sets the welcome message for the handshake protocol.
func (s *Service) SetWelcomeMessage(val string) error {
	return s.handshakeService.SetWelcomeMessage(val)
}

// GetWelcomeMessage returns the value of the welcome message.
func (s *Service) GetWelcomeMessage() string {
	return s.handshakeService.GetWelcomeMessage()
}

func (s *Service) Ready() error {
	if err := s.reachabilityWorker(); err != nil {
		return fmt.Errorf("reachability worker: %w", err)
	}

	close(s.ready)
	return nil
}

func (s *Service) Halt() {
	close(s.halt)
}

func (s *Service) Ping(ctx context.Context, addr ma.Multiaddr) (rtt time.Duration, err error) {
	info, err := libp2ppeer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		return rtt, fmt.Errorf("unable to parse underlay address: %w", err)
	}

	// Add the address to libp2p peerstore for it to be dialable
	s.pingDialer.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.TempAddrTTL)

	// Cleanup connection after ping is done
	defer func() {
		_ = s.pingDialer.Network().ClosePeer(info.ID)
	}()

	select {
	case <-ctx.Done():
		return rtt, ctx.Err()
	case res := <-libp2pping.Ping(ctx, s.pingDialer, info.ID):
		return res.RTT, res.Error
	}
}

// peerUserAgent returns User Agent string of the connected peer if the peer
// provides it. It ignores the default libp2p user agent string
// "github.com/libp2p/go-libp2p" and returns empty string in that case.
func (s *Service) peerUserAgent(ctx context.Context, peerID libp2ppeer.ID) string {
	ctx, cancel := context.WithTimeout(ctx, peerUserAgentTimeout)
	defer cancel()
	var (
		v   interface{}
		err error
	)
	// Peerstore may not contain all keys and values right after the connections is created.
	// This retry mechanism ensures more reliable user agent propagation.
	for iterate := true; iterate; {
		v, err = s.host.Peerstore().Get(peerID, "AgentVersion")
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			iterate = false
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err != nil {
		// error is ignored as user agent is informative only
		return ""
	}
	ua, ok := v.(string)
	if !ok {
		return ""
	}
	// Ignore the default user agent.
	if ua == "github.com/libp2p/go-libp2p" {
		return ""
	}
	return ua
}

// NetworkStatus implements the p2p.NetworkStatus interface.
func (s *Service) NetworkStatus() p2p.NetworkStatus {
	return p2p.NetworkStatus(s.networkStatus.Load())
}

// determineCurrentNetworkStatus determines if the network
// is available/unavailable based on the given error, and
// returns ErrNetworkUnavailable if unavailable.
// The result of this operation is stored and can be reflected
// in the results of future NetworkStatus method calls.
func (s *Service) determineCurrentNetworkStatus(err error) error {
	switch {
	case err == nil:
		s.networkStatus.Store(int32(p2p.NetworkStatusAvailable))
	case errors.Is(err, lp2pswarm.ErrDialBackoff):
		if s.NetworkStatus() == p2p.NetworkStatusUnavailable {
			err = p2p.ErrNetworkUnavailable
		}
	case isNetworkOrHostUnreachableError(err):
		s.networkStatus.Store(int32(p2p.NetworkStatusUnavailable))
		err = p2p.ErrNetworkUnavailable
	default:
		if s.NetworkStatus() != p2p.NetworkStatusUnavailable {
			s.networkStatus.Store(int32(p2p.NetworkStatusUnknown))
		}
	}
	return nil
}

// appendSpace adds a leading space character if the string is not empty.
// It is useful for constructing log messages with conditional substrings.
func appendSpace(s string) string {
	if s == "" {
		return ""
	}
	return " " + s
}

// userAgent returns a User Agent string passed to the libp2p host to identify peer node.
func userAgent() string {
	return fmt.Sprintf("favorX/%s %s %s/%s", fx.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func newConnMetricNotify(m metrics) *connectionNotifier {
	return &connectionNotifier{
		metrics:  m,
		Notifiee: new(network.NoopNotifiee),
	}
}

type connectionNotifier struct {
	metrics metrics
	network.Notifiee
}

func (c *connectionNotifier) Connected(_ network.Network, _ network.Conn) {
	c.metrics.HandledConnectionCount.Inc()
}

// isNetworkOrHostUnreachableError determines based on the
// given error whether the host or network is reachable.
func isNetworkOrHostUnreachableError(err error) bool {
	var de *lp2pswarm.DialError
	if !errors.As(err, &de) {
		return false
	}

	// Since TransportError doesn't implement the Unwrap
	// method we need to inspect the errors manually.
	for i := range de.DialErrors {
		var te *lp2pswarm.TransportError
		if !errors.As(&de.DialErrors[i], &te) {
			continue
		}

		var ne *net.OpError
		if !errors.As(te.Cause, &ne) || ne.Op != "dial" {
			continue
		}

		var se *os.SyscallError
		if errors.As(ne, &se) && strings.HasPrefix(se.Syscall, "connect") &&
			(errors.Is(se.Err, errHostUnreachable) || errors.Is(se.Err, errNetworkUnreachable)) {
			return true
		}
	}
	return false
}

// PingPong 兼容旧接口，返回自身实现的 Ping 方法
func (s *Service) PingPong() func(ctx context.Context, addr ma.Multiaddr) (time.Duration, error) {
	return s.Ping
}

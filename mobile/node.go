package mobile

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	fx "github.com/FavorLabs/favorX"
	"github.com/FavorLabs/favorX/pkg/address"
	"github.com/FavorLabs/favorX/pkg/boson"
	"github.com/FavorLabs/favorX/pkg/crypto"
	filekeystore "github.com/FavorLabs/favorX/pkg/keystore/file"
	"github.com/FavorLabs/favorX/pkg/keystore/p2pkey"
	"github.com/FavorLabs/favorX/pkg/logging"
	"github.com/FavorLabs/favorX/pkg/node"
	crypto2 "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/sirupsen/logrus"
	"github.com/FavorLabs/favorX/pkg/p2p/libp2p"
	"github.com/FavorLabs/favorX/pkg/topology/kademlia"
	"errors"
)

type Node struct {
	node   *node.Favor
	opts   *Options
	logger logging.Logger
}

type signerConfig struct {
	signer           crypto.Signer
	address          boson.Address
	publicKey        *ecdsa.PublicKey
	libp2pPrivateKey crypto2.PrivKey
}

func Version() string {
	return fx.Version
}

func NewNode(o *Options) (*Node, error) {
	logger, err := newLogger(o.Verbosity)
	if err != nil {
		return nil, err
	}

	// put keys into dataDir
	keyPath := filepath.Join(o.DataPath, "keys")

	signerConfig, err := configureSigner(keyPath, o.Password, uint64(o.NetworkID), logger)
	if err != nil {
		return nil, err
	}

	logger.Infof("version: %v", Version())

	mode := address.NewModel()
	if o.EnableFullNode {
		mode.SetMode(address.FullNode)
		logger.Info("start node mode full.")
	} else {
		logger.Info("start node mode light.")
	}

	config := o.export()
	p2pAddr := fmt.Sprintf("%s:%d", listenAddress, o.P2PPort)

	favorXNode, err := node.NewNode(mode, p2pAddr, signerConfig.address, *signerConfig.publicKey, signerConfig.signer, uint64(o.NetworkID), logger, signerConfig.libp2pPrivateKey, config)
	if err != nil {
		return nil, err
	}

	return &Node{node: favorXNode, opts: o, logger: logger}, nil
}

func (n *Node) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return n.node.Shutdown(ctx)
}

func configureSigner(path, password string, networkID uint64, logger logging.Logger) (*signerConfig, error) {
	if path == "" {
		return nil, fmt.Errorf("keystore directory not provided")
	}

	keystore := filekeystore.New(path)

	PrivateKey, created, err := keystore.Key("boson", password)
	if err != nil {
		return nil, fmt.Errorf("boson key: %w", err)
	}
	signer := crypto.NewDefaultSigner(PrivateKey)
	publicKey := &PrivateKey.PublicKey

	addr, err := crypto.NewOverlayAddress(*publicKey, networkID)
	if err != nil {
		return nil, err
	}
	if created {
		logger.Infof("new boson network address created: %s", addr)
	} else {
		logger.Infof("using existing boson network address: %s", addr)
	}

	logger.Infof("boson public key %x", crypto.EncodeSecp256k1PublicKey(publicKey))

	libp2pPrivateKey, created, err := p2pkey.New(path).Key("libp2p", password)
	if err != nil {
		return nil, fmt.Errorf("libp2p key: %w", err)
	}
	if created {
		logger.Debugf("new libp2p key created")
	} else {
		logger.Debugf("using existing libp2p key")
	}

	return &signerConfig{
		signer:           signer,
		address:          addr,
		publicKey:        publicKey,
		libp2pPrivateKey: libp2pPrivateKey,
	}, nil
}

func cmdOutput() io.Writer {
	return os.Stdout
}

func newLogger(verbosity string) (logging.Logger, error) {
	var logger logging.Logger
	switch verbosity {
	case "0", "silent":
		logger = logging.New(io.Discard, 0)
	case "1", "error":
		logger = logging.New(cmdOutput(), logrus.ErrorLevel)
	case "2", "warn":
		logger = logging.New(cmdOutput(), logrus.WarnLevel)
	case "3", "info":
		logger = logging.New(cmdOutput(), logrus.InfoLevel)
	case "4", "debug":
		logger = logging.New(cmdOutput(), logrus.DebugLevel)
	case "5", "trace":
		logger = logging.New(cmdOutput(), logrus.TraceLevel)
	default:
		return nil, fmt.Errorf("unknown verbosity level %q", verbosity)
	}

	return logger, nil
}

// 检查并重连当前已连接P2P节点：对每个 peer 主动 ping，ping 不通则重连
func (n *Node) CheckAndReconnectPeers() (checked int, reconnected int, err error) {
	if n == nil || n.node == nil {
		return 0, 0, errors.New("node not initialized")
	}
	kad, ok := n.node.Topology().(*kademlia.Kad)
	if !ok {
		return 0, 0, errors.New("kad not available")
	}
	p2ps, ok := n.node.P2PService().(*libp2p.Service)
	if !ok {
		return 0, 0, errors.New("p2pService not available")
	}
	pingpongService := n.node.PingPong()
	if pingpongService == nil {
		return 0, 0, errors.New("pingpong service not available")
	}
	peers := p2ps.Peers()
	for _, peer := range peers {
		checked++
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := pingpongService.Ping(ctx, peer.Address)
		cancel()
		if err != nil {
			// ping 不通，尝试重连
			ab := kad.AddressBook()
			bzzAddr, err2 := ab.Get(peer.Address)
			if err2 == nil {
				ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel2()
				_, err2 = p2ps.Connect(ctx2, bzzAddr.Underlay)
				if err2 == nil {
					reconnected++
				}
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

// 检查并重启HTTP服务（增强：端口+HTTP活性检测）
func (n *Node) CheckAndRestartHTTP() (healthy bool, restarted bool, err error) {
	if n == nil || n.node == nil {
		return false, false, errors.New("node not initialized")
	}
	addr := "127.0.0.1"
	port := n.opts.ApiPort
	apiAddr := net.JoinHostPort(addr, fmt.Sprintf("%d", port))
	// 1. 端口可达性检测
	conn, err := net.DialTimeout("tcp", apiAddr, 2*time.Second)
	if err != nil {
		// 端口不可达，需重启
		return n.restartHTTPServer()
	}
	conn.Close()
	// 2. HTTP 层活性检测
	url := "http://" + apiAddr + "/v1/ping"
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		// HTTP 不通或返回异常，需重启
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return n.restartHTTPServer()
	}
	resp.Body.Close()
	return true, false, nil
}

// restartHTTPServer 关闭并重启 HTTP 服务
func (n *Node) restartHTTPServer() (healthy bool, restarted bool, err error) {
	srv := n.node
	if srv == nil {
		return false, false, errors.New("node not initialized")
	}
	if srv.ApiServer() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.ApiServer().Shutdown(ctx)
	}
	if srv.ApiCloser() != nil {
		_ = srv.ApiCloser().Close()
	}
	// 这里建议你将 FavorX API 服务的启动逻辑单独封装为 StartAPI 方法，然后在这里调用
	// 目前只能返回"已关闭"，实际重启需你补充完整启动流程
	return false, true, errors.New("HTTP服务已关闭，请手动重启或补充自动重启逻辑")
}

// OnResume: 用于移动端前台恢复时的自愈入口
func (n *Node) OnResume() (peerChecked, peerReconnected int, httpHealthy, httpRestarted bool, err error) {
	peerChecked, peerReconnected, err1 := n.CheckAndReconnectPeers()
	httpHealthy, httpRestarted, err2 := n.CheckAndRestartHTTP()
	if err1 != nil && err2 != nil {
		err = fmt.Errorf("peer: %v; http: %v", err1, err2)
	} else if err1 != nil {
		err = err1
	} else if err2 != nil {
		err = err2
	}
	return
}

package mobile

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"net"
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
	_ "golang.org/x/mobile/bind"
)

const exportKey = "dOVqGYDUcTSOS0D8FP8Z0qBNUGThii37qVjwQF0ML+c="

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

// ResumeResult 用于封装 OnResume 的所有返回信息
type ResumeResult struct {
	PeerChecked     int
	PeerReconnected int
	HttpHealthy     bool
	HttpRestarted   bool
	ErrMsg          string
}

// OnResume: 用于移动端前台恢复时的自愈入口，返回 ResumeResult 和 error
func (n *Node) OnResume() (*ResumeResult, error) {
	if n == nil || n.node == nil {
		return nil, fmt.Errorf("node not initialized")
	}
	addr := "127.0.0.1"
	port := n.opts.ApiPort
	apiAddr := net.JoinHostPort(addr, fmt.Sprintf("%d", port))
	peerChecked, peerReconnected, httpHealthy, httpRestarted, err := n.node.OnResume(apiAddr)
	res := &ResumeResult{
		PeerChecked:     peerChecked,
		PeerReconnected: peerReconnected,
		HttpHealthy:     httpHealthy,
		HttpRestarted:   httpRestarted,
	}
	if err != nil {
		res.ErrMsg = err.Error()
		return res, err
	}
	return res, nil
}

// ConnectedPeerCount 返回 outbound 类型已连接 peer 数
func (n *Node) ConnectedPeerCount() int {
	if n == nil || n.node == nil {
		return 0
	}
	return n.node.ConnectedPeerCount()
}

// ExportOutboundPeers 导出最多 max 个 outbound 已连接节点的 Underlay 地址，加密后 base64 输出
func (n *Node) ExportOutboundPeers(max int) (string, error) {
	if n == nil || n.node == nil {
		return "", errors.New("node not initialized")
	}
	return n.node.ExportOutboundPeers(max)
}

// ImportBootNodes 解密 base64 字符串，解析出 Underlay 地址，存入 Favor.Bootnodes
func (n *Node) ImportBootNodes(enc string) error {
	if n == nil || n.node == nil {
		return errors.New("node not initialized")
	}
	return n.node.ImportBootNodes(enc)
}

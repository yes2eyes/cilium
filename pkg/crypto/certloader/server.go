// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certloader

import (
	"crypto/tls"
	"errors"

	"github.com/sirupsen/logrus"
)

// ServerConfig creates tls.Config to be used as TLS server.
type ServerConfig interface {
	IsMutualTLS() bool
	ServerConfig(base *tls.Config) *tls.Config
}

// WatchedServerConfig is a ServerConfig backed up by files to be watched for
// changes. The tls.Config created will use the latest CA and keypair on each
// TLS handshake, allowing for smooth TLS configuration rotation.
type WatchedServerConfig struct {
	*WatchedConfig
}

var (
	// ErrMissingCertFile is returned when the certificate file is missing.
	ErrMissingCertFile = errors.New("certificate file path is required")
	// ErrMissingPrivkeyFile is returned when the private key file is missing.
	ErrMissingPrivkeyFile = errors.New("private key file path is required")
)

// NewWatchedServerConfig returns a WatchedServerConfig configured with the
// provided files. both certFile and privkeyFile must be provided. To configure
// a mTLS capable ServerConfig, caFiles must contains at least one file path.
func NewWatchedServerConfig(log logrus.FieldLogger, caFiles []string, certFile, privkeyFile string) (*WatchedServerConfig, error) {
	if certFile == "" {
		return nil, ErrMissingCertFile
	}
	if privkeyFile == "" {
		return nil, ErrMissingPrivkeyFile
	}

	cfg, err := NewWatchedConfig(log, caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}
	return &WatchedServerConfig{cfg}, nil
}

// IsMutualTLS implement ServerConfig.
func (cfg *WatchedServerConfig) IsMutualTLS() bool {
	return cfg.CertificateAuthorityConfigured()
}

// ServerConfig implement ServerConfig.
func (cfg *WatchedServerConfig) ServerConfig(base *tls.Config) *tls.Config {
	// We return a tls.Config having only the GetConfigForClient member set.
	// When a client initialize a TLS handshake, this function will be called
	// and the tls.Config returned by GetConfigForClient will be used. This
	// mechanism allow us to reload the certificates transparently between two
	// clients connections without having to restart the server.
	// See also the discussion at https://github.com/golang/go/issues/16066.
	return &tls.Config{
		GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			keypair, caCertPool := cfg.KeypairAndCACertPool()
			tlsConfig := base.Clone()
			if cfg.IsMutualTLS() {
				// We've been configured to serve mTLS, so setup the ClientCAs
				// accordingly.
				tlsConfig.ClientCAs = caCertPool
				// The caller may have its own desire about the handshake
				// ClientAuthType. We honor it unless its tls.NoClientCert (the
				// default zero value) as we are configured to serve mTLS.
				if tlsConfig.ClientAuth == tls.NoClientCert {
					tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
				}
			}
			tlsConfig.Certificates = []tls.Certificate{*keypair}
			return tlsConfig, nil
		},
	}
}

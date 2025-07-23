package key

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

var (
	// Global variables for private key content, public key content, and fingerprint with RWLock for thread safety
	privateKeyContent    string
	publicKeyContent     string
	publicKeyFingerprint string
	privateKeyMutex      sync.RWMutex

	logger *logrus.Logger
)

func init() {
	logger = logrus.New()
}

func SetLogger(_logger *logrus.Logger) {
	logger = _logger
}

func SetupPrivateKeyWatcher(filePath string) (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create private key watcher: %w", err)
	}

	// Get the directory path to watch
	dir := filepath.Dir(filePath)

	// Add the directory to watcher
	err = watcher.Add(dir)
	if err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to add directory to private key watcher: %w", err)
	}

	// Try to read initial file content if it exists
	if _, err := os.Stat(filePath); err == nil {
		loadPrivateKeyContent(filePath)
	}

	// Debouncing variables
	var debounceTimer *time.Timer
	var lastEvent fsnotify.Event
	const debounceDelay = time.Second

	// Start watching in a goroutine
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// Only process events for our specific file
				if event.Name != filePath {
					continue
				}

				// Only process Create, Write, or Rename events
				if !(event.Op&fsnotify.Create == fsnotify.Create ||
					event.Op&fsnotify.Write == fsnotify.Write ||
					event.Op&fsnotify.Rename == fsnotify.Rename) {
					logger.WithFields(logrus.Fields{
						"file":  event.Name,
						"event": event.Op.String(),
					}).Debug("Private key event ignored (not Create/Write/Rename)")
					continue
				}

				logger.WithFields(logrus.Fields{
					"file":  event.Name,
					"event": event.Op.String(),
				}).Debug("Private key event received")

				// Store the latest event
				lastEvent = event

				// Cancel existing timer if any
				if debounceTimer != nil {
					debounceTimer.Stop()
				}

				// Start new debounce timer
				debounceTimer = time.AfterFunc(debounceDelay, func() {
					processPrivateKeyEvent(lastEvent, filePath)
				})

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.WithError(err).Error("Private key watcher error")
			}
		}
	}()

	logger.WithFields(logrus.Fields{
		"path":           filePath,
		"dir":            dir,
		"debounce_delay": debounceDelay.String(),
	}).Info("Private key watcher initialized with debouncing")

	return watcher, nil
}

func processPrivateKeyEvent(event fsnotify.Event, filePath string) {
	logger.WithFields(logrus.Fields{
		"file":  event.Name,
		"event": event.Op.String(),
	}).Info("Processing debounced private key event")

	if event.Op&fsnotify.Create == fsnotify.Create ||
		event.Op&fsnotify.Write == fsnotify.Write {
		// File created or modified - read content
		loadPrivateKeyContent(filePath)
	} else if event.Op&fsnotify.Rename == fsnotify.Rename {
		// File renamed - try to load, clear if failed
		if err := loadPrivateKeyContent(filePath); err != nil {
			clearPrivateKeyContent()
		}
	}
}

func loadPrivateKeyContent(filePath string) error {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		logger.WithError(err).WithField("path", filePath).Error("Failed to read private key file")
		return err
	}

	var fingerprint string
	var publicKeyPEM string
	if len(content) > 0 {
		// Parse RSA private key and generate public key
		block, _ := pem.Decode(content)
		if block != nil && block.Type == "RSA PRIVATE KEY" {
			privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				// Generate public key from private key
				pubKey := &privKey.PublicKey
				fingerprint = calculateRSAFingerprint(pubKey)

				// Convert public key to PEM format
				pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
				if err == nil {
					pubKeyBlock := &pem.Block{
						Type:  "PUBLIC KEY",
						Bytes: pubKeyBytes,
					}
					publicKeyPEM = string(pem.EncodeToMemory(pubKeyBlock))
				} else {
					logger.WithError(err).WithField("path", filePath).Warn("Failed to marshal public key to PEM")
				}
			} else {
				logger.WithError(err).WithField("path", filePath).Warn("Failed to parse RSA private key")
			}
		} else if block != nil && block.Type == "PRIVATE KEY" {
			privKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				if rsaPrivKey, ok := privKeyInterface.(*rsa.PrivateKey); ok {
					// Generate public key from private key
					pubKey := &rsaPrivKey.PublicKey
					fingerprint = calculateRSAFingerprint(pubKey)

					// Convert public key to PEM format
					pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
					if err == nil {
						pubKeyBlock := &pem.Block{
							Type:  "PUBLIC KEY",
							Bytes: pubKeyBytes,
						}
						publicKeyPEM = string(pem.EncodeToMemory(pubKeyBlock))
					} else {
						logger.WithError(err).WithField("path", filePath).Warn("Failed to marshal public key to PEM")
					}
				} else {
					logger.WithField("path", filePath).Warn("Private key is not an RSA key")
				}
			} else {
				logger.WithError(err).WithField("path", filePath).Warn("Failed to parse private key")
			}
		} else {
			logger.WithField("path", filePath).Warn("Invalid PEM format or unsupported key type")
		}
	}

	privateKeyMutex.Lock()
	privateKeyContent = string(content)
	publicKeyContent = publicKeyPEM
	publicKeyFingerprint = fingerprint
	privateKeyMutex.Unlock()

	logger.WithFields(logrus.Fields{
		"path":        filePath,
		"size":        len(content),
		"fingerprint": fingerprint,
	}).Info("Private key content loaded")
	return nil
}

func clearPrivateKeyContent() {
	privateKeyMutex.Lock()
	privateKeyContent = ""
	publicKeyContent = ""
	publicKeyFingerprint = ""
	privateKeyMutex.Unlock()

	logger.Info("Private key content cleared")
}

func GetPrivateKeyContent() string {
	privateKeyMutex.RLock()
	defer privateKeyMutex.RUnlock()
	return privateKeyContent
}

func GetPublicKeyFingerprint() string {
	privateKeyMutex.RLock()
	defer privateKeyMutex.RUnlock()
	return publicKeyFingerprint
}

func GetPublicKeyContent() string {
	privateKeyMutex.RLock()
	defer privateKeyMutex.RUnlock()
	return publicKeyContent
}

func calculateRSAFingerprint(pubKey *rsa.PublicKey) string {
	// Convert RSA public key to DER format
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal RSA public key to DER")
		return ""
	}

	// Calculate SHA256 hash
	hash := sha256.Sum256(derBytes)
	return hex.EncodeToString(hash[:])
}

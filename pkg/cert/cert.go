package cert

import (
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
	// Global variables for certificate content and fingerprint with RWLock for thread safety
	certificateContent     string
	certificateFingerprint string
	certificateMutex       sync.RWMutex

	logger *logrus.Logger
)

func init() {
	logger = logrus.New()
}

func SetLogger(_logger *logrus.Logger) {
	logger = _logger
}

func SetupCertificateWatcher(filePath string) (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate watcher: %w", err)
	}

	// Get the directory path to watch
	dir := filepath.Dir(filePath)

	// Add the directory to watcher
	err = watcher.Add(dir)
	if err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to add directory to certificate watcher: %w", err)
	}

	// Try to read initial file content if it exists
	if _, err := os.Stat(filePath); err == nil {
		loadCertificateContent(filePath)
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
					}).Debug("Certificate event ignored (not Create/Write/Rename)")
					continue
				}

				logger.WithFields(logrus.Fields{
					"file":  event.Name,
					"event": event.Op.String(),
				}).Debug("Certificate event received")

				// Store the latest event
				lastEvent = event

				// Cancel existing timer if any
				if debounceTimer != nil {
					debounceTimer.Stop()
				}

				// Start new debounce timer
				debounceTimer = time.AfterFunc(debounceDelay, func() {
					processCertificateEvent(lastEvent, filePath)
				})

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.WithError(err).Error("Certificate watcher error")
			}
		}
	}()

	logger.WithFields(logrus.Fields{
		"path":           filePath,
		"dir":            dir,
		"debounce_delay": debounceDelay.String(),
	}).Info("Certificate watcher initialized with debouncing")

	return watcher, nil
}

func processCertificateEvent(event fsnotify.Event, filePath string) {
	logger.WithFields(logrus.Fields{
		"file":  event.Name,
		"event": event.Op.String(),
	}).Info("Processing debounced certificate event")

	if event.Op&fsnotify.Create == fsnotify.Create ||
		event.Op&fsnotify.Write == fsnotify.Write {
		// File created or modified - read content
		loadCertificateContent(filePath)
	} else if event.Op&fsnotify.Rename == fsnotify.Rename {
		// File renamed - try to load, clear if failed
		if err := loadCertificateContent(filePath); err != nil {
			clearCertificateContent()
		}
	}
}

func calculateCertificateFingerprint(cert *x509.Certificate) string {
	// Calculate SHA256 hash of certificate DER bytes
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

func loadCertificateContent(filePath string) error {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		logger.WithError(err).WithField("path", filePath).Error("Failed to read certificate file")
		return err
	}

	var fingerprint string
	if len(content) > 0 {
		// Parse TLS certificate
		block, _ := pem.Decode(content)
		if block != nil && block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				fingerprint = calculateCertificateFingerprint(cert)
			} else {
				logger.WithError(err).WithField("path", filePath).Warn("Failed to parse certificate")
			}
		} else {
			logger.WithField("path", filePath).Warn("Invalid PEM format or not a certificate")
		}
	}

	certificateMutex.Lock()
	certificateContent = string(content)
	certificateFingerprint = fingerprint
	certificateMutex.Unlock()

	logger.WithFields(logrus.Fields{
		"path":        filePath,
		"size":        len(content),
		"fingerprint": fingerprint,
	}).Info("Certificate content loaded")
	return nil
}

func clearCertificateContent() {
	certificateMutex.Lock()
	certificateContent = ""
	certificateFingerprint = ""
	certificateMutex.Unlock()

	logger.Info("Certificate content cleared")
}

func GetCertificateContent() string {
	certificateMutex.RLock()
	defer certificateMutex.RUnlock()
	return certificateContent
}

func GetCertificateFingerprint() string {
	certificateMutex.RLock()
	defer certificateMutex.RUnlock()
	return certificateFingerprint
}

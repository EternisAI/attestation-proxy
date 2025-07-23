package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cristalhq/base64"
	"github.com/fsnotify/fsnotify"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/EternisAI/attestation-proxy/pkg/cert"
	"github.com/EternisAI/attestation-proxy/pkg/key"
)

var (
	bindAddress      string
	bindPort         uint16
	enclaverAddress  string
	enclaverPort     uint16
	enclaverEndpoint string
	logLevel         string
	privateKeyPath   string
	certificatePath  string
	logger           *logrus.Logger

	// Global enclaveData variable
	enclaveData EnclaveData
)

const ATTESTATION_ENDPOINT_PATH = "/-/attestation"
const ATTESTATION_NONCE_HEADER = "x-attestation-nonce"
const ATTESTATION_PAYLOAD_HEADER = "x-attestation-payload"
const CONTENT_TYPE_OCTET_STREAM = "application/octet-stream"
const MAX_DATA_LEN = 512

// EnclaveData holds enclave build information
type EnclaveData struct {
	BuildID        string `json:"build_id,omitempty"`
	BuildVersion   string `json:"build_version,omitempty"`
	ProvenancePath string `json:"provenance_path,omitempty"`
}

// empty checks if all EnclaveData fields are empty
func (ed *EnclaveData) empty() bool {
	return ed.BuildID == "" && ed.BuildVersion == "" && ed.ProvenancePath == ""
}

// LoadEnclaveData loads EnclaveData fields from environment variables
func LoadEnclaveData() EnclaveData {
	var ed EnclaveData

	ed.BuildID = os.Getenv("ENCLAVE_BUILD_ID")
	if ed.BuildID == "" {
		logger.Warn("ENCLAVE_BUILD_ID environment variable is empty")
	} else {
		logger.WithField("build_id", ed.BuildID).Info("Loaded ENCLAVE_BUILD_ID")
	}

	ed.BuildVersion = os.Getenv("ENCLAVE_BUILD_VERSION")
	if ed.BuildVersion == "" {
		logger.Warn("ENCLAVE_BUILD_VERSION environment variable is empty")
	} else {
		logger.WithField("build_version", ed.BuildVersion).Info("Loaded ENCLAVE_BUILD_VERSION")
	}

	ed.ProvenancePath = os.Getenv("ENCLAVE_PROVENANCE_PATH")
	if ed.ProvenancePath == "" {
		logger.Warn("ENCLAVE_PROVENANCE_PATH environment variable is empty")
	} else {
		logger.WithField("provenance_path", ed.ProvenancePath).Info("Loaded ENCLAVE_PROVENANCE_PATH")
	}

	return ed
}

func init() {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)

	cert.SetLogger(logger)
	key.SetLogger(logger)
}

func main() {
	var rootCmd = &cobra.Command{
		Use:          "attestation-proxy",
		Short:        "Attestation API proxy service",
		Run:          runServer,
		SilenceUsage: true,
	}

	// Define command line flags
	rootCmd.Flags().StringVarP(&bindAddress, "bind-address", "a", "127.0.0.1", "Address to bind to")
	rootCmd.Flags().Uint16VarP(&bindPort, "bind-port", "p", 9901, "Port to listen on")
	rootCmd.Flags().StringVarP(&enclaverAddress, "enclaver-address", "A", "127.0.0.1", "Enclaver API endpoint address")
	rootCmd.Flags().Uint16VarP(&enclaverPort, "enclaver-port", "P", 9900, "Enclaver API endpoint port")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (trace, debug, info, warn, error, fatal, panic)")
	rootCmd.Flags().StringVarP(&privateKeyPath, "private-key", "k", "", "Path to private key file")
	rootCmd.Flags().StringVarP(&certificatePath, "certificate", "c", "", "Path to certificate file")

	if err := rootCmd.Execute(); err != nil {
		logger.WithError(err).Fatal("Failed to execute command")
		os.Exit(1)
	}
}

func runServer(cmd *cobra.Command, args []string) {
	// Set log level
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logger.WithError(err).WithField("log_level", logLevel).Fatal("Invalid log level")
	}
	logger.SetLevel(level)

	// Set Enclaver API endpoint
	enclaverEndpoint = fmt.Sprintf("http://%s:%d/v1/attestation", enclaverAddress, enclaverPort)

	// Fiber doesn't have global mode settings like Gin

	// Create Fiber app with custom middleware
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,

		// Faster JSON encoding/decoding with go-json
		JSONEncoder: json.Marshal,
		JSONDecoder: json.Unmarshal,
	})

	// Add request ID middleware that reuses x-request-id header if present
	app.Use(requestid.New(requestid.Config{
		Header:     "x-request-id",
		ContextKey: "requestid",
	}))

	// Custom logging middleware using logrus
	app.Use(fiberLogrusMiddleware())
	app.Use(recover.New())

	// Set up the generic routing handler
	app.Use("*", httpHandler)

	// Initialize enclave data from environment variables
	enclaveData = LoadEnclaveData()

	// Setup file watchers if paths are specified
	var privateKeyWatcher *fsnotify.Watcher
	if privateKeyPath != "" {
		var err error
		privateKeyWatcher, err = key.SetupPrivateKeyWatcher(privateKeyPath)
		if err != nil {
			logger.WithError(err).WithField("path", privateKeyPath).Fatal("Failed to setup private key watcher")
		}
		defer privateKeyWatcher.Close()
	}

	var certificateWatcher *fsnotify.Watcher
	if certificatePath != "" {
		var err error
		certificateWatcher, err = cert.SetupCertificateWatcher(certificatePath)
		if err != nil {
			logger.WithError(err).WithField("path", certificatePath).Fatal("Failed to setup certificate watcher")
		}
		defer certificateWatcher.Close()
	}

	// No need to create HTTP server manually with Fiber

	// Channel to listen for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		logger.WithFields(logrus.Fields{
			"address": bindAddress,
			"port":    bindPort,
		}).Info("Starting HTTP server")

		if err := app.Listen(fmt.Sprintf("%s:%d", bindAddress, bindPort)); err != nil {
			logger.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Wait for interrupt signal
	<-quit
	logger.Info("Shutting down server...")

	// Attempt graceful shutdown
	if err := app.ShutdownWithTimeout(30 * time.Second); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	} else {
		logger.Info("Server gracefully stopped")
	}
}

func fiberLogrusMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		latency := time.Since(start)

		l := logger.WithFields(logrus.Fields{
			"request_id": c.Locals("requestid"),
			"status":     c.Response().StatusCode(),
			"method":     c.Method(),
			"path":       c.Path(),
			"latency":    latency.String(),
		})

		if mode, ok := c.Locals("mode").(string); ok {
			l = l.WithFields(logrus.Fields{
				"mode": mode,
			})

			if nonce, ok := c.Locals("nonce").(string); ok {
				l = l.WithFields(logrus.Fields{
					"nonce": nonce,
				})
			}

			l.Info("HTTP request")
		}

		return err
	}
}

func httpHandler(c *fiber.Ctx) error {
	if c.Path() == ATTESTATION_ENDPOINT_PATH {
		if c.Method() != "GET" {
			return c.SendStatus(http.StatusMethodNotAllowed)
		}
		return directAttestationHandler(c)
	} else {
		// Try to get nonce from request header
		nonce := c.Get(ATTESTATION_NONCE_HEADER)
		if nonce == "" {
			return c.Status(fiber.StatusOK).SendString("")
		} else {
			c.Locals("nonce", nonce[:min(len(nonce), MAX_DATA_LEN)])
			return inlineAttestationHandler(c)
		}
	}
}

func directAttestationHandler(c *fiber.Ctx) error {
	// Get nonce from query parameter, fall back to request header
	nonce := c.Query("nonce")
	if nonce == "" {
		nonce = c.Get(ATTESTATION_NONCE_HEADER)
	}

	c.Locals("mode", "direct")
	if nonce != "" {
		c.Locals("nonce", nonce[:min(len(nonce), MAX_DATA_LEN)])
	}

	c.Set("cache-control", "no-store")

	requestID := c.Locals("requestid").(string)
	if payloadBytes, payloadString, err := getAttestationPayload(requestID, nonce); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	} else {
		if c.Get("accept") == CONTENT_TYPE_OCTET_STREAM || strings.ToLower(c.Query("cbor")) == "true" {
			return c.Status(fiber.StatusOK).Type(CONTENT_TYPE_OCTET_STREAM).Send(payloadBytes)
		} else {
			return c.Status(fiber.StatusOK).SendString(payloadString)
		}
	}
}

func inlineAttestationHandler(c *fiber.Ctx) error {
	c.Locals("mode", "inline")
	requestID := c.Locals("requestid").(string)
	if _, payload, err := getAttestationPayload(requestID, c.Locals("nonce").(string)); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	} else {
		c.Set(ATTESTATION_PAYLOAD_HEADER, payload)
		return c.Status(fiber.StatusOK).SendString("")
	}
}

func getAttestationPayload(requestID, nonce string) ([]byte, string, error) {
	var payloadBytes []byte
	var payloadString string

	// Get current public key content and fingerprints
	publicKey := key.GetPublicKeyContent()
	publicKeyFingerprint := key.GetPublicKeyFingerprint()
	certificateFingerprint := cert.GetCertificateFingerprint()

	// Create JSON payload
	payload := make(map[string]interface{})
	if publicKey != "" {
		payload["public_key"] = publicKey
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}

	// Add user_data if we have enclave data or TLS data
	userData := make(map[string]interface{})

	// Add enclave data if not empty
	if !enclaveData.empty() {
		userData["enclave"] = enclaveData
	}

	// Add TLS data if we have public key or certificate fingerprints
	if publicKeyFingerprint != "" || certificateFingerprint != "" {
		tlsData := make(map[string]interface{})
		if publicKeyFingerprint != "" {
			tlsData["public_key"] = publicKeyFingerprint
		}
		if certificateFingerprint != "" {
			tlsData["certificate"] = certificateFingerprint
		}
		userData["tls"] = tlsData
	}

	// Marshal user_data if we have any data
	if len(userData) > 0 {
		userDataJSON, err := json.Marshal(userData)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"request_id": requestID,
			}).WithError(err).Error("Failed to marshal user_data")
			return payloadBytes, payloadString, fmt.Errorf("Failed to marshal user_data: %w", err)
		}
		payload["user_data"] = base64.StdEncoding.EncodeToString(userDataJSON)
	}

	// Marshal JSON payload
	jsonData, err := json.Marshal(payload)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"request_id": requestID,
		}).WithError(err).Error("Failed to marshal JSON payload")
		return payloadBytes, payloadString, fmt.Errorf("Failed to marshal JSON payload: %w", err)
	}

	// Create HTTP client that ignores proxy settings
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil, // Explicitly ignore proxy settings
		},
		Timeout: 10 * time.Second,
	}

	// Create POST request to localhost:9900
	req, err := http.NewRequest("POST", enclaverEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		logger.WithFields(logrus.Fields{
			"request_id": requestID,
		}).WithError(err).Error("Failed to create HTTP request")
		return payloadBytes, payloadString, fmt.Errorf("Failed to create HTTP request: %w", err)
	}

	// Set content type
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"request_id": requestID,
		}).WithError(err).Error("Failed to send HTTP request")
		return payloadBytes, payloadString, fmt.Errorf("Failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	payloadBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"request_id": requestID,
		}).WithError(err).Error("Failed to read response body")
		return payloadBytes, payloadString, fmt.Errorf("Failed to read response body: %w", err)
	}

	// Check if request was successful
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body := string(payloadBytes)
		body = body[0:min(2048, len(body))]
		logger.WithFields(logrus.Fields{
			"request_id":  requestID,
			"status_code": resp.StatusCode,
			"response":    body,
		}).Error("Attestation request failed")
		return payloadBytes, payloadString, fmt.Errorf("Attestation request failed: %s", body)
	}

	// Encode response body in Base64
	payloadString = base64.StdEncoding.EncodeToString(payloadBytes)

	// Log successful response
	logger.WithFields(logrus.Fields{
		"request_id":    requestID,
		"status_code":   resp.StatusCode,
		"response_size": len(payloadBytes),
		"encoded_size":  len(payloadString),
	}).Info("Attestation request successful")

	return payloadBytes, payloadString, nil
}

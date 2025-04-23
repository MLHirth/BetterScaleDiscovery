package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

type Peer struct {
	UserID   string `json:"user_id"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	PubKey   string `json:"pubkey"`
	PeerID   string `json:"peer_id"`
	LastSeen int64  `json:"last_seen"`
}

type RegisterPayload struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	PubKey string `json:"pubkey"`
	PeerID string `json:"peer_id"`
}

var (
	jwks   *keyfunc.JWKS
	peers  = make(map[string][]Peer) // key: userID
	peerMu sync.RWMutex
)

func main() {
	fmt.Println("🚀 Discovery server running on :8080")
	initJWKS()

	http.HandleFunc("/register-peer", registerPeerHandler)
	http.HandleFunc("/peers", getPeersHandler)

	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil)) // public interface
}

func initJWKS() {
	var err error
	jwksURL := "https://www.googleapis.com/oauth2/v3/certs"
	jwks, err = keyfunc.Get(jwksURL, keyfunc.Options{})
	if err != nil {
		log.Fatalf("❌ Failed to get JWKS: %v", err)
	}
	log.Println("✅ Google JWKS initialized")
}

func extractBearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return parts[1]
}

func validateJWT(tokenStr string) (*jwt.Token, jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, jwks.Keyfunc)
	if err != nil || !token.Valid {
		return nil, nil, fmt.Errorf("invalid token: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["sub"] == nil {
		return nil, nil, fmt.Errorf("invalid claims")
	}
	return token, claims, nil
}

func registerPeerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenStr := extractBearerToken(r.Header.Get("Authorization"))
	_, claims, err := validateJWT(tokenStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	userID := fmt.Sprintf("%v", claims["sub"])

	body, _ := io.ReadAll(r.Body)
	var payload RegisterPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if payload.IP == "" {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		payload.IP = host
	}

	peer := Peer{
		UserID:   userID,
		IP:       payload.IP,
		Port:     payload.Port,
		PubKey:   payload.PubKey,
		PeerID:   payload.PeerID,
		LastSeen: time.Now().Unix(),
	}

	peerMu.Lock()
	defer peerMu.Unlock()

	existing := peers[userID]
	found := false
	for i := range existing {
		if existing[i].PeerID == peer.PeerID {
			existing[i] = peer
			found = true
			break
		}
	}
	if !found {
		existing = append(existing, peer)
	}
	peers[userID] = existing

	log.Printf("%s peer %s (%s:%d)", map[bool]string{true: "🔄 Refreshed", false: "➕ Registered"}[found], peer.PeerID, peer.IP, peer.Port)
	respondWithPeers(w, userID, peer.PeerID)
}

func getPeersHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr := extractBearerToken(r.Header.Get("Authorization"))
	_, claims, err := validateJWT(tokenStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	userID := fmt.Sprintf("%v", claims["sub"])
	peerID := r.URL.Query().Get("peer_id")

	peerMu.RLock()
	defer peerMu.RUnlock()

	visible := []Peer{}
	for _, p := range peers[userID] {
		if peerID == "" || p.PeerID != peerID {
			visible = append(visible, p)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(visible)
}

func respondWithPeers(w http.ResponseWriter, userID string, requestingPeerID string) {
	visible := []Peer{}

	for _, p := range peers[userID] {
		if p.PeerID != requestingPeerID {
			visible = append(visible, p)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"peers": visible,
	})
}

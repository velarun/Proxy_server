package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var proxyConfig ProxyConfig

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// HandleHTTPS handles https traffic by opening tunnel to destination
func HandleHTTPS(w http.ResponseWriter, r *http.Request) {

	ipAddr, _, _ := net.SplitHostPort(r.RemoteAddr)
	if existsBlockedIP(ipAddr) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		log.Println("Too many requests from client blocked Establishing https connection -> ", getIP(r))
		return
	}

	requestCounter := 0
	for _, ip := range lastRequestsIPs {
		if ip == ipAddr {
			requestCounter++
		}
	}

	// Connection limit per minute for client
	if requestCounter > 50 {
		blockedIPs = append(blockedIPs, ipAddr)
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		log.Println("Too many requests from client blocked Establishing https connection -> ", getIP(r))
		return
	}
	lastRequestsIPs = append(lastRequestsIPs, ipAddr)

	// Authorization using http headers
	value := r.Header.Get("Authorization")

	if value != "null" || value != " " {
		if strings.ContainsAny(value, apikey) {
			r.Header.Set("Authorization", proxyConfig.Apikey)
		} else if strings.ContainsAny(value, accesstoken) {
			r.Header.Set("Authorization", proxyConfig.AccessToken)
		} else if strings.ContainsAny(value, basic) {
			r.Header.Set("Authorization", "Basic "+basicAuth(proxyConfig.Username, proxyConfig.Password))
		} else {
			r.Header.Set("Authorization", "null")
		}

		log.Println("Authorization using ", value, "with value ", r.Header.Get("Authorization"))
	}

	destConn, err := net.DialTimeout("tcp", r.Host, 60*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)

}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func main() {
	pwd, _ := os.Getwd()
	jsonFile, err := os.Open(pwd + "/config.json")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Read config.json file successfully")
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	json.Unmarshal(byteValue, &proxyConfig)

	var PEM string
	flag.StringVar(&PEM, "pem", proxyConfig.ServerPem, proxyConfig.CertLocation)

	var KEY string
	flag.StringVar(&KEY, "key", proxyConfig.ServerKey, proxyConfig.CertLocation)

	var proto string
	flag.StringVar(&proto, "proto", "https", "Proxy protocol https")
	flag.Parse()

	if proto != "https" {
		log.Fatal("Protocol should be https")
	}

	go clearLastRequestsIPs()
	go clearBlockedIPs()

	server := &http.Server{
		Addr:    proxyConfig.HTTPSPort,
		Handler: http.HandlerFunc(HandlerHTTPS),

		// Read & write timeout of a http request
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxHeaderBytes: 1 << 20,

		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Fatal(server.ListenAndServeTLS(PEM, KEY))

}

// HandlerHTTPS handles handlerfunc (there is a pb/bug that req is not getting header details properly on handlerfunc from client)
func HandlerHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		HandleHTTPS(w, r)
		log.Println("Established & Served https connection for Client -> ", getIP(r))
	} else {
		http.Error(w, "Blocked non-Https Traffic", http.StatusInternalServerError)
		log.Println("Blocked Establishing & Serving http request for Client -> ", getIP(r))
	}
}

/*
dsproxy.go - Dead Simple Proxy

BSD 2-Clause License

Copyright (c) 2019-2025, Bozhin Zafirov.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  - Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  - Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package main

import (
	"context"
	"crypto/tls"
	"dsproxy/clap"
	"embed"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"html/template"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/rpc"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed static/*
var static embed.FS

/* MutexTransaction runs a callback function in a mutex lock */
func MutexTransaction(mu sync.RWMutex, readWrite bool, callback func(args ...interface{}) error, args ...interface{}) error {
	if readWrite {
		mu.Lock()
		defer mu.Unlock()
	} else {
		mu.RLock()
		defer mu.RUnlock()
	}
	return callback(args...)
}

/* MutexUInt64 specifies an integer with mutex struct */
type MutexUInt64 struct {
	Value uint64       `json:"-"`
	mu    sync.RWMutex `json:"-"`
}

/* Increase integer value by one */
func (m *MutexUInt64) Increase() (ret uint64) {
	MutexTransaction(m.mu, true, func(args ...interface{}) error {
		ret = m.Value
		m.Value++
		return nil
	})
	return
}

/* Decrease integer value by one */
func (m *MutexUInt64) Decrease() (ret uint64) {
	MutexTransaction(m.mu, true, func(args ...interface{}) error {
		ret = m.Value
		m.Value--
		return nil
	})
	return
}

/* Set integer value */
func (m *MutexUInt64) SetValue(value uint64) {
	MutexTransaction(m.mu, true, func(args ...interface{}) error {
		m.Value = value
		return nil
	})
	return
}

/* Read integer value */
func (m MutexUInt64) GetValue() (ret uint64) {
	MutexTransaction(m.mu, false, func(args ...interface{}) error {
		ret = m.Value
		return nil
	})
	return
}

/* GetReset reads and clears value */
func (m *MutexUInt64) GetReset() (ret uint64) {
	MutexTransaction(m.mu, true, func(args ...interface{}) error {
		ret = m.Value
		m.Value = 0
		return nil
	})
	return
}

/* NewMutexUInt64 creates a MutexUInt64 instance */
func NewMutexUInt64() MutexUInt64 {
	return MutexUInt64{
		Value: 0,
		mu:    sync.RWMutex{},
	}
}

/* SSLKeyPair implements GetCertificate */
type SSLKeyPair struct {
	mu      sync.RWMutex
	cert    *tls.Certificate
	crtPath string
	keyPath string
	mtime   time.Time
}

/* reload certificate */
func (kp *SSLKeyPair) reload() error {
	cert, err := tls.LoadX509KeyPair(kp.crtPath, kp.keyPath)
	if err != nil {
		return err
	}
	return MutexTransaction(kp.mu, true, func(args ...interface{}) error {
		kp.cert = &cert
		return nil
	})
}

/* GetCertificate is used by web server to get server certificate */
func (kp *SSLKeyPair) GetCertificate(*tls.ClientHelloInfo) (ret *tls.Certificate, err error) {
	MutexTransaction(kp.mu, false, func(args ...interface{}) error {
		ret = kp.cert
		return nil
	})
	return
}

/* UpdateLoop runs a background process to check for certificate updates */
func (kp *SSLKeyPair) UpdateLoop() error {
	if len(kp.crtPath) == 0 || len(kp.keyPath) == 0 {
		return fmt.Errorf("Certificate and certificate keys must be provided.")
	}
	loop := func() {
		for {
			time.Sleep(time.Minute)
			/* check certificate modification time */
			crtFi, err := os.Stat(kp.crtPath)
			if err != nil {
				fmt.Printf("kp.UpdateLoop: os.Stat: %v\n", err)
				continue
			}
			if crtFi.ModTime().After(kp.mtime) {
				kp.mtime = crtFi.ModTime()
				if err = kp.reload(); err != nil {
					fmt.Printf("kp.UpdateLoop: reload: %v\n", err)
				}
				continue
			}
			/* check certificate key modification time */
			keyFi, err := os.Stat(kp.keyPath)
			if err != nil {
				fmt.Printf("kp.UpdateLoop: os.Stat: %v\n", err)
				continue
			}
			if keyFi.ModTime().After(kp.mtime) {
				kp.mtime = keyFi.ModTime()
				if err = kp.reload(); err != nil {
					fmt.Printf("kp.UpdateLoop: reload: %v\n", err)
				}
				continue
			}
		}
	}
	go loop()
	return nil
}

/* NewSSLKeyPair returns new SSLKeyPair object */
func NewSSLKeyPair(crtPath string, keyPath string) (*SSLKeyPair, error) {
	kp := &SSLKeyPair{
		mu:      sync.RWMutex{},
		crtPath: crtPath,
		keyPath: keyPath,
	}
	if err := kp.reload(); err != nil {
		return nil, err
	}
	return kp, nil
}

/* BackendAddr couples a backend IP address with a counter */
type BackendAddr struct {
	Address string      `json:"address"`
	Counter MutexUInt64 `json:"counter"`
}

/* BackendAddrList automates backend address usage */
type BackendAddrList struct {
	mu        sync.RWMutex  `json:"-"`
	index     MutexUInt64   `json:"index"`
	Addresses []BackendAddr `json:"addresses"`
}

/* GetAddrIndex returns index of specified IP address, -1 if not found */
func (b *BackendAddrList) GetAddrIndex(address string) (ret int) {
	ret = -1
	MutexTransaction(b.mu, false, func(args ...interface{}) error {
		for idx := 0; idx < len(b.Addresses); idx++ {
			if b.Addresses[idx].Address == address {
				ret = idx
				break
			}
		}
		return nil
	})
	return
}

/* Update address list by adding or removing the specified address */
func (b *BackendAddrList) Update(address string, present bool) {
	addrIndex := b.GetAddrIndex(address)
	/* add new address in the list if not yet present */
	if addrIndex == -1 {
		if present {
			MutexTransaction(b.mu, true, func(args ...interface{}) error {
				b.Addresses = append(b.Addresses, BackendAddr{Address: address})
				return nil
			})
		}
		return
	}
	/* address is present in the list, remove it if it shoud not be there */
	if present {
		MutexTransaction(b.mu, true, func(args ...interface{}) error {
			b.Addresses = append(b.Addresses[:addrIndex], b.Addresses[addrIndex+1:]...)
			return nil
		})
	}
}

/* GetInc returns next address from a list and updates stats */
func (b *BackendAddrList) GetInc() (ret string) {
	if len(b.Addresses) == 0 {
		return ""
	}
	MutexTransaction(b.index.mu, true, func(args ...interface{}) error {
		idx := b.index.Value % uint64(len(b.Addresses))
		ret = b.Addresses[idx].Address
		b.Addresses[idx].Counter.Increase()
		b.index.Value++
		return nil
	})
	return
}

/* Backend represents backend server data */
type Backend struct {
	ID       int             `json:"id"`
	Location string          `json:"location"`
	Target   string          `json:"target"`
	AddrList BackendAddrList `json:"addrlist"`
	Counter  MutexUInt64     `json:"counter"`
	Active   bool            `json:"active"`
	Headers  http.Header     `json:"headers"`
}

type BackendList []Backend
type BackendMap map[string]BackendList

/* BackendData mapping for local names to upstream addresses */
type BackendData struct {
	ActiveRequests    MutexUInt64
	RequestsCounter   MutexUInt64
	RequestsPerSecond MutexUInt64
	Backend           BackendMap     `json:"backends"`
	Whitelist         []netip.Prefix `json:"whitelist"`
	mu                sync.RWMutex   `json:"-"`
}

/* update requests per second once every second */
func (b *BackendData) RequestsPerSecondServer() {
	last := uint64(0)
	for {
		current := b.RequestsCounter.GetValue()
		b.RequestsPerSecond.SetValue(current - last)
		last = current
		time.Sleep(time.Second)
	}
}

/* AclAdd adds a new network prefix to the whitelist */
func (b *BackendData) AclAdd(address string) error {
	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return err
	}
	b.Whitelist = append(b.Whitelist, prefix)
	return nil
}

/* AclCheck compares address against ACL list and returns nil if preent */
func (b BackendData) AclCheck(address string) bool {
	/* parse address */
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return false
	}
	/* check acl for address */
	if b.Whitelist != nil {
		for idx := 0; idx < len(b.Whitelist); idx++ {
			if b.Whitelist[idx].Contains(addrPort.Addr()) {
				return true
			}
		}
	}
	return false
}

/* SaveConfiguration stores endpoints configuration to a JSON file */
func (b *BackendData) SaveConfiguration(name string) error {
	return MutexTransaction(b.mu, false, func(args ...interface{}) error {
		/* create configuration file */
		file, err := os.Create(name)
		if err != nil {
			return err
		}
		CloseFile := func() {
			if err := file.Close(); err != nil {
				log.Println(err)
			}
		}
		defer CloseFile()
		encoder := json.NewEncoder(file)
		/* save configuration */
		if err = encoder.Encode(b); err != nil {
			return err
		}
		return nil
	})
}

/* loadConfiguration reads a JSON file containing backend endpoints */
func loadConfiguration(name string) (*BackendData, error) {
	/* initialize backend data */
	b := new(BackendData)
	b.Backend = make(BackendMap)
	b.Whitelist = make([]netip.Prefix, 0)

	/* open configuration file for reading */
	file, err := os.Open(name)
	if err != nil {
		return b, err
	}
	CloseFile := func() {
		if err := file.Close(); err != nil {
			log.Println(err)
		}
	}
	defer CloseFile()
	/* load configuration */
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&b); err != nil {
		return b, err
	}
	return b, nil
}

/* Find an endpoint by looking up Location */
func (b BackendData) Find(host string, location string) (ret int) {
	ret = -1
	MutexTransaction(b.mu, false, func(args ...interface{}) error {
		for idx := 0; idx < len(b.Backend[host]); idx++ {
			if b.Backend[host][idx].Location == location {
				ret = idx
				break
			}
		}
		return nil
	})
	return ret
}

/* SetLocation updates the specified location with a new one */
func (b *BackendData) SetLocation(host string, location string, newPath string) error {
	/* make sure newPath does not yet exist */
	err := MutexTransaction(b.mu, false, func(args ...interface{}) error {
		for idx := 0; idx < len(b.Backend[host]); idx++ {
			if b.Backend[host][idx].Location == newPath {
				/* newPath alread exists, don't update */
				return fmt.Errorf("endpoint %s already exists for host %s.", newPath, host)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	/* lock for update */
	return MutexTransaction(b.mu, true, func(args ...interface{}) error {
		/* perform the update */
		for idx := 0; idx < len(b.Backend[host]); idx++ {
			if b.Backend[host][idx].Location == location {
				b.Backend[host][idx].Location = newPath
				return nil
			}
		}
		return fmt.Errorf("endpoint %s was not found for host %s.", location, host)
	})
}

/* AddressUpdate updates the address list by adding or removing the specified IP address */
func (b *BackendData) AddressUpdate(host string, location string, address string, present bool) error {
	/* check for valid address */
	if len(address) != 0 && address != "-" {
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("invalid address:port pair: %s", address)
		}
	}
	/* lock for update */
	return MutexTransaction(b.mu, true, func(args ...interface{}) error {
		/* perform the update */
		for idx := 0; idx < len(b.Backend[host]); idx++ {
			if b.Backend[host][idx].Location == location {
				b.Backend[host][idx].AddrList.Update(address, present)
				return nil
			}
		}
		return fmt.Errorf("endpoint %s was not found for host %s.", location, host)
	})
}

/* SetTarget updates the upstream for the specified backend with a new one */
func (b *BackendData) SetTarget(host string, location string, newTarget string) error {
	/* lock for update */
	return MutexTransaction(b.mu, true, func(args ...interface{}) error {
		/* perform the update */
		for idx := 0; idx < len(b.Backend[host]); idx++ {
			if b.Backend[host][idx].Location == location {
				b.Backend[host][idx].Target = newTarget
				return nil
			}
		}
		return fmt.Errorf("endpoint %s was not found for host %s.", location, host)
	})
}

/* Remove specified endpoint */
func (b *BackendData) Remove(host string, location string) error {
	/* lock for backend removal */
	return MutexTransaction(b.mu, true, func(args ...interface{}) error {
		/* lookup specified backend by location */
		for idx := 0; idx < len(b.Backend[host]); idx++ {
			if b.Backend[host][idx].Location == location {
				/* remove backend */
				b.Backend[host] = append(b.Backend[host][:idx], b.Backend[host][idx+1:]...)
				/* remove host if there are no more backends */
				if len(b.Backend[host]) == 0 {
					delete(b.Backend, host)
				}
				return nil
			}
		}
		return fmt.Errorf("backend %s was not found for host %s.", location, host)
	})
}

/* Add new backend to the running list */
func (b *BackendData) Add(host string, location string, address string, target string) error {
	if len(host) == 0 {
		return fmt.Errorf("empty hostname not allowed")
	}
	if len(location) == 0 {
		return fmt.Errorf("empty location not allowed")
	}
	if len(address) != 0 && address != "-" {
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("invalid address:port pair: %s", address)
		}
	}
	/* lock for backend addition */
	return MutexTransaction(b.mu, true, func(args ...interface{}) error {
		/* look for existing backend with same location */
		for idx := 0; idx < len(b.Backend[host]); idx++ {
			if b.Backend[host][idx].Location == location {
				return fmt.Errorf("non-unique location path %s for host %s.", location, host)
			}
		}
		/* add the new backend */
		backend := Backend{
			Location: location,
			Target:   target,
			Active:   true,
		}
		if len(address) != 0 {
			backend.AddrList.Update(address, true)
		}
		b.Backend[host] = append(b.Backend[host], backend)
		slices.SortFunc(
			b.Backend[host],
			func(b Backend, a Backend) int {
				if len(a.Location) < len(b.Location) {
					return -1
				}
				if len(a.Location) > len(b.Location) {
					return 1
				}
				return 0
			},
		)
		return nil
	})
}

/* SetActive sets endpoint Active status, returns true on success */
func (b *BackendData) SetActive(host string, location string, active bool, autoCreate bool) (ret bool) {
	MutexTransaction(b.mu, true, func(args ...interface{}) error {
		/* look for existing endpoint and set its status */
		for idx := 0; idx < len(b.Backend[host]); idx++ {
			if b.Backend[host][idx].Location == location {
				b.Backend[host][idx].Active = active
				ret = true
				break
			}
		}
		return nil
	})
	if ret == true {
		return
	}
	/* create endpoint if it does not exists and autoCreate is true */
	if autoCreate {
		fmt.Printf("auto-creating: %s/%s\n", host, location)
		if idx := b.Find(host, "/"); idx != -1 {
			/* attempt to auto-create the new endpoint */
			if err := b.Add(host, location, "-", fmt.Sprintf("%s/%s", b.Backend[host][idx].Target, location)); err != nil {
				return false
			}
			/* copy backend IP addresses */
			for idx := 0; idx < len(b.Backend[host][idx].AddrList.Addresses); idx++ {
				b.AddressUpdate(host, location, b.Backend[host][idx].AddrList.Addresses[idx].Address, true)
			}
			return b.SetActive(host, location, active, false)
		}
	}
	/* endpoint does not exist, return false */
	return false
}

/* HandleProxyRequest performs proxy operation */
func HandleProxyRequestGenerator(timeout time.Duration, static embed.FS, maintenanceFile string, endPoint *BackendData) http.HandlerFunc {
	/* initialize global templates */
	tplNotFound := loadTemplate(static, "static/404.html")
	tplUnavailable := loadTemplate(static, "static/503.html")
	tplMaintenance := tplUnavailable
	/* load custom maintenance page if provided */
	if len(maintenanceFile) != 0 {
		var err error
		tplMaintenance, err = template.ParseFiles(maintenanceFile)
		if err != nil {
			log.Fatal(err)
		}
	}

	/* list of headers that will not be transferred */
	hopHeaders := map[string]bool{
		"connection":          true,
		"keep-alive":          true,
		"proxy-authenticate":  true,
		"proxy-authorization": true,
		"te":                  true,
		"trailers":            true,
		"transfer-encoding":   true,
		"upgrade":             true,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		/* declare variables */
		var err error
		var resp *http.Response

		/* initialize handler */
		endPoint.ActiveRequests.Increase()
		defer endPoint.ActiveRequests.Decrease()

		/* update total requests stats */
		endPoint.RequestsCounter.Increase()

		/* get requested hostname */
		host := strings.Split(r.Host, ":")[0]
		if _, ok := endPoint.Backend[host]; !ok {
			host = "*"
		}

		/* lock endpoint for reading */
		MutexTransaction(endPoint.mu, false, func(args ...interface{}) error {

			/* get backend name */
			var endpoint *Backend
			for idx := range endPoint.Backend[host] {
				/* match beginning of a location */
				location := endPoint.Backend[host][idx].Location
				if location != "/" {
					location = fmt.Sprintf("/%s/", location)
				}
				if strings.HasPrefix(r.URL.String(), location) {
					endpoint = &endPoint.Backend[host][idx]
					break
				}
			}

			/* make sure endpoint exists */
			if endpoint == nil || len(endpoint.Target) == 0 {
				if err := RenderStatus(w, http.StatusNotFound, tplNotFound, r.URL.String()); err != nil {
					log.Println(err)
				}
				return err
			}

			/* check endpoint active status */
			if !endpoint.Active && !endPoint.AclCheck(r.RemoteAddr) {
				/* render maintenance page and exit */
				if err := RenderStatus(w, http.StatusServiceUnavailable, tplMaintenance, r.URL.String()); err != nil {
					log.Println(err)
				}
				return err
			}

			endpoint.Counter.Increase()

			/* make a client and request objects */
			target := fmt.Sprintf(
				"%s/%s",
				strings.TrimRight(endpoint.Target, "/"),
				strings.TrimLeft(
					strings.TrimPrefix(
						strings.TrimLeft(r.URL.String(), "/"),
						endpoint.Location,
					),
					"/",
				),
			)

			/* prepare custom client transport */
			client := http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyFromEnvironment,
					DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
						if addr := endpoint.AddrList.GetInc(); len(addr) != 0 && addr != "-" {
							address = addr
						}
						dialer := &net.Dialer{
							Timeout:   time.Second * time.Duration(timeout),
							KeepAlive: 15 * time.Second,
						}
						return dialer.DialContext(ctx, network, address)
					},
					TLSHandshakeTimeout: 5 * time.Second,
				},
				Timeout: time.Second * time.Duration(timeout),
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			req, err := http.NewRequest(r.Method, target, r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return err
			}
			/* populate request headers */
			for key, headers := range r.Header {
				if skipHeader, ok := hopHeaders[strings.ToLower(key)]; ok {
					if skipHeader {
						continue
					}
				}
				for _, value := range headers {
					req.Header.Add(key, value)
				}
			}
			if len(r.Header.Get("x-forwarded-for")) == 0 {
				req.Header.Add("x-forwarded-for", r.RemoteAddr)
			}

			/* perform proxy request */
			resp, err = client.Do(req)
			if err != nil {
				if err := RenderStatus(w, http.StatusServiceUnavailable, tplUnavailable, r.URL.String()); err != nil {
					log.Println(err)
				}
				return err
			}

			/* close body after job is finished */
			closeBody := func() {
				if err := resp.Body.Close(); err != nil {
					log.Println(err)
				}
			}
			defer closeBody()

			/* copy over all headers from client to backend */
			for key, headers := range resp.Header {
				if skipHeader, ok := hopHeaders[strings.ToLower(key)]; ok {
					if skipHeader {
						continue
					}
				}
				for _, value := range headers {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(resp.StatusCode)

			/* copy data from upstream to client */
			if _, err = io.Copy(w, resp.Body); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return err
			}
			return nil
		})
	}
}

/* RenderStatus is a generic template render with custom status code */
func RenderStatus(w http.ResponseWriter, status int, template *template.Template, what string) error {
	w.WriteHeader(status)
	if err := template.Execute(w, what); err != nil {
		return err
	}
	return nil
}

/* loadTemplate reads and parses named template from embeded storage */
func loadTemplate(storage embed.FS, name string) *template.Template {
	/* read file data */
	data, err := storage.ReadFile(name)
	if err != nil {
		panic(err)
	}
	/* parse and return template */
	return template.Must(
		template.New(name).Parse(string(data)),
	)
}

/* convert duration to human readable string */
func strDuration(duration time.Duration) (strDuration string) {
	/* format duration of up to 1 second */
	nano := duration.Nanoseconds()
	if nano <= 1000000000 {
		suffixList := []string{"ns", "us", "ms", "s"}
		for idx, suffix := range suffixList {
			delimiter := math.Pow(float64(1000.0), float64(idx))
			part := float64(nano) / delimiter
			if part <= 1000.0 {
				return fmt.Sprintf("%.3f%s", part, suffix)
			}
		}
	}
	/* format duration larger than a second */
	secondsList := []uint64{31536000, 86400, 3600, 60, 1}
	suffixList := []string{" years, ", " days, ", "h", "m", "s"}
	durationStarted := false
	for seconds := uint64(duration.Seconds()); seconds != 0; {
		for idx := range secondsList {
			part := uint64(seconds / secondsList[idx])
			if part != 0 {
				strDuration = fmt.Sprintf("%s%02d%s", strDuration, part, suffixList[idx])
				seconds = seconds - part*secondsList[idx]
				durationStarted = true
				continue
			}
			if durationStarted {
				strDuration = fmt.Sprintf("%s00%s", strDuration, suffixList[idx])
			}
		}
	}
	return
}

/* RpcMessage represents a request/response message structure */
type RpcMessage struct {
	Host      string     `json:"host"`
	Location  string     `json:"location"`
	Address   string     `json:"address"`
	Target    string     `json:"target"`
	Payload   string     `json:"payload"`
	Active    bool       `json:"active"`
	Force     bool       `json:"force"`
	Endpoints BackendMap `json:"endpoints"`
	Whitelist []string   `json:"whitelist"`
}

/* RpcBroker defines RPC methods for remote control */
type RpcBroker struct {
	startTime  time.Time
	configFile string
	endPoint   *BackendData
	httpServer *http.Server
	rpcServer  *http.Server
	shutdown   chan bool
}

/* Shutdown stops a running web server */
func (r *RpcBroker) Shutdown(arg *int, reply *int) error {
	r.shutdown <- true
	return nil
}

/* Status returns endpoints status */
func (r *RpcBroker) Status(arg *int, message *RpcMessage) error {
	MutexTransaction(r.endPoint.mu, false, func(args ...interface{}) error {
		message.Endpoints = make(BackendMap)
		for host, backends := range r.endPoint.Backend {
			message.Endpoints[host] = make(BackendList, len(backends))
			copy(message.Endpoints[host], backends)
		}
		message.Whitelist = make([]string, len(r.endPoint.Whitelist))
		for idx := 0; idx < len(r.endPoint.Whitelist); idx++ {
			message.Whitelist[idx] = r.endPoint.Whitelist[idx].String()
		}
		return nil
	})
	message.Payload = fmt.Sprintf(
		"uptime: %s   total: %d   rate: %d/s",
		strDuration(time.Now().Sub(r.startTime)),
		r.endPoint.RequestsCounter.GetValue(),
		r.endPoint.RequestsPerSecond.GetValue(),
	)
	return nil
}

/* SetActive activates or deactivates a proxy endpoint */
func (r *RpcBroker) SetActive(msg *RpcMessage, reply *int) error {
	if r.endPoint.SetActive(msg.Host, msg.Location, msg.Active, msg.Force) {
		if err := r.endPoint.SaveConfiguration(r.configFile); err != nil {
			return err
		}
	}
	return nil
}

/* Add a new endpoint to the proxy server */
func (r *RpcBroker) Add(msg *RpcMessage, reply *int) error {
	if err := r.endPoint.Add(msg.Host, msg.Location, msg.Address, msg.Target); err != nil {
		return err
	}
	if err := r.endPoint.SaveConfiguration(r.configFile); err != nil {
		return err
	}
	return nil
}

/* Remove existing endpoint from the proxy server */
func (r *RpcBroker) Remove(msg *RpcMessage, reply *int) error {
	if err := r.endPoint.Remove(msg.Host, msg.Location); err != nil {
		return err
	}
	if err := r.endPoint.SaveConfiguration(r.configFile); err != nil {
		return err
	}
	return nil
}

/* EditHost changes endpoint host */
func (r *RpcBroker) EditHost(msg *RpcMessage, reply *int) error {
	var idx int
	if idx = r.endPoint.Find(msg.Host, msg.Location); idx == -1 {
		return fmt.Errorf("backend %s for host %s does not exist.", msg.Location, msg.Host)
	}
	endpoint := r.endPoint.Backend[msg.Host][idx]
	if err := r.endPoint.Remove(msg.Host, msg.Location); err != nil {
		fmt.Printf("oops\n")
		return err
	}
	if err := r.endPoint.Add(msg.Payload, msg.Location, msg.Address, endpoint.Target); err != nil {
		return err
	}
	if err := r.endPoint.SaveConfiguration(r.configFile); err != nil {
		return err
	}
	return nil
}

/* EditLocation changes location of an endpoint */
func (r *RpcBroker) EditLocation(msg *RpcMessage, reply *int) error {
	var idx int
	if idx = r.endPoint.Find(msg.Host, msg.Location); idx == -1 {
		return fmt.Errorf("backend %s for host %s does not exist.", msg.Location, msg.Host)
	}
	if err := r.endPoint.SetLocation(msg.Host, msg.Location, msg.Payload); err != nil {
		return err
	}
	if err := r.endPoint.SaveConfiguration(r.configFile); err != nil {
		return err
	}
	return nil
}

/* AddressAdd adds specified IP address to an endpoint */
func (r *RpcBroker) AddressAdd(msg *RpcMessage, reply *int) error {
	var idx int
	if idx = r.endPoint.Find(msg.Host, msg.Location); idx == -1 {
		return fmt.Errorf("backend %s for host %s does not exist.", msg.Location, msg.Host)
	}
	if err := r.endPoint.AddressUpdate(msg.Host, msg.Location, msg.Address, true); err != nil {
		return err
	}
	if err := r.endPoint.SaveConfiguration(r.configFile); err != nil {
		return err
	}
	return nil
}

/* AddressRemove removes specified IP address from an endpoint */
func (r *RpcBroker) AddressRemove(msg *RpcMessage, reply *int) error {
	var idx int
	if idx = r.endPoint.Find(msg.Host, msg.Location); idx == -1 {
		return fmt.Errorf("backend %s for host %s does not exist.", msg.Location, msg.Host)
	}
	if err := r.endPoint.AddressUpdate(msg.Host, msg.Location, msg.Address, false); err != nil {
		return err
	}
	if err := r.endPoint.SaveConfiguration(r.configFile); err != nil {
		return err
	}
	return nil
}

/* EditTarget changes upstream address of an endpoint */
func (r *RpcBroker) EditTarget(msg *RpcMessage, reply *int) error {
	var idx int
	if idx = r.endPoint.Find(msg.Host, msg.Location); idx == -1 {
		return fmt.Errorf("backend %s for host %s does not exist.", msg.Location, msg.Host)
	}
	if err := r.endPoint.SetTarget(msg.Host, msg.Location, msg.Payload); err != nil {
		return err
	}
	if err := r.endPoint.SaveConfiguration(r.configFile); err != nil {
		return err
	}
	return nil
}

/* ProxyPID returns pid of currently running dsproxy service */
func (r *RpcBroker) ProxyPID(args *int, pid *int) error {
	*pid = os.Getpid()
	return nil
}

/* AclList returns list of all CIDR records in the ACL */
func (r *RpcBroker) AclList(args *int, reply *[]string) error {
	for idx := range r.endPoint.Whitelist {
		*reply = append(*reply, r.endPoint.Whitelist[idx].String())
	}
	return nil
}

/* AclAddr appends a cidr address to the ACL list */
func (r *RpcBroker) AclAdd(cidr *string, reply *int) error {
	/* convert address to network */
	prefix, err := netip.ParsePrefix(*cidr)
	if err != nil {
		return err
	}
	/* do nothing if acl entry already exists */
	for idx := range r.endPoint.Whitelist {
		if r.endPoint.Whitelist[idx] == prefix {
			return fmt.Errorf("cidr address %s already exists.", *cidr)
		}
	}
	/* append address to the acl */
	r.endPoint.Whitelist = append(r.endPoint.Whitelist, prefix)
	if err := r.endPoint.SaveConfiguration(r.configFile); err != nil {
		return err
	}
	return nil
}

/* AclRemove deletes a cidr record from the ACL whitelist */
func (r *RpcBroker) AclRemove(element *string, reply *int) error {
	for idx := range r.endPoint.Whitelist {
		if r.endPoint.Whitelist[idx].String() == *element {
			r.endPoint.Whitelist = append(r.endPoint.Whitelist[:idx], r.endPoint.Whitelist[idx+1:]...)
			if err := r.endPoint.SaveConfiguration(r.configFile); err != nil {
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("%s not found in whitelist.", *element)
}

/* Clear hits statistics */
func (r *RpcBroker) Clear(request *int, reply *int) error {
	return MutexTransaction(r.endPoint.mu, true, func(args ...interface{}) error {
		for _, backends := range r.endPoint.Backend {
			for idx := range backends {
				backends[idx].Counter.SetValue(0)
			}
		}
		return nil
	})
}

/* Max returns the larger integer from a and b */
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

/* cmdListBackendsFunc prints a list with all backends on the terminal */
func cmdListBackendsFunc(m *RpcMessage, filter string) {
	var (
		hostLen     int
		countLen    int
		locationLen int
		upstreamLen int
		addressLen  int
	)
	/* calculate max elements lenghts */
	for host, backends := range m.Endpoints {
		if len(filter) != 0 && !strings.Contains(host, filter) {
			continue
		}
		hostLen = Max(Max(hostLen, len(host)), 4)
		for idx := range backends {
			countLen = Max(Max(countLen, len(strconv.FormatUint(backends[idx].Counter.GetValue(), 10))), 5)
			locationLen = Max(Max(locationLen, len(backends[idx].Location)), 8)
			upstreamLen = Max(Max(upstreamLen, len(backends[idx].Target)), 6)
			for beIdx := 0; beIdx < len(backends[idx].AddrList.Addresses); beIdx++ {
				addressLen = Max(Max(addressLen, len(backends[idx].AddrList.Addresses[beIdx].Address)), 7)
			}
		}
	}
	/* build format string */
	hdrFormatStr := fmt.Sprintf(
		"  \033[01;33m%%%ds  %%-%ds  %%-%ds  %%%ds  %%-%ds  %%-12s\033[00m\n",
		hostLen,
		locationLen,
		upstreamLen,
		addressLen,
		countLen,
	)
	formatStr := fmt.Sprintf(
		"  \033[01;36m%%%ds\033[00m  %%-%ds  %%-%ds  \033[01;36m%%%ds\033[00m  %%-%dd  %%-12s\n",
		hostLen,
		locationLen,
		upstreamLen,
		addressLen,
		countLen,
	)
	addrStr := fmt.Sprintf(
		"        \033[01;36m%%%-ds\033[00m  %%d\n",
		hostLen+locationLen+upstreamLen+addressLen,
	)
	/* mapping between bool value and console message */
	activeMap := map[bool]string{
		false: "\033[01;31mmaintenance\033[00m",
		true:  "\033[01;32mactive\033[00m",
	}
	/* get a sorted list of hosts for stable endpoints order */
	keys := make([]string, len(m.Endpoints))
	for k, _ := range m.Endpoints {
		if len(filter) != 0 && !strings.Contains(k, filter) {
			continue
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	/* print list of backends */
	fmt.Printf(hdrFormatStr, "Host", "Location", "Target", "Address", "Count", "Status")
	for _, host := range keys {
		backends := m.Endpoints[host]
		for idx := range backends {
			primaryAddress := "-"
			if len(backends[idx].AddrList.Addresses) != 0 {
				primaryAddress = backends[idx].AddrList.Addresses[0].Address
			}
			/* print endpoint stats */
			fmt.Printf(
				formatStr,
				host,
				backends[idx].Location,
				backends[idx].Target,
				primaryAddress,
				backends[idx].Counter.Value,
				activeMap[backends[idx].Active],
			)
			/* print addresses stats */
			for addrIdx := 1; addrIdx < len(backends[idx].AddrList.Addresses); addrIdx++ {
				fmt.Printf(
					addrStr,
					backends[idx].AddrList.Addresses[addrIdx].Address,
					backends[idx].AddrList.Addresses[addrIdx].Counter.GetValue(),
				)
			}
		}
	}
	fmt.Printf("  \033[01;38m%s\033[00m\n", m.Payload)
}

/* RpcClient returns connected rpc.Client object */
func RpcClient(socket string) *rpc.Client {
	client, err := rpc.DialHTTP("unix", socket)
	if err != nil {
		log.Fatal(err)
	}
	return client
}

/* startRpcService initializes and starts RPC for remote control */
func startRpcService(config string, rpcSocket string, httpServer *http.Server, shutdown chan bool, endPoint *BackendData) (*http.Server, error) {
	/* check for unix domain socket */
	if _, err := os.Stat(rpcSocket); err == nil {
		/* attempt to connect to socket */
		if client, err := rpc.DialHTTP("unix", rpcSocket); err == nil {
			var pid int
			if err := client.Call("RpcBroker.ProxyPID", 0, &pid); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("dsproxy already running on pid %d.", pid)
		}
		/* remove socket file */
		if err := os.Remove(rpcSocket); err != nil {
			return nil, err
		}
	}

	/* prepare new rpc server */
	rpcSrv := rpc.NewServer()

	/* prepare new rpc http server */
	rpcServer := &http.Server{
		Handler: rpcSrv,
	}

	/* prepare and register rpc broker */
	broker := &RpcBroker{
		startTime:  time.Now(),
		configFile: config,
		endPoint:   endPoint,
		httpServer: httpServer,
		rpcServer:  rpcServer,
		shutdown:   shutdown,
	}
	/* listen on a unix domain socket */
	sock, err := net.Listen("unix", rpcSocket)
	if err != nil {
		log.Fatal(err)
	}
	/* prepare and start rpc server */
	if err := rpcSrv.Register(broker); err != nil {
		return nil, err
	}
	rpcSrv.HandleHTTP(rpc.DefaultRPCPath, rpc.DefaultDebugPath)
	go rpcServer.Serve(sock)
	return rpcServer, nil
}

/* main program */
func main() {
	/* initialize global variables */
	sslCertificate := clap.String(0, "ssl-certificate", "", "SSL Certificate file", false)
	sslCertificateKey := clap.String(0, "ssl-certificate-key", "", "SSL Certificate Key file", false)
	bindAddress := clap.String('b', "bind-address", ":8000", "Address and port to bind proxy [default :8000]", false)
	requestTimeout := clap.Int('t', "request-timeout", 5, "Request timeout in seconds [default 5]", false)
	maintenancePage := clap.String('m', "maintenance", "", "Path to maintenance html page", false)
	configurationFile := clap.String(
		'c',
		"config",
		"dsproxy.json",
		"Endpoints configuration file [default dsproxy.json]",
		false,
	)
	cmdServer := clap.Bool('s', "server", false, "Start dsproxy server", false)
	cmdAutoCreate := clap.Bool(0, "auto-create", false, "Auto create endpoint on deactivate if possible", false)
	cmdActivate := clap.Bool('a', "activate", false, "Set backend to active state", false)
	cmdDeactivate := clap.Bool('d', "deactivate", false, "Set backend to maintenance state", false)
	cmdAdd := clap.Bool(0, "add", false, "Create new endpoint", false)
	cmdRemove := clap.Bool('r', "remove", false, "Remove existing endpoint", false)
	cmdEditHost := clap.String(0, "edit-host", "", "Update specified host", false)
	cmdEditLocation := clap.String(0, "edit-location", "", "Update specified endpoint location", false)
	cmdAddressAdd := clap.String(0, "address-add", "", "Add specified endpoint IP address", false)
	cmdAddressRemove := clap.String(0, "address-remove", "", "Remove specified endpoint IP address", false)
	cmdEditTarget := clap.String(0, "edit-target", "", "Update specified upstream URL", false)
	cmdHost := clap.String(0, "host", "*", "Host address for backend", false)
	cmdLocation := clap.String('l', "location", "", "Specify endpoint location", false)
	cmdAddress := clap.String(0, "address", "-", "Specify endpoint IP address", false)
	cmdTarget := clap.String(0, "target", "", "Endpoint target address", false)
	cmdFilter := clap.String('f', "filter", "", "Filter output by host names when listing endpoints", false)
	cmdAclList := clap.Bool(0, "acl-list", false, "List whitelisted networks", false)
	cmdAclAdd := clap.String(0, "acl-add", "", "Add cidr to the acl whitelist", false)
	cmdAclRemove := clap.String(0, "acl-remove", "", "Remove cidr from the acl whitelist", false)
	cmdClear := clap.Bool(0, "clear", false, "Clear hits statistics", false)
	cmdShutdown := clap.Bool(0, "shutdown", false, "Shutdown current dsproxy instance", false)
	rpcSocket := clap.String(
		0,
		"rpc-socket",
		"/tmp/dsproxy.sock",
		"Unix domain socket for RPC communication [default /tmp/dsproxy.sock]",
		false,
	)
	clap.Parse()

	/* handle cmd commands */
	var reply int
	switch {
	case *cmdServer:
		/* initialize endpoint */
		endPoint, err := loadConfiguration(*configurationFile)
		if err != nil {
			log.Println(err)
		}
		/* start requests per second statistics server */
		go endPoint.RequestsPerSecondServer()

		/* prepare server configuration */
		shutdown := make(chan bool)
		httpServer := &http.Server{
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
			Addr:         *bindAddress,
			Handler: HandleProxyRequestGenerator(
				time.Duration(*requestTimeout),
				static,
				*maintenancePage,
				endPoint,
			),
		}
		/* start rpc socket listener */
		rpcServer, err := startRpcService(*configurationFile, *rpcSocket, httpServer, shutdown, endPoint)
		if err != nil {
			log.Fatal(err)
		}
		/* configure SSL certificate key reloader */
		var kp *SSLKeyPair
		/* start http server */
		startHttpServer := func() {
			if len(*sslCertificate) != 0 && len(*sslCertificateKey) != 0 {
				/* cofigure SSL certificate reloader */
				kp, err = NewSSLKeyPair(*sslCertificate, *sslCertificateKey)
				if err != nil {
					log.Fatal(err)
				}
				httpServer.TLSConfig = &tls.Config{
					GetCertificate: kp.GetCertificate,
				}
				/* listen config */
				lc := &net.ListenConfig{
					Control: func(network string, address string, conn syscall.RawConn) (opErr error) {
						err := conn.Control(
							func(fd uintptr) {
								opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
							},
						)
						if err != nil {
							return err
						}
						return
					},
				}
				/* initialize listener */
				ln, err := lc.Listen(context.Background(), "tcp", httpServer.Addr)
				if err != nil {
					log.Fatal(err)
				}
				/* start certificate checks */
				if err = kp.UpdateLoop(); err != nil {
					log.Fatal(err)
				}
				/* start ssl server */
				if err := httpServer.ServeTLS(ln, "", ""); err != http.ErrServerClosed {
					log.Fatal(err)
				}
			} else {
				/* start http server */
				if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
					log.Fatal(err)
				}
			}
		}
		go startHttpServer()

		/* wait for shutdown command */
		<-shutdown
		if err := httpServer.Shutdown(context.Background()); err != nil {
			log.Fatal(err)
		}
		if err := rpcServer.Shutdown(context.Background()); err != nil {
			log.Fatal(err)
		}
		return
	case *cmdShutdown:
		if err := RpcClient(*rpcSocket).Call("RpcBroker.Shutdown", 0, &reply); err != nil {
			log.Fatal(err)
		}
		return
	case *cmdClear:
		if err := RpcClient(*rpcSocket).Call("RpcBroker.Clear", 0, &reply); err != nil {
			log.Fatal(err)
		}
		return
	case *cmdAdd:
		req := RpcMessage{
			Host:     *cmdHost,
			Location: *cmdLocation,
			Address:  *cmdAddress,
			Target:   *cmdTarget,
		}
		if err := RpcClient(*rpcSocket).Call("RpcBroker.Add", &req, &reply); err != nil {
			log.Fatal(err)
		}
		return
	case *cmdRemove:
		req := RpcMessage{
			Host:     *cmdHost,
			Location: *cmdLocation,
		}
		if err := RpcClient(*rpcSocket).Call("RpcBroker.Remove", &req, &reply); err != nil {
			log.Fatal(err)
		}
		return
	case len(*cmdEditHost) != 0:
		req := RpcMessage{
			Host:     *cmdHost,
			Location: *cmdLocation,
			Payload:  *cmdEditHost,
		}
		if err := RpcClient(*rpcSocket).Call("RpcBroker.EditHost", &req, &reply); err != nil {
			log.Fatal(err)
		}
		return
	case len(*cmdEditLocation) != 0:
		req := RpcMessage{
			Host:     *cmdHost,
			Location: *cmdLocation,
			Payload:  *cmdEditLocation,
		}
		if err := RpcClient(*rpcSocket).Call("RpcBroker.EditLocation", &req, &reply); err != nil {
			log.Fatal(err)
		}
		return
	case len(*cmdAddressAdd) != 0:
		req := RpcMessage{
			Host:     *cmdHost,
			Location: *cmdLocation,
			Address:  *cmdAddressAdd,
			Payload:  *cmdEditLocation,
		}
		if err := RpcClient(*rpcSocket).Call("RpcBroker.AddressAdd", &req, &reply); err != nil {
			log.Fatal(err)
		}
		return
	case len(*cmdAddressRemove) != 0:
		req := RpcMessage{
			Host:     *cmdHost,
			Location: *cmdLocation,
			Address:  *cmdAddressRemove,
			Payload:  *cmdEditLocation,
		}
		if err := RpcClient(*rpcSocket).Call("RpcBroker.AddressRemove", &req, &reply); err != nil {
			log.Fatal(err)
		}
		return
	case len(*cmdEditTarget) != 0:
		req := RpcMessage{
			Host:     *cmdHost,
			Location: *cmdLocation,
			Payload:  *cmdEditTarget,
		}
		if err := RpcClient(*rpcSocket).Call("RpcBroker.EditTarget", &req, &reply); err != nil {
			log.Fatal(err)
		}
		return
	case *cmdActivate:
		req := RpcMessage{
			Host:     *cmdHost,
			Location: *cmdLocation,
			Active:   true,
			Force:    *cmdAutoCreate,
		}
		if err := RpcClient(*rpcSocket).Call("RpcBroker.SetActive", &req, &reply); err != nil {
			log.Fatal(err)
		}
		return
	case *cmdDeactivate:
		req := RpcMessage{
			Host:     *cmdHost,
			Location: *cmdLocation,
			Active:   false,
			Force:    *cmdAutoCreate,
		}
		if err := RpcClient(*rpcSocket).Call("RpcBroker.SetActive", &req, &reply); err != nil {
			log.Fatal(err)
		}
		return
	case *cmdAclList:
		var whitelist []string
		if err := RpcClient(*rpcSocket).Call("RpcBroker.AclList", 0, &whitelist); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("ACL Networks:\n")
		for idx := range whitelist {
			fmt.Printf("  %s\n", whitelist[idx])
		}
		return
	case len(*cmdAclAdd) != 0:
		if err := RpcClient(*rpcSocket).Call("RpcBroker.AclAdd", *cmdAclAdd, &reply); err != nil {
			log.Fatal(err)
		}
		return
	case len(*cmdAclRemove) != 0:
		if err := RpcClient(*rpcSocket).Call("RpcBroker.AclRemove", cmdAclRemove, &reply); err != nil {
			log.Fatal(err)
		}
		return
	default:
		var msg RpcMessage
		if err := RpcClient(*rpcSocket).Call("RpcBroker.Status", 0, &msg); err != nil {
			log.Fatal(err)
		}
		cmdListBackendsFunc(&msg, *cmdFilter)
		return
	}

}

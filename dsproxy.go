// dsproxy.go - Dead Simple Proxy
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// -- MutexInt64 specifies an integer with mutex struct
type MutexInt64 struct {
	Value int64
	Mu    *sync.RWMutex
}

// Increase integer value by one
func (m *MutexInt64) Increase() {
	m.Mu.Lock()
	m.Value = m.Value + 1
	m.Mu.Unlock()
}

// Decrease integer value by one
func (m *MutexInt64) Decrease() {
	m.Mu.Lock()
	m.Value = m.Value - 1
	m.Mu.Unlock()
}

// Set integer value
func (m *MutexInt64) SetValue(value int64) {
	m.Mu.Lock()
	m.Value = value
	m.Mu.Unlock()
}

// Read integer value
func (m MutexInt64) GetValue() int64 {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	return m.Value
}

// NewMutexInt64 creates a MutexInt64 instance
func NewMutexInt64() MutexInt64 {
	return MutexInt64{
		Value: 0,
		Mu:    &sync.RWMutex{},
	}
}

// EndPointBackend represents backend server data
type EndPointBackend struct {
	LocalPath string
	Upstream  string
	Headers   http.Header
}

// EndPointData mapping for local names to upstream addresses
type EndPointData struct {
	Backend []EndPointBackend
	Mu      sync.RWMutex
}

/* Get endpoint index from global variable */
func (e EndPointData) Get(name string) int {
	for idx := range e.Backend {
		if strings.Compare(EndPoint.Backend[idx].LocalPath, name) == 0 {
			return idx
		}
	}
	return -1
}

// global variables
var (
	ServerStart       time.Time
	ContentType       string
	BindAddress       string
	RequestTimeout    int
	ActiveRequests    MutexInt64
	TotalRequests     MutexInt64
	RequestsPerSecond MutexInt64
	EndPoint          EndPointData
)

// HandleStats renders statistics page
func HandleStatistics(w http.ResponseWriter, _ *http.Request) {
	// update active requests stats
	ActiveRequests.Increase()
	defer ActiveRequests.Decrease()

	// update total requests stats
	TotalRequests.Increase()

	// Lock EndPoint for reading
	EndPoint.Mu.RLock()
	defer EndPoint.Mu.RUnlock()

	// define statistics data structure
	type StatsData struct {
		ActiveRequests    int64
		RequestsPerSecond int64
		TotalRequests     int64
		ServerUptime      string
		Backend           []EndPointBackend
	}

	// prepare statistics data
	Data := StatsData{
		ActiveRequests.GetValue(),
		RequestsPerSecond.GetValue(),
		TotalRequests.GetValue(),
		time.Since(ServerStart).Round(time.Second).String(),
		EndPoint.Backend,
	}

	// render statistics information in plain text
	if err := RenderStats(w, Data); err != nil {
		log.Println(err)
	}

	return
}

// HandleSetEndpoint changes or sets currently active endpoint
func HandleSetEndpoint(w http.ResponseWriter, r *http.Request) {
	// update active requests stats
	ActiveRequests.Increase()
	defer ActiveRequests.Decrease()

	// update total requests stats
	TotalRequests.Increase()

	// get endpoint name
	name, ok := r.URL.Query()["name"]
	if !ok || len(name) < 1 {
		http.Error(
			w,
			"Bad Request",
			http.StatusBadRequest,
		)
		return
	}

	// get endpoint address
	address, ok := r.URL.Query()["address"]
	if !ok || len(address) < 1 {
		http.Error(
			w,
			"Bad Request",
			http.StatusBadRequest,
		)
		return
	}

	// change existing endpoint
	EndPoint.Mu.Lock()
	defer EndPoint.Mu.Unlock()
	for idx, endpoint := range EndPoint.Backend {
		if strings.Compare(endpoint.LocalPath, name[0]) == 0 {
			// lock EndPoint for writing
			EndPoint.Backend[idx].Upstream = address[0]
			_, err := fmt.Fprintf(
				w,
				"Updated endpoint for %s with backend %s\n",
				name[0],
				address[0],
			)
			if err != nil {
				log.Println(err)
			}
			return
		}
	}
	// add new endpoint to list
	EndPoint.Backend = append(
		EndPoint.Backend,
		EndPointBackend{
			name[0],
			address[0],
			make(http.Header),
		},
	)

	if _, err := fmt.Fprintf(w, "New endpoint for %s: %s\n", name[0], address[0]); err != nil {
		log.Println(err)
	}
}

// HandleProxyRequest performs proxy operation
func HandleProxyRequest(w http.ResponseWriter, r *http.Request) {
	// declare variables
	var err error
	var resp *http.Response

	if strings.HasPrefix(r.URL.String(), "/_control/") {
		// do nothing here
		return
	}

	// initialize handler
	ActiveRequests.Increase()
	defer ActiveRequests.Decrease()

	// update total requests stats
	TotalRequests.Increase()

	// lock endpoint for reading
	EndPoint.Mu.RLock()
	defer EndPoint.Mu.RUnlock()

	// get backend name
	var endpoint EndPointBackend
	for _, ep := range EndPoint.Backend {
		if strings.HasPrefix(r.URL.String(), fmt.Sprintf("/%s", ep.LocalPath)) {
			endpoint = ep
			break
		}
	}

	// make sure endpoint exists
	if len(endpoint.Upstream) == 0 {
		if err := Render404(w, r.URL.String()); err != nil {
			log.Println(err)
		}
		//http.Error(w, "Endpoint Not Found", http.StatusNotFound)
		return
	}

	UrlString := strings.TrimPrefix(r.URL.String(), fmt.Sprintf("/%s", endpoint.LocalPath))

	// handle GET requests
	if r.Method == http.MethodGet {
		client := http.Client{Timeout: time.Second * 5}
		resp, err = client.Get(endpoint.Upstream + UrlString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// handle POST requests
	if r.Method == http.MethodPost {
		resp, err = http.Post(endpoint.Upstream, "application/xml", r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// close body after job is finished
	CloseBody := func() {
		if err := resp.Body.Close(); err != nil {
			log.Println(err)
		}
	}
	defer CloseBody()

	// copy over all headers from client to backend
	for key, headers := range r.Header {
		for _, value := range headers {
			w.Header().Add(key, value)
		}
	}
	// append additional headers whenever necessary
	if endpoint.Headers != nil {
		for key, headers := range endpoint.Headers {
			for _, value := range headers {
				w.Header().Set(key, value)
			}
		}
	}

	// copy data from upstream to client
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// print debug stats
	if false {
		fmt.Println("payload size:", n)
	}
}

/* HandleRemoveEndpoint deletes an endpoint from the endpoints list */
func HandleRemoveEndpoint(w http.ResponseWriter, r *http.Request) {
	// get endpoint name
	name, ok := r.URL.Query()["name"]
	if !ok || len(name) < 1 {
		http.Error(
			w,
			"Bad Request",
			http.StatusBadRequest,
		)
		return
	}
	// lock endpoint data structure for writing
	EndPoint.Mu.Lock()
	defer EndPoint.Mu.Unlock()
	// remove endpoint configuration
	for i := range EndPoint.Backend {
		fmt.Println("DEBUG:", EndPoint.Backend[i].LocalPath)
		if strings.Compare(name[0], EndPoint.Backend[i].LocalPath) == 0 {
			EndPoint.Backend[i] = EndPoint.Backend[len(EndPoint.Backend)-1]
			EndPoint.Backend = EndPoint.Backend[:len(EndPoint.Backend)-1]
			http.Redirect(w, r, "/_control/stats", http.StatusFound)
			return
		}
	}
	// not found, render error
	if err := Render404(w, name[0]); err != nil {
		log.Println(err)
	}
}

/* HandleEditEndpoint renders a form to edit endpoint parameters */
func HandleEditEndpoint(w http.ResponseWriter, r *http.Request) {
	// get endpoint name
	name, ok := r.URL.Query()["name"]
	if !ok || len(name) < 1 {
		http.Error(
			w,
			"Bad Request",
			http.StatusBadRequest,
		)
		return
	}
	// lock endpoint data structure for writing
	EndPoint.Mu.Lock()
	defer EndPoint.Mu.Unlock()
	// look up endpoint index
	idx := EndPoint.Get(name[0])
	if idx == -1 {
		if err := Render404(w, name[0]); err != nil {
			log.Println(err)
		}
		return
	}
	// handle POST requests
	if r.Method == http.MethodPost {
		// parse http form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// check address
		address := r.FormValue("address")
		if len(address) == 0 {
			http.Error(w, "Bad Request", http.StatusBadRequest)
		}
		EndPoint.Backend[idx].Upstream = address
		http.Redirect(w, r, "/_control/stats", http.StatusFound)
		return
	}
	// render endpoint edit form
	if err := RenderEdit(w, EndPoint.Backend[idx]); err != nil {
		log.Println(err)
	}
}

// initialize program variables
func init() {
	// initialize endpoint
	EndPoint.Backend = []EndPointBackend{
		{
			"default",
			"https://www.google.com",
			make(http.Header),
		},
	}

	// initialize global variables
	flag.StringVar(
		&ContentType,
		"content-type",
		"application/xml",
		"Specify POST request content type",
	)
	flag.StringVar(
		&BindAddress,
		"bind-address",
		":8000",
		"Address and port to bind proxy",
	)
	flag.IntVar(
		&RequestTimeout,
		"request-timeout",
		3000,
		"Request timeout in milliseconds",
	)

	// initialize server start time
	ServerStart = time.Now()

	// initialize global counters
	ActiveRequests = NewMutexInt64()
	TotalRequests = NewMutexInt64()
	RequestsPerSecond = NewMutexInt64()
}

// update requests per second once every second
func RequestsPerSecondServer() {
	active := TotalRequests.GetValue()
	for {
		time.Sleep(time.Second)
		current := TotalRequests.GetValue()
		RequestsPerSecond.SetValue(current - active)
		active = current
	}
}

// main program
func main() {
	flag.Parse()
	mux := http.NewServeMux()
	// attach server handlers
	mux.HandleFunc(
		"/_control/endpoint",
		HandleSetEndpoint,
	)
	mux.HandleFunc(
		"/_control/stats",
		HandleStatistics,
	)
	mux.HandleFunc(
		"/_control/remove",
		HandleRemoveEndpoint,
	)
	mux.HandleFunc(
		"/_control/edit",
		HandleEditEndpoint,
	)
	mux.HandleFunc(
		"/",
		HandleProxyRequest,
	)
	// start requests per second statistics server
	go RequestsPerSecondServer()
	// bind to server port and listen for connections
	if err := http.ListenAndServe(BindAddress, mux); err != nil {
		log.Fatal(err)
	}
}

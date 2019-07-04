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
	"text/template"
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

// -- MutexString specifies a string protected with mutex
type MutexString struct {
	Value string
	Mu    sync.RWMutex
}

// GetValue safely returns string value with read lock
func (m *MutexString) GetValue() string {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	return m.Value
}

// SetValue safely changes value of MutexString
func (m *MutexString) SetValue(value string) {
	m.Mu.Lock()
	m.Value = value
	m.Mu.Unlock()
}

// -- EndPoint variable that c
var EndPoint struct {
	Upstream MutexString
	Headers  http.Header
	Mu       sync.RWMutex
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
)

// HandleStats renders statistics page
func HandleStatistics(w http.ResponseWriter, _ *http.Request) {
	// update active requests stats
	ActiveRequests.Increase()
	defer ActiveRequests.Decrease()

	// update total requests stats
	TotalRequests.Increase()

	// define statistics data structure
	type StatsData struct {
		ActiveRequests    int64
		RequestsPerSecond int64
		TotalRequests     int64
		ServerUptime      string
		ActiveEndpoint    string
	}

	// prepare statistics page template
	TemplateStats := `Dead Simple Proxy, Statistics Page
----------------------------------

Active Requests     : {{ .ActiveRequests }}
Requests per Second : {{ .RequestsPerSecond }}
Total Requests      : {{ .TotalRequests }}
Server Uptime       : {{ .ServerUptime }}
Active Endpoint     : {{ .ActiveEndpoint }}
`
	// prepare statistics data
	Data := StatsData{
		ActiveRequests.GetValue(),
		RequestsPerSecond.GetValue(),
		TotalRequests.GetValue(),
		time.Since(ServerStart).Round(time.Second).String(),
		EndPoint.Upstream.GetValue(),
	}

	// render statistics information in plain text
	Stats := template.Must(template.New("statistics").Parse(TemplateStats))
	if err := Stats.Execute(w, Data); err != nil {
		log.Print(err)
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

	q, ok := r.URL.Query()["q"]
	if !ok || len(q) < 1 {
		http.Error(
			w,
			"Bad Request",
			http.StatusBadRequest,
		)
		return
	}
	EndPoint.Upstream.SetValue(q[0])
	if _, err := fmt.Fprintf(w, "New endpoint: %s\n", q[0]); err != nil {
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

	// handle GET requests
	if r.Method == http.MethodGet {
		client := http.Client{Timeout: time.Second * 5}
		resp, err = client.Get(EndPoint.Upstream.GetValue() + r.URL.String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// handle POST requests
	if r.Method == http.MethodPost {
		resp, err = http.Post(EndPoint.Upstream.GetValue(), "application/xml", r.Body)
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
	if EndPoint.Headers != nil {
		for key, headers := range EndPoint.Headers {
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

// initialize program variables
func init() {
	// initialize endpoint
	EndPoint.Upstream.SetValue("https://www.google.com")
	EndPoint.Headers = make(http.Header)

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

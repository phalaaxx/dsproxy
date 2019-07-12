// dsproxy.go - Dead Simple Proxy
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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
	ConfigurationFile string
	SaveConfiguration bool
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
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

/* SaveConfiguration stores endpoints configuration to a JSON file */
func SaveConfigurationFile(name string, data []EndPointBackend) error {
	if !SaveConfiguration {
		return nil
	}
	// create configuration file
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
	// save configuration
	if err = encoder.Encode(data); err != nil {
		return err
	}
	return nil
}

/* LoacConfiguration reads a JSON file containing backend endpoints */
func LoadConfigurationFile(name string) ([]EndPointBackend, error) {
	// open configuration file for reading
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	CloseFile := func() {
		if err := file.Close(); err != nil {
			log.Println(err)
		}
	}
	defer CloseFile()
	// load configuration
	decoder := json.NewDecoder(file)
	var result []EndPointBackend
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
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
		if strings.Compare(name[0], EndPoint.Backend[i].LocalPath) == 0 {
			EndPoint.Backend[i] = EndPoint.Backend[len(EndPoint.Backend)-1]
			EndPoint.Backend = EndPoint.Backend[:len(EndPoint.Backend)-1]
			// store configuration to persistent storage
			if err := SaveConfigurationFile(ConfigurationFile, EndPoint.Backend); err != nil {
				log.Println(err)
			}
			// redirect to _control view
			http.Redirect(w, r, "/_control/", http.StatusFound)
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
		// store configuration to persistent storage
		if err := SaveConfigurationFile(ConfigurationFile, EndPoint.Backend); err != nil {
			log.Println(err)
		}
		// redirect to _control view
		http.Redirect(w, r, "/_control/", http.StatusFound)
		return
	}
	// render endpoint edit form
	if err := RenderEdit(w, EndPoint.Backend[idx]); err != nil {
		log.Println(err)
	}
}

/* HandleNewEndpoint renders a form to edit endpoint parameters */
func HandleNewEndpoint(w http.ResponseWriter, r *http.Request) {
	// lock endpoint data structure for writing
	EndPoint.Mu.Lock()
	defer EndPoint.Mu.Unlock()
	// handle POST requests
	if r.Method == http.MethodPost {
		// parse http form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// check endpoint name
		endpoint := r.FormValue("endpoint")
		if len(endpoint) == 0 {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		// check address
		address := r.FormValue("address")
		if len(address) == 0 {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		// look up endpoint index
		idx := EndPoint.Get(endpoint)
		if idx != -1 {
			http.Error(w, "Endpoint Exists", http.StatusConflict)
			return
		}
		// add new endpoint to list
		EndPoint.Backend = append(
			EndPoint.Backend,
			EndPointBackend{
				endpoint,
				address,
				make(http.Header),
			},
		)
		// store configuration to persistent storage
		if err := SaveConfigurationFile(ConfigurationFile, EndPoint.Backend); err != nil {
			log.Println(err)
		}
		http.Redirect(w, r, "/_control/", http.StatusFound)
		return
	}
	// render endpoint edit form
	if err := RenderNew(w); err != nil {
		log.Println(err)
	}
}

// initialize program variables
func init() {
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
	flag.StringVar(
		&ConfigurationFile,
		"config",
		"dsproxy.json",
		"Endpoints configuration file",
	)
	flag.BoolVar(
		&SaveConfiguration,
		"save",
		false,
		"Save configuration to file when changed",
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
	// initialize endpoint
	var err error
	if EndPoint.Backend, err = LoadConfigurationFile(ConfigurationFile); err != nil {
		log.Println(err)
	}
	// http muxer and handlers
	mux := http.NewServeMux()
	mux.HandleFunc(
		"/_control/",
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
		"/_control/new",
		HandleNewEndpoint,
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

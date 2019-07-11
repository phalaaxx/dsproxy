## dsproxy

A dead simple proxy for GET and POST requests that allows upstream server change without service restart or connection loss.

### Running dsproxy

Compile to native binary with:

    go build
    
Then run the binary. To make it save configuration to a file every time it is changed, run it with the following arguments:

    ./dsproxy --config dsproxy.json --save


Finally point your browser to http://localhost:8000/_control/ to get started.
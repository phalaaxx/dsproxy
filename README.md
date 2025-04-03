## dsproxy

A dead simple proxy is a hot-configurable reverse proxy server with virtual hosts support. It is also able to activate or deactivate
endpoints on the fly with a CLI interface.

The dsproxy server is cappable of running with SSL support, which makes it possible to configure it to listen directly on 80/tcp or
443/tcp for accepting https connections.

It also supports endpoint IP address configuration (in the form ip:port) to avoid resolving target's IP addresses. Default behaviour
is to resolve target's address (when no specific address is provided, in that case address is "-" by default). When ip:port pair is
provided, it is used when initiating backend connection regardless of how target's address is resolved.

### Compilation

To compile the binary simply run:

    go build

This will produce a binary that can be used to start the server (foreground only) and control a running service. If dsproxy is
going to be used under Linux environment and running on a privileged port, to avoid running it as a root user it should also be
configured with proper capabilities:

    setcap cap_net_bind_service=+ep dsproxy

This way dsproxy can be started by a regular user and bind to a privileged port (below 1024).

### Running dsproxy

After the binary has been properly compiled, the service can be started either from the command line or through a service monitor
(like daemontools/runit/systemd/etc.)
An example systemd unit file is also included in the repository.

To start the service from the command line (like for testing purposes), simply run it with the --server argument:

    ./dsproxy --server

By default the service will listen on http port 8000. This can be changed with the -bind-address cli argument.
For a full list of command line options, use -help on the command line.

### Listing configured endpoints

When run without any arguments, dsproxy will connect to a running daemon on the same server and get list of configured endpoints.
The list is then printed on the standard output.

    ./dsproxy

### Add, remove, edit endpoints

#### Add and endpoint

To add new endpoint, all of host, location and target parameters must be specified. Additionally the -add parameter is required
in order to create a new endpoint configuration:

    ./dsproxy -add -host some.host.com -location test/location -target https://www.google.com

When the default host is used '\*', the -host parameter can be omitted:

    ./dsproxy -add -location sample -upsteram https://sample.com


#### Edit existing endpoint

An endpoint is always identified by a host and location. In order to edit an endpoint it should be identified and the field to
edit should be specified:

    ./dsproxy -host some.host.com       -location test/location    -edit-host     some.other.host.com
    ./dsproxy -host some.other.host.com -location test/location    -edit-location example/location
    ./dsproxy -host some.other.host.com -location example/location -edit-target   https://www.duckduckgo.com
    ./dsproxy -host some.other.host.com -location example/location -edit-address  127.0.1.1:443

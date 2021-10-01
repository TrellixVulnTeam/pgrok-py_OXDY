# Python Tunneling client for [pgrok](https://github.com/jerson/pgrok) 

`pgrok-py` is a Python wrapper for `pgrok` that manages its own binary and puts
it on your path, making `pgrok` readily available from anywhere on the command line and via a
convenient Python API.

[pgrok](https://github.com/jerson/pgrok) is a reverse proxy tool which is open-source version of [ngrok](https://ngrok.com/) that opens secure tunnels from public URLs to localhost, perfect for exposing local web servers, building webhook integrations, enabling SSH access, testing chatbots, demoing from
your own machine, and more, and its made even more powerful with native Python integration through `pgrok-py`.

This provide additional functionality of self-hosting tunnelling server to aws/droplet instance and also additional benefits to escape monthly recurring charges of ngrok. 
## Installation

```sh
pip install pgrok
```

## Basic Usage
<!-- Write about basic usage -->

### Pgrok tunnel-backend
```python
from pgrok import pgrok

# Open a HTTP tunnel on the default port 80
# <PgrokTunnel: "http://<public_sub>.pgrok.io" -> "http://localhost:80">
http_tunnel = pgrok.connect()
# Open a SSH tunnel
# <PgrokTunnel: "https://colabshell.ejemplo.me" -> "localhost:8080">
ssh_tunnel = pgrok.connect(addr=8080, proto='http', name='colabshell')
```

The `connect` method takes `kwargs` as well, which allows us to pass additional properties that are [supported by pgrok](https://github.com/jerson/pgrok/blob/master/docs/DEVELOPMENT.md).

This package puts the default `pgrok` binary on our path, so all features of `pgrok` are available on the command line.

```sh
pgrok http 80
```

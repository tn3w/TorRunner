# TorRunner

Expose local ports as a Tor onion service from Python or the command line.
Uses the system `tor` if installed, otherwise downloads the official Tor Expert Bundle
(Linux, macOS, Windows) into `~/.cache/tor_runner`. No dependencies, Python 3.10+.

```bash
pip install tor_runner
```

## Command line

```bash
tor_runner 80:5000                  # onion port 80 -> 127.0.0.1:5000
tor_runner 80:5000 22 -s 9050       # plus onion port 22 and a SOCKS proxy on 9050
tor_runner -s 9050                  # SOCKS proxy only
tor_runner 80:5000 -b "obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0"
tor_runner --delete                 # remove downloaded Tor, keys and state
```

| Option | Meaning |
| --- | --- |
| `ONION_PORT:LOCAL_PORT` | port mapping, repeatable; local port defaults to onion port |
| `-d, --directory` | hidden service key directory (keeps the address stable) |
| `-b, --bridge` | bridge line, repeatable; obfs4, webtunnel, meek, snowflake |
| `-s, --socks-port` | open a SOCKS5 proxy |
| `--delete` | delete all TorRunner data |

## Python

```python
from tor_runner import TorRunner

runner = TorRunner(hidden_service_directory="keys", socks_port=9050)
address = runner.start([(80, 5000)])
runner.stop()
```

`start` blocks until Tor is fully bootstrapped and raises `RuntimeError` with Tor's
warnings if it exits early. Tor stops automatically on interpreter exit.

### Flask

```python
from flask import Flask
from tor_runner import TorRunner

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello, Anonymous!"

TorRunner().flask_run(app, port=5000)
```

### Requests through Tor

```python
import requests  # pip install requests[socks]

proxies = {"https": "socks5h://127.0.0.1:9050"}
print(requests.get("https://check.torproject.org/api/ip", proxies=proxies).json())
```

## Publishing

Publishing a GitHub release uploads to PyPI via trusted publishing.

## License

[GPL-3.0](LICENSE)

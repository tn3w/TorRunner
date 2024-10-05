<h1 align="center">🧅 𝙏𝙤𝙧𝙍𝙪𝙣𝙣𝙚𝙧</h1>
<p align="center">TorRunner is a Python package designed to facilitate the deployment of Tor hidden services. It simplifies the process by allowing you to set up and run a hidden service that listens on a specified port. This package automates the installation and configuration of the Tor software, removing the need for manual setup and making it easier to get started.</p>
<p align="center"><a rel="noreferrer noopener" href="https://github.com/tn3w/TorRunner"><img alt="Github" src="https://img.shields.io/badge/Github-141e24.svg?&style=for-the-badge&logo=github&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://pypi.org/project/tor-runner/"><img alt="PyPI" src="https://img.shields.io/badge/PyPi-141e24.svg?&style=for-the-badge&logo=python&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://libraries.io/pypi/tor-runner"><img alt="Libraries.io" src="https://img.shields.io/badge/Libraries.io-141e24.svg?&style=for-the-badge&logo=npm&logoColor=white"></a></p>

<br>

## Examples

### On the command line
```bash
tor_runner --help
```

Output:
```
usage: tor_runner [-h] [-p PORT] [-l [LISTENER ...]] [-d [HIDDEN_SERVICE_DIRS ...]] [-b [BRIDGES ...]] [-t DEFAULT_BRIDGE_TYPE] [-q BRIDGE_QUANTITY] [-s SOCKS_PORT] [--quiet]

Run as Tor hidden service

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  HTTP Port to listen
  -l [LISTENER ...], --listener [LISTENER ...]
                        List of listeners in the format 'tor_port,listen_port'
  -d [HIDDEN_SERVICE_DIRS ...], --hidden-service-dirs [HIDDEN_SERVICE_DIRS ...]
                        List of hidden service directories
  -b [BRIDGES ...], --bridges [BRIDGES ...]
                        List of bridges for Tor
  -t DEFAULT_BRIDGE_TYPE, --default-bridge-type DEFAULT_BRIDGE_TYPE
                        Default bridge type
  -q BRIDGE_QUANTITY, --bridge-quantity BRIDGE_QUANTITY
                        How many bridges to use
  -s SOCKS_PORT, --socks-port SOCKS_PORT
                        The socks port for tor.
  --quiet               Run in quiet mode (no output)
```

---

### Without an App
```python
from tor_runner import TorRunner

# Uses 11 default obfs4 bridges to connect
runner = TorRunner(
    hs_dirs = ["/path/to/hs"], bridges = [],
    default_bridge_type = "obfs4", bridge_quantity = 11
)

if __name__ == '__main__':
    # Forwards 80 -> 5000 and 22 -> 22
    runner.run([(80, 5000), (22, 22)], socks_port = 9050, quite = False, wait = True)
```

---

### For Flask
```python
from flask import Flask
from tor_runner import TorRunner

app = Flask(__name__)

# Uses 11 default obfs4 bridges to connect
runner = TorRunner(default_bridge_type = "obfs4", bridge_quantity = 11)

@app.route('/')
def index():
    """
    Route accessible via the Tor network
    """

    return 'Hello, Anonymous!🖐️'

if __name__ == '__main__':
    runner.flask_run(app, host = '127.0.0.1', port = 9000)
```

---

### For Sanic
```python
from sanic import Sanic, HTTPResponse
from sanic.response import text
from tor_runner import TorRunner

app = Sanic(__name__)

# Uses 11 default obfs4 bridges to connect
runner = TorRunner(default_bridge_type = "obfs4", bridge_quantity = 11)

@app.route('/')
async def index(request) -> HTTPResponse:
    """
    Route accessible via the Tor network
    """

    return text('Hello, Anonymous!🖐️')

if __name__ == '__main__':
    runner.sanic_run(app, host = '127.0.0.1', port = 8000, workers = 16)
```

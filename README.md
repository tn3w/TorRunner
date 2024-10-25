<h1 align="center">🧅 𝙏𝙤𝙧𝙍𝙪𝙣𝙣𝙚𝙧</h1>
<p align="center">TorRunner is a Python package designed to facilitate the deployment of Tor hidden services. It simplifies the process by allowing you to set up and run a hidden service that listens on a specified port. This package automates the installation and configuration of the Tor software, removing the need for manual setup and making it easier to get started.</p>
<p align="center"><a rel="noreferrer noopener" href="https://github.com/tn3w/TorRunner"><img alt="Github" src="https://img.shields.io/badge/Github-141e24.svg?&style=for-the-badge&logo=github&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://pypi.org/project/tor-runner/"><img alt="PyPI" src="https://img.shields.io/badge/PyPi-141e24.svg?&style=for-the-badge&logo=python&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://libraries.io/pypi/tor-runner"><img alt="Libraries.io" src="https://img.shields.io/badge/Libraries.io-141e24.svg?&style=for-the-badge&logo=npm&logoColor=white"></a></p>

<br>

## Special thanks
This project uses the Vanguards implementation of [mikeperry-tor](https://github.com/mikeperry-tor) at [mikeperry-tor/vanguards](https://github.com/mikeperry-tor/vanguards) under MIT license found [here](https://github.com/mikeperry-tor/vanguards/blob/master/LICENSE), the socks implementation of [Anorov](https://github.com/Anorov) at [Anorov/PySocks](https://github.com/Anorov/PySocks) under BSD License found [here](https://github.com/Anorov/PySocks/blob/master/LICENSE) and the win_inet_pton implementation of [hickeroar](https://github.com/hickeroar) at [hickeroar/win_inet_pton](https://github.com/hickeroar/win_inet_pton) under Public Domain License found [here](https://github.com/hickeroar/win_inet_pton/blob/master/LICENSE).

## 📌 Planned for the future
- [x] Vanguards
- [ ] Auto Bridge Updates
- [ ] Multi Threads
- [ ] Tor version check & auto update
- [x] Proxy mode [only for urllib implemented]<br>
❌ (not feasible) Tor preinstalled

## 🚀 Installation
Make sure you have the latest version of Python and Pip installed.

1. Create an virtual env with `python3 -m venv .venv` and `source .venv/bin/activate`
2. Install TorRunner with pip `pip install tor-runner` or manually via `git clone https://github.com/tn3w/TorRunner` or download the zip [here](https://github.com/tn3w/TorRunner/archive/refs/heads/master.zip).
3. If you installed it manually, run `pip install .` in the downloaded and extracted folder.
4. [Optional] Install stem with `pip install stem` if you want to use Vanguards.

<br>

Quick command:
```bash
python3 -m venv .venv; source .venv/bin/activate; pip install tor-runner
```

## Examples
Note: TorRunner uses only built-in Python libraries, if you want to use vanguards, install stem with `pip install stem` after you have created a virtual environment: `python3 -m venv .venv` and activated: `source .venv/bin/activate`.

### TorProxy
TorRunner has the ability to route your urllib requests through Tor.

Example:
```python
import time
import urllib.request
import urllib.error
from tor_runner import TorProxy

proxy = TorProxy()
proxy.start()
print("SocksPort running on 127.0.0.1:" + str(proxy.socks_port))

with proxy.urllib():
    start_time = time.time()
    url = "https://check.torproject.org/?lang=en_US"

    try:
        response = urllib.request.urlopen(url)
        content = response.read().decode('utf-8')

        if "Congratulations" in content:
            print("Connected to Tor!")

        elif "Sorry" in content:
            print("Not connected to Tor")

    except urllib.error.URLError as e:
        print(f"Error connecting to {url}: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

    first_byte_time = time.time() - start_time
    print(f"Time to first byte: {first_byte_time:.4f} seconds")
```

---

### On the command line
```bash
tor_runner --help
```

Output:
```
usage: tor_runner [-h] [-p PORT] [-l [LISTENER ...]] [-t THREADS] [-d [HIDDEN_SERVICE_DIRS ...]] [-b [BRIDGES ...]] [-s SOCKS_PORT] [-v [VANGUARDS]] [--bridge-quantity BRIDGE_QUANTITY]
                  [--default-bridge-type DEFAULT_BRIDGE_TYPE] [--direct] [--delete] [--quiet]

Run as a Tor hidden service, allowing configuration of listeners, hidden service directories, and bridges.

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  HTTP port for the hidden service to listen on.
  -l [LISTENER ...], --listener [LISTENER ...]
                        List of listeners in the format 'tor_port,listen_port'.
  -t THREADS, --threads THREADS
                        How many times Tor should start. (default: 1)
  -d [HIDDEN_SERVICE_DIRS ...], --hidden-service-dirs [HIDDEN_SERVICE_DIRS ...]
                        Directories for storing hidden service keys and hostname files.
  -b [BRIDGES ...], --bridges [BRIDGES ...]
                        List of bridges to use for connecting to the Tor network.
  -s SOCKS_PORT, --socks-port SOCKS_PORT
                        SOCKS port for Tor connections.
  -v [VANGUARDS], --vanguards [VANGUARDS]
                        Enables Vanguards with an optional thread count to protect against guard discovery and related traffic analysis attacks.
  --bridge-quantity BRIDGE_QUANTITY
                        Number of bridges to use for connecting to the Tor network.
  --default-bridge-type DEFAULT_BRIDGE_TYPE
                        Default bridge type to use when connecting to Tor.
  --direct              Executes your command directly via Tor.
  --delete              Delete all data associated with tor_runner.
  --quiet               Run the script in quiet mode with no output.
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
    # Forwards 5000 -> 80 and 22 -> 22
    runner.run([(5000, 80), (22, 22)], socks_port = 9050, quite = False, wait = True)
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

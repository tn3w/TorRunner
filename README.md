<h1 align="center">🧅 𝙏𝙤𝙧𝙍𝙪𝙣𝙣𝙚𝙧</h1>
<p align="center">TorRunner is a Python package designed to facilitate the deployment of Tor hidden services. It simplifies the process by allowing you to set up and run a hidden service that listens on a specified port. This package automates the installation and configuration of the Tor software, removing the need for manual setup and making it easier to get started.</p>
<p align="center"><a rel="noreferrer noopener" href="https://github.com/tn3w/TorRunner"><img alt="Github" src="https://img.shields.io/badge/Github-141e24.svg?&style=for-the-badge&logo=github&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://pypi.org/project/tor-runner/"><img alt="PyPI" src="https://img.shields.io/badge/PyPi-141e24.svg?&style=for-the-badge&logo=python&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://libraries.io/pypi/tor-runner"><img alt="Libraries.io" src="https://img.shields.io/badge/Libraries.io-141e24.svg?&style=for-the-badge&logo=npm&logoColor=white"></a></p>

<br>

```python
from flask import Flask
from tor_runner import TorRunner

app = Flask(__name__)
runner = TorRunner(app)

@app.route('/')
def index():
    """
    Route accessible via the Tor network
    """

    return 'Hello, anonymous guy!🖐️'

if __name__ == '__main__':
    runner.run(host = 'localhost', port = 9000)
```

With TorRunner, you can quickly configure your application to be accessible over the Tor network, providing anonymous access. This is particularly useful for creating secure and private communication channels, as the Tor network is known for its ability to conceal both the user's and the server's locations. By using TorRunner, developers can focus on building their applications without worrying about the complexities of Tor's underlying infrastructure.

> [!NOTE]
> This is an beta release. Please report any issues or feedback to [tn3wA8xxfuVMs2@proton.me](mailto:tn3wA8xxfuVMs2@proton.me) or create a [GitHub issue](https://github.com/tn3w/TorRunner/issues).
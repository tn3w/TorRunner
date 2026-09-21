import argparse

from . import TorRunner, delete_data


def listener(value: str) -> tuple[int, int]:
    onion_port, _, local_port = value.partition(":")
    return int(onion_port), int(local_port or onion_port)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tor_runner", description="Expose local ports as a Tor onion service."
    )
    parser.add_argument(
        "listeners",
        nargs="*",
        type=listener,
        help="ONION_PORT:LOCAL_PORT, e.g. 80:5000 (LOCAL_PORT defaults to ONION_PORT)",
    )
    parser.add_argument("-d", "--directory", help="hidden service key directory")
    parser.add_argument("-b", "--bridge", action="append", help="bridge line, repeatable")
    parser.add_argument("-s", "--socks-port", type=int, default=0, help="SOCKS port")
    parser.add_argument("--delete", action="store_true", help="delete Tor and all keys")
    arguments = parser.parse_args()

    if arguments.delete:
        delete_data()
        return
    if not arguments.listeners and not arguments.socks_port:
        parser.error("give at least one listener or --socks-port")

    runner = TorRunner(arguments.directory, arguments.bridge, arguments.socks_port)
    runner.start(arguments.listeners)
    if arguments.socks_port:
        print(f" * SOCKS proxy on 127.0.0.1:{arguments.socks_port}", flush=True)
    try:
        runner.process.wait()
    except KeyboardInterrupt:
        runner.stop()


if __name__ == "__main__":
    main()

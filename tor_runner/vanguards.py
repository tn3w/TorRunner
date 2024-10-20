#!/usr/bin/env python

"""
vanguards.py

The Vanguards Onion Service Addon

This is an edited version of Vanguards that has been edited for use with TorRunner,
changes have not been verified for integrity by The Tor Project, Inc. or any other entity.

License: Made available under the MIT license.
    https://github.com/mikeperry-tor/vanguards/blob/master/LICENSE
Source: https://github.com/mikeperry-tor/vanguards
"""

import sys
import time
import socket
import random
import pickle
import string
import getpass
import argparse
import functools
from configparser import SafeConfigParser

import os
import os.path

import logging
import logging.handlers

import ipaddress
from ipaddress import ip_network as net

import stem
import stem.control
import stem.connection
import stem.descriptor
import stem.response.events

from . import rendguard
from . import bandguards
from . import logguard
from . import cbtverify
from . import pathverify
from . import control
from .NodeSelection import BwWeightedGenerator, NodeRestrictionList
from .NodeSelection import FlagsRestriction

__version__ = "0.4.0-dev1"
close_circuits = True
logger = None
loglevel = "DEBUG"
logfile = None
_MIN_TOR_VERSION_FOR_BW = stem.version.Version("0.3.4.10")


ENABLE_VANGUARDS=True
ENABLE_RENDGUARD=True
ENABLE_BANDGUARDS=True
ENABLE_LOGGUARD=True
ENABLE_CBTVERIFY=False
ENABLE_PATHVERIFY=False

# State file location
STATE_FILE = "vanguards.state"

# Config file location
_CONFIG_FILE = "vanguards.conf"

# Loglevel
LOGLEVEL = "NOTICE"

# Log to file instead of stdout
LOGFILE = ""

# If true, write/update vanguards to torrc and then exit
ONE_SHOT_VANGUARDS = False

CLOSE_CIRCUITS = True

CONTROL_IP = "127.0.0.1"
CONTROL_PORT = ""
CONTROL_SOCKET = ""
CONTROL_PASS = ""

_RETRY_LIMIT = None

NUM_LAYER1_GUARDS = 2 # 0 is Tor default
NUM_LAYER2_GUARDS = 4
NUM_LAYER3_GUARDS = 8

# In days:
LAYER1_LIFETIME_DAYS = 0 # Use tor default

# In hours
MIN_LAYER2_LIFETIME_HOURS = 24*1
MAX_LAYER2_LIFETIME_HOURS = 24*45

# In hours
MIN_LAYER3_LIFETIME_HOURS = 1
MAX_LAYER3_LIFETIME_HOURS = 48

_SEC_PER_HOUR = (60*60)

# --- logger.py ----

loglevels = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "NOTICE": logging.INFO + 5,
    "WARN": logging.WARN,
    "ERROR": logging.ERROR,
    "ERR": logging.ERROR,
    "NONE": logging.ERROR + 5
}

def set_loglevel(level: str = "DEBUG") -> None:
    global loglevel

    if level not in loglevels:
        plog("ERROR", "Invalid loglevel: " + str(level))
        return

    loglevel = level


def set_logfile(file_name: str) -> None:
    global logfile

    try:
        new_log_file = file_name
        if file_name != ":syslog:":
            new_log_file = open(file_name, "a")

        logfile = new_log_file

        logger_init()
    except Exception as e:
        plog("ERROR", "Can't open log file " + str(file_name) + ": " + str(e))



def logger_init():
    global logger, logfile

    logger = logging.getLogger("TorCtl")

    if logfile == ":syslog:":
        if os.path.exists("/dev/log"):
            ch = logging.handlers.SysLogHandler("/dev/log")
        elif os.path.exists("/var/run/syslog"):
            ch = logging.handlers.SysLogHandler("/var/run/syslog")
        else:
            ch = logging.handlers.SysLogHandler()

        formatter = logging.Formatter("vanguards %(levelname)s: %(message)s")
    else:
        formatter = logging.Formatter("%(levelname)s[%(asctime)s]: %(message)s",
                                      "%a %b %d %H:%M:%S %Y")
        if not logfile:
            logfile = sys.stdout
            ch = logging.StreamHandler(logfile)
        else:
            ch = logging.StreamHandler(logfile)

    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logger.setLevel(loglevels[loglevel])


def plog(level, msg, *args):
    if not logger:
        logger_init()
    logger.log(loglevels[level], msg.strip(), *args)


# --- config.py ----


def setup_options():
    global CONTROL_IP, CONTROL_PORT, CONTROL_SOCKET, CONTROL_PASS, STATE_FILE
    global ENABLE_BANDGUARDS, ENABLE_RENDGUARD, ENABLE_LOGGUARD, ENABLE_CBTVERIFY
    global ENABLE_PATHVERIFY
    global LOGLEVEL, LOGFILE
    global ONE_SHOT_VANGUARDS, ENABLE_VANGUARDS

    parser = argparse.ArgumentParser()

    parser.add_argument("--state", dest="state_file",
                        default=os.environ.get("VANGUARDS_STATE", STATE_FILE),
                        help="File to store vanguard state")

    parser.add_argument("--generate_config", dest="write_file", type=str,
                        help="Write config to a file after applying command args")

    parser.add_argument("--loglevel", dest="loglevel", type=str,
                        help="Log verbosity (DEBUG, INFO, NOTICE, WARN, or ERROR)")

    parser.add_argument("--logfile", dest="logfile", type=str,
                        help="Log to LOGFILE instead of stdout")

    parser.add_argument("--config", dest="config_file",
                        default=os.environ.get("VANGUARDS_CONFIG", _CONFIG_FILE),
                        help="Location of config file with more advanced settings")

    parser.add_argument("--control_ip", dest="control_ip", default=CONTROL_IP,
                        help="The IP address of the Tor Control Port to connect to (default: "+
                        CONTROL_IP+")")
    parser.add_argument("--control_port", type=str, dest="control_port",
                        default=CONTROL_PORT,
                        help="The Tor Control Port to connect to (default: "+
                        "tries both 9050 and 9151)")

    parser.add_argument("--control_socket", dest="control_socket",
                        default=CONTROL_SOCKET,
                        help="The Tor Control Socket path to connect to "+
                        "(default: try /run/tor/control, then control port)")
    parser.add_argument("--control_pass", dest="control_pass",
                        default=CONTROL_PASS,
                        help="The Tor Control Port password (optional) ")

    parser.add_argument("--retry_limit", dest="retry_limit",
                        default=_RETRY_LIMIT, type=int,
                        help="Reconnect attempt limit on failure (default: Infinite)")

    parser.add_argument("--one_shot_vanguards", dest="one_shot_vanguards",
                        action="store_true",
                        help="Set and write layer2 and layer3 guards to Torrc and exit.")

    parser.add_argument("--disable_vanguards", dest="vanguards_enabled",
                        action="store_false",
                        help="Disable setting any layer2 and layer3 guards.")
    parser.set_defaults(vanguards_enabled=ENABLE_VANGUARDS)

    parser.add_argument("--disable_bandguards", dest="bandguards_enabled",
                        action="store_false",
                        help="Disable circuit side channel checks (may help performance)")
    parser.set_defaults(bandguards_enabled=ENABLE_BANDGUARDS)

    parser.add_argument("--disable_logguard", dest="logguard_enabled",
                        action="store_false",
                        help="Disable Tor log monitoring (may help performance)")
    parser.set_defaults(logguard_enabled=ENABLE_LOGGUARD)

    parser.add_argument("--disable_rendguard", dest="rendguard_enabled",
                        action="store_false",
                        help="Disable rendezvous misuse checks (may help performance)")
    parser.set_defaults(rendguard_enabled=ENABLE_RENDGUARD)

    parser.add_argument("--enable_cbtverify", dest="cbtverify_enabled",
                        action="store_true",
                        help="Enable Circuit Build Time monitoring")
    parser.set_defaults(cbtverify_enabled=ENABLE_CBTVERIFY)

    parser.add_argument("--enable_pathverify", dest="pathverify_enabled",
                        action="store_true",
                        help="Enable path selection monitoring")
    parser.set_defaults(pathverify_enabled=ENABLE_PATHVERIFY)

    options = parser.parse_args()

    (STATE_FILE, CONTROL_IP, CONTROL_PORT, CONTROL_SOCKET, CONTROL_PASS,
    ENABLE_BANDGUARDS, ENABLE_RENDGUARD, ENABLE_LOGGUARD, ENABLE_CBTVERIFY,
    ENABLE_PATHVERIFY, ONE_SHOT_VANGUARDS, ENABLE_VANGUARDS) = \
        (options.state_file, options.control_ip, options.control_port,
        options.control_socket, options.control_pass,
        options.bandguards_enabled, options.rendguard_enabled,
        options.logguard_enabled,
        options.cbtverify_enabled, options.pathverify_enabled,
        options.one_shot_vanguards, options.vanguards_enabled)

    if options.loglevel is not None:
        LOGLEVEL = options.loglevel
    logger.set_loglevel(LOGLEVEL)

    if options.logfile is not None:
        LOGFILE = options.logfile

    if LOGFILE != "":
        logger.set_logfile(LOGFILE)

    if options.write_file is not None:
        config = generate_config()
        config.write(open(options.write_file, "w"))
        plog("NOTICE", "Wrote config to "+options.write_file)
        sys.exit(0)

    # If control_ip is a domain name, try to resolve it.
    if options.control_ip is not None:
        try:
            _ = ipaddress.ip_address(options.control_ip)
        except ValueError:
            try:
                # We're fine with AF_INET, stem supports only IPv4 addresses anyway.
                addr = socket.getaddrinfo(options.control_ip, None, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                CONTROL_IP = addr[0][4][0]
            except socket.gaierror:
                plog("ERROR", "Failed to resolve hostname "+options.control_ip)
                sys.exit(1)

    plog("DEBUG", "Applied command line options")

    return options

# Avoid a big messy dict of defaults. We already have them.
def get_option(config, section, option, default):
    try:
        if type(default) == bool:
            ret = config.get(section, option) == "True"
        else:
            ret = type(default)(config.get(section, option))
    except Error as e:
        return default

    return ret

def get_options_for_module(config, module, section):
    for param in dir(module):
        if param.isupper() and param[0] != '_':
            val = getattr(module, param)
            setattr(module, param,
                    get_option(config, section, param.lower(), val))

def set_options_from_module(config, module, section):
    config.add_section(section)
    for param in dir(module):
        if param.isupper() and param[0] != '_':
            val = getattr(module, param)
            config.set(section, param, str(val))

def generate_config():
    config = SafeConfigParser(allow_no_value=True)
    set_options_from_module(config, sys.modules[__name__], "Global")
    set_options_from_module(config, vanguards, "Vanguards")
    set_options_from_module(config, bandguards, "Bandguards")
    set_options_from_module(config, rendguard, "Rendguard")
    set_options_from_module(config, rendguard, "Logguard")

    return config

def apply_config(config_file):
    config = SafeConfigParser(allow_no_value=True)

    config.readfp(open(config_file, "r"))

    get_options_for_module(config, sys.modules[__name__], "Global")
    get_options_for_module(config, vanguards, "Vanguards")
    get_options_for_module(config, bandguards, "Bandguards")
    get_options_for_module(config, rendguard, "Rendguard")
    get_options_for_module(config, rendguard, "Logguard")

    # Special cased CLOSE_CIRCUITS option has to be transferred
    # to the control.py module
    setattr(control, "_CLOSE_CIRCUITS", CLOSE_CIRCUITS)

    plog("NOTICE", "Vanguards successfully applied config options from "+
         config_file)


# --- vanguards.py ----


class GuardNode:
    def __init__(self, idhex, chosen_at, expires_at):
        self.idhex = idhex
        self.chosen_at = chosen_at
        self.expires_at = expires_at

class ExcludeNodes:
    def __init__(self, controller):
        self.networks = []
        self.idhexes = set()
        self.nicks = set()
        self.countries = set()
        self.controller = controller
        self.exclude_unknowns = controller.get_conf("GeoIPExcludeUnknown")
        self._parse_line(controller.get_conf("ExcludeNodes"))

    def _parse_line(self, conf_line):
        if self.exclude_unknowns == "1":
            self.countries.add("??")
            self.countries.add("a1")

        if conf_line is None:
            return

        parts = conf_line.split(",")
        for p in parts:
            if p[0] == "$":
                p = p[1:]
            if "~" in p:
                p = p.split("~")[0]
            if "=" in p:
                p = p.split("=")[0]

            if len(p) == 40 and all(c in string.hexdigits for c in p):
                self.idhexes.add(p)
            elif p[0] == "{" and p[-1] == "}":
                self.countries.add(p[1:-1].lower())
            elif ":" in p or "." in p:
                self.networks.append(net(str(p), strict=False))
            else:
                self.nicks.add(p)

        plog("INFO", "Honoring ExcludeNodes line: " + conf_line)
        if len(self.networks):
            plog("INFO", "Excluding networks " + str(self.networks))
        if len(self.idhexes):
            plog("INFO", "Excluding idhexes " + str(self.idhexes))
        if len(self.nicks):
            plog("INFO", "Excluding nicks " + str(self.nicks))
        if len(self.countries):
            if self.exclude_unknowns == "auto":
                self.countries.add("??")
                self.countries.add("a1")

            if self.controller.get_info("ip-to-country/ipv4-available", "0") == "0":
                plog("WARN", "ExcludeNodes contains countries, but Tor has no GeoIP file! "
                     "Tor is not excluding countries!")
            else:
                plog("INFO", "Excluding countries " + str(self.countries))

    def router_is_excluded(self, r):
        if r.fingerprint in self.idhexes:
            return True
        if r.nickname in self.nicks:
            return True
        if "or_addresses" in r.__dict__:  # Stem 1.7.0 only
            addresses = r.or_addresses
        else:
            addresses = [(r.address, 9001, False)]

        for addr in addresses:
            is_ipv6 = addr[2]
            if len(self.countries):
                country = None
                if is_ipv6 and \
                   self.controller.get_info("ip-to-country/ipv6-available", "0") == "1":
                    country = self.controller.get_info("ip-to-country/" + addr[0])
                if not is_ipv6 and \
                   self.controller.get_info("ip-to-country/ipv4-available", "0") == "1":
                    country = self.controller.get_info("ip-to-country/" + addr[0])

                if country is not None and country.lower() in self.countries:
                    return True

            for network in self.networks:
                if is_ipv6:
                    if network.version == 6 and net(addr[0] + "/128").overlaps(network):
                        return True
                else:
                    if network.version == 4 and net(addr[0] + "/32").overlaps(network):
                        return True
        return False


class VanguardState:
    def __init__(self, state_file):
        self.layer2 = []
        self.layer3 = []
        self.state_file = state_file
        self.rendguard = rendguard.RendGuard()
        self.pickle_revision = 1
        self.enable_vanguards = True  # Set from main, irrelevant to pickle

    def set_state_file(self, state_file):
        self.state_file = state_file

    def sort_and_index_routers(self, routers):
        sorted_r = list(routers)
        dict_r = {}

        for r in sorted_r:
            if r.measured is None:
                # FIXME: Hrmm...
                r.measured = r.bandwidth
        sorted_r.sort(key=lambda x: x.measured, reverse=True)
        for r in sorted_r:
            dict_r[r.fingerprint] = r
        return sorted_r, dict_r

    def consensus_update(self, routers, weights, exclude):
        sorted_r, dict_r = self.sort_and_index_routers(routers)
        ng = BwWeightedGenerator(
            sorted_r,
            NodeRestrictionList(
                [FlagsRestriction(["Fast", "Stable", "Valid"], ["Authority"])]),
            weights, BwWeightedGenerator.POSITION_MIDDLE
        )
        gen = ng.generate()

        if self.enable_vanguards:
            self.remove_down_from_layer(self.layer2, dict_r)
            self.remove_down_from_layer(self.layer3, dict_r)
            self.remove_expired_from_layer(self.layer2)
            self.remove_expired_from_layer(self.layer3)
            self.remove_excluded_from_layer(self.layer2, dict_r, exclude)
            self.remove_excluded_from_layer(self.layer3, dict_r, exclude)
            self.replenish_layers(gen, exclude)

        ng = BwWeightedGenerator(
            sorted_r,
            NodeRestrictionList(
                [FlagsRestriction(["Fast", "Valid"], ["Authority"])]),
            weights, BwWeightedGenerator.POSITION_MIDDLE
        )

        ng.repair_exits()
        self.rendguard.xfer_use_counts(ng)

    def new_consensus_event(self, controller, event):
        routers = controller.get_network_statuses()
        exclude_nodes = ExcludeNodes(controller)
        data_dir = controller.get_conf("DataDirectory")

        if data_dir is None:
            plog("ERROR", "You must set a DataDirectory location option in your torrc.")
            sys.exit(1)

        consensus_file = os.path.join(controller.get_conf("DataDirectory"), "cached-microdesc-consensus")

        try:
            weights = control.get_consensus_weights(consensus_file)
        except IOError as e:
            raise stem.DescriptorUnavailable(f"Cannot read {consensus_file}: {e}")

        self.consensus_update(routers, weights, exclude_nodes)

        if self.enable_vanguards:
            self.configure_tor(controller)

        try:
            self.write_to_file(open(self.state_file, "wb"))
        except IOError as e:
            plog("ERROR", f"Cannot write state to {self.state_file}: {e}")
            sys.exit(1)

    def signal_event(self, controller, event):
        if event.signal == "RELOAD":
            plog("NOTICE", "Tor got SIGHUP. Reapplying vanguards.")
            self.configure_tor(controller)

    def configure_tor(self, controller):
        if NUM_LAYER1_GUARDS:
            controller.set_conf("NumEntryGuards", str(NUM_LAYER1_GUARDS))
            controller.set_conf("NumDirectoryGuards", str(NUM_LAYER1_GUARDS))

        if LAYER1_LIFETIME_DAYS > 0:
            controller.set_conf("GuardLifetime", f"{LAYER1_LIFETIME_DAYS} days")

        try:
            controller.set_conf("HSLayer2Nodes", self.layer2_guardset())

            if NUM_LAYER3_GUARDS:
                controller.set_conf("HSLayer3Nodes", self.layer3_guardset())
        except stem.InvalidArguments:
            plog("ERROR", "Vanguards requires Tor 0.3.3.x (and ideally 0.3.4.x or newer).")
            sys.exit(1)

    def write_to_file(self, outfile):
        return pickle.dump(self, outfile)

    @staticmethod
    def read_from_file(infile):
        ret = pickle.load(open(infile, "rb"))
        ret.set_state_file(infile)
        return ret

    def layer2_guardset(self):
        return ",".join(map(lambda g: g.idhex, self.layer2))

    def layer3_guardset(self):
        return ",".join(map(lambda g: g.idhex, self.layer3))

    def add_new_layer2(self, generator, excluded):
        guard = next(generator)
        while guard.fingerprint in map(lambda g: g.idhex, self.layer2) or \
              excluded.router_is_excluded(guard):
            guard = next(generator)

        now = time.time()
        expires = now + max(
            random.uniform(MIN_LAYER2_LIFETIME_HOURS * _SEC_PER_HOUR,
                           MAX_LAYER2_LIFETIME_HOURS * _SEC_PER_HOUR),
            random.uniform(MIN_LAYER2_LIFETIME_HOURS * _SEC_PER_HOUR,
                           MAX_LAYER2_LIFETIME_HOURS * _SEC_PER_HOUR)
        )
        self.layer2.append(GuardNode(guard.fingerprint, now, expires))
        plog("INFO", "New layer2 guard: " + guard.fingerprint)

    def add_new_layer3(self, generator, excluded):
        guard = next(generator)
        while guard.fingerprint in map(lambda g: g.idhex, self.layer3) or \
              excluded.router_is_excluded(guard):
            guard = next(generator)

        now = time.time()
        expires = now + max(
            random.uniform(MIN_LAYER3_LIFETIME_HOURS * _SEC_PER_HOUR,
                           MAX_LAYER3_LIFETIME_HOURS * _SEC_PER_HOUR),
            random.uniform(MIN_LAYER3_LIFETIME_HOURS * _SEC_PER_HOUR,
                           MAX_LAYER3_LIFETIME_HOURS * _SEC_PER_HOUR)
        )
        self.layer3.append(GuardNode(guard.fingerprint, now, expires))
        plog("INFO", "New layer3 guard: " + guard.fingerprint)

    def remove_excluded_from_layer(self, layer, dict_r, excluded):
        for g in list(layer):
            if excluded.router_is_excluded(dict_r[g.idhex]):
                layer.remove(g)
                plog("INFO", "Removing newly-excluded guard " + g.idhex)

    def remove_expired_from_layer(self, layer):
        now = time.time()
        for g in list(layer):
            if g.expires_at < now:
                layer.remove(g)
                plog("INFO", "Removing expired guard " + g.idhex)

    def remove_down_from_layer(self, layer, dict_r):
        for g in list(layer):
            if g.idhex not in dict_r:
                layer.remove(g)
                plog("INFO", "Removing down guard " + g.idhex)

    def replenish_layers(self, generator, excluded):
        self.layer2 = self.layer2[:NUM_LAYER2_GUARDS]
        self.layer3 = self.layer3[:NUM_LAYER3_GUARDS]

        while len(self.layer2) < NUM_LAYER2_GUARDS:
            self.add_new_layer2(generator, excluded)

        while len(self.layer3) < NUM_LAYER3_GUARDS:
            self.add_new_layer3(generator, excluded)


# ---- main.py ----


def authenticate_any(controller, passwd=""):
    try:
        controller.authenticate()
    except stem.connection.MissingPassword:
        if passwd == "":
            passwd = getpass.getpass("Controller password: ")
        try:
            controller.authenticate(password=passwd)
        except stem.connection.PasswordAuthFailed:
            print("Unable to authenticate, password is incorrect")
            sys.exit(1)
    except stem.connection.AuthenticationFailure as exc:
        print("Unable to authenticate: %s" % exc)
        sys.exit(1)

    plog("NOTICE", "Vanguards %s connected to Tor %s using stem %s",
         __version__, controller.get_version(), stem.__version__)


def get_consensus_weights(consensus_file_name: str):
    parsed_consensus = next(stem.descriptor.parse_file(
        consensus_file_name,
        document_handler = stem.descriptor.DocumentHandler.BARE_DOCUMENT
    ))

    assert parsed_consensus.is_consensus
    return parsed_consensus.bandwidth_weights


def try_close_circuit(controller, circ_id):
    if controller._logguard:
        controller._logguard.dump_log_queue(circ_id, "Pre")

    if close_circuits:
        try:
            controller.close_circuit(circ_id)
            plog("INFO", "We force-closed circuit " + str(circ_id))
        except stem.InvalidRequest as e:
            plog("INFO", "Failed to close circuit " + str(circ_id) + ": " + str(e.message))


def main():
    try:
        run_main()
    except KeyboardInterrupt:
        plog("NOTICE", "Got CTRL+C. Exiting.")


def run_main():
    try:
        config.apply_config(config._CONFIG_FILE)
    except Exception:
        pass  # Default config can be absent.
    options = config.setup_options()

    if options.config_file != config._CONFIG_FILE:
        try:
            config.apply_config(options.config_file)
        except Exception as e:
            plog("ERROR", "Specified config file " + options.config_file + " can't be read: " + str(e))
            sys.exit(1)
        options = config.setup_options()

    try:
        state = vanguards.VanguardState.read_from_file(config.STATE_FILE)
        plog("INFO", "Current layer2 guards: " + state.layer2_guardset())
        plog("INFO", "Current layer3 guards: " + state.layer3_guardset())
    except Exception:
        plog("NOTICE", "Creating new vanguard state file at: " + config.STATE_FILE)
        state = vanguards.VanguardState(config.STATE_FILE)

    state.enable_vanguards = config.ENABLE_VANGUARDS
    stem.response.events.PARSE_NEWCONSENSUS_EVENTS = False

    reconnects = 0
    last_connected_at = None
    connected = False
    while options.retry_limit is None or reconnects < options.retry_limit:
        ret = control_loop(state)
        if not last_connected_at:
            last_connected_at = time.time()

        if ret == "closed":
            connected = True

        if ret == "closed" or reconnects % 10 == 0:
            if time.time() - last_connected_at > bandguards.CONN_MAX_DISCONNECTED_SECS:
                plog("WARN", "Tor daemon connection " + ret + ". Trying again...")
            else:
                plog("NOTICE", "Tor daemon connection " + ret + ". Trying again...")

        reconnects += 1
        time.sleep(1)

    if not connected:
        sys.exit(1)


def control_loop(state):
    if not config.CONTROL_SOCKET and not config.CONTROL_PORT:
        try:
            controller = stem.control.Controller.from_socket_file("/run/tor/control")
            plog("NOTICE", "Connected to Tor via /run/tor/control socket")
        except stem.SocketError:
            try:
                controller = stem.control.Controller.from_port(config.CONTROL_IP)
            except stem.SocketError as e:
                return "failed: " + str(e)
            plog("NOTICE", "Connected to Tor via " + config.CONTROL_IP + " control port")
    else:
        try:
            if config.CONTROL_SOCKET != "":
                controller = stem.control.Controller.from_socket_file(config.CONTROL_SOCKET)
                plog("NOTICE", "Connected to Tor via socket " + config.CONTROL_SOCKET)
            else:
                if not config.CONTROL_PORT or config.CONTROL_PORT == "default":
                    controller = stem.control.Controller.from_port(config.CONTROL_IP)
                    plog("NOTICE", "Connected to Tor via " + config.CONTROL_IP + " control port")
                else:
                    controller = stem.control.Controller.from_port(config.CONTROL_IP, int(config.CONTROL_PORT))
                    plog("NOTICE", "Connected to Tor via control port " + config.CONTROL_IP + ":" + config.CONTROL_PORT)
        except ValueError:
            plog("ERROR", "Control port must be an integer or 'default'. Got " + str(config.CONTROL_PORT))
            sys.exit(1)
        except stem.SocketError as e:
            return "failed: " + str(e)

    authenticate_any(controller, config.CONTROL_PASS)

    if config.ENABLE_VANGUARDS or config.ENABLE_RENDGUARD:
        try:
            state.new_consensus_event(controller, None)
        except stem.DescriptorUnavailable as e:
            controller.close()
            plog("NOTICE", "Tor needs descriptors: " + str(e) + ". Trying again...")
            return "failed: " + str(e)

    if config.ONE_SHOT_VANGUARDS:
        try:
            controller.save_conf()
        except stem.OperationFailed as e:
            plog("NOTICE", "Tor can't save its own config file: " + str(e))
            sys.exit(1)
        plog("NOTICE", "Updated vanguards in torrc. Exiting.")
        sys.exit(0)

    if config.ENABLE_RENDGUARD:
        controller.add_event_listener(
            functools.partial(rendguard.RendGuard.circ_event, state.rendguard, controller),
            stem.control.EventType.CIRC
        )

    controller._logguard = None

    if config.ENABLE_LOGGUARD:
        logs = logguard.LogGuard(controller)
        controller._logguard = logs

        controller.add_event_listener(
            functools.partial(logguard.LogGuard.log_warn_event, logs),
            stem.control.EventType.WARN
        )
        controller.add_event_listener(
            functools.partial(logguard.LogGuard.circ_event, logs),
            stem.control.EventType.CIRC
        )

    if config.ENABLE_BANDGUARDS:
        bandwidths = bandguards.BandwidthStats(controller)

        controller.add_event_listener(
            functools.partial(bandguards.BandwidthStats.circ_event, bandwidths),
            stem.control.EventType.CIRC
        )
        controller.add_event_listener(
            functools.partial(bandguards.BandwidthStats.bw_event, bandwidths),
            stem.control.EventType.BW
        )

    try:
        controller.loop()
    finally:
        plog("NOTICE", "Closing controller")
        controller.close()
    return "closed"

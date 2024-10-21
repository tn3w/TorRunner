#!/usr/bin/env python

import os
import sys
import time
import random
import pickle
import string
import atexit
import functools
from typing import Optional
from multiprocessing import Process
from ipaddress import ip_network as net

import stem
import stem.control
import stem.response.events

from . import control
from . import rendguard
from . import bandguards
from . import pathverify
from .nodeselection import BwWeightedGenerator, NodeRestrictionList
from .nodeselection import FlagsRestriction
from .logger import plog


################### Vanguard options ##################
#
NUM_LAYER1_GUARDS = 3  # 0 is Tor default
NUM_LAYER2_GUARDS = 6
NUM_LAYER3_GUARDS = 8

# In days:
LAYER1_LIFETIME_DAYS = 0  # Use tor default

# In hours
MIN_LAYER2_LIFETIME_HOURS = 24 * 1
MAX_LAYER2_LIFETIME_HOURS = 24 * 45

# In hours
MIN_LAYER3_LIFETIME_HOURS = 1
MAX_LAYER3_LIFETIME_HOURS = 48

_SEC_PER_HOUR = 60 * 60

exited = False

def no_keyboard_interrupt(func: callable, *args, **kwargs) -> any:
    global exited

    try:
        return func(*args, **kwargs)
    except KeyboardInterrupt:
        sys.exit(0)

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
        # We assume Tor has validated the line already. So this parsing
        # is very dumb+simple (except for semantics of valid data).
        # See routerset_parse() in tor for parser semantic ordering.
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
                plog("WARN", "ExcludeNodes contains countries, but Tor has no GeoIP file! " +
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
        return (sorted_r, dict_r)

    def consensus_update(self, routers, weights, exclude):
        (sorted_r, dict_r) = self.sort_and_index_routers(routers)
        ng = BwWeightedGenerator(sorted_r,
                                 NodeRestrictionList(
                                     [FlagsRestriction(["Fast", "Stable", "Valid",
                                                        "Authority"])]),
                                 weights, BwWeightedGenerator.POSITION_MIDDLE)
        gen = ng.generate()
        if self.enable_vanguards:
            # Remove any nodes that are now down in the consensus
            self.remove_down_from_layer(self.layer2, dict_r)
            self.remove_down_from_layer(self.layer3, dict_r)

            # Remove any nodes whose rotation times are past due.
            # FIXME: We should check this more often... But we also
            # need to replenish our layers if they get too low/empty.
            # This can be slow (consensus parse required)... :/
            self.remove_expired_from_layer(self.layer2)
            self.remove_expired_from_layer(self.layer3)

            # Remove any nodes in case ExcludeNodes changed.
            self.remove_excluded_from_layer(self.layer2, dict_r, exclude)
            self.remove_excluded_from_layer(self.layer3, dict_r, exclude)

            # Replenish our guard lists with new nodes
            self.replenish_layers(gen, exclude)

        ng = BwWeightedGenerator(sorted_r,
                                 NodeRestrictionList(
                                     [FlagsRestriction(["Fast", "Valid",
                                                        "Authority"])]),
                                 weights, BwWeightedGenerator.POSITION_MIDDLE)

        # Repair Exit-flagged node weights, since they can be chosen
        # sometimes by other clients as RPs (when cannibalized)
        ng.repair_exits()
        # Transfer and scale RP use counts to this consensus
        self.rendguard.xfer_use_counts(ng)

    def new_consensus_event(self, controller, _):
        routers = controller.get_network_statuses()

        exclude_nodes = ExcludeNodes(controller)

        data_dir = controller.get_conf("DataDirectory")
        if data_dir is None:
            plog("ERROR",
                 "You must set a DataDirectory location option in your torrc.")
            sys.exit(1)

        consensus_file = os.path.join(controller.get_conf("DataDirectory"),
                                       "cached-microdesc-consensus")

        try:
            weights = control.get_consensus_weights(consensus_file)
        except IOError as e:
            raise stem.DescriptorUnavailable("Cannot read " + consensus_file + ": " + str(e))

        self.consensus_update(routers, weights, exclude_nodes)

        if self.enable_vanguards:
            self.configure_tor(controller)

        try:
            with open(self.state_file, "wb") as file_stream:
                self.write_to_file(file_stream)

        except IOError as e:
            plog("ERROR", "Cannot write state to " + self.state_file + ": " + str(e))
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
            controller.set_conf("GuardLifetime", str(LAYER1_LIFETIME_DAYS) + " days")

        try:
            controller.set_conf("HSLayer2Nodes", self.layer2_guardset())

            if NUM_LAYER3_GUARDS:
                controller.set_conf("HSLayer3Nodes", self.layer3_guardset())
        except stem.InvalidArguments:
            plog("ERROR",
                "Vanguards requires Tor 0.3.3.x (and ideally 0.3.4.x or newer).")
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

    # Adds a new layer2 guard
    def add_new_layer2(self, generator, excluded):
        guard = next(generator)
        while guard.fingerprint in map(lambda g: g.idhex, self.layer2) or \
                excluded.router_is_excluded(guard):
            guard = next(generator)

        now = time.time()
        expires = now + max(random.uniform(MIN_LAYER2_LIFETIME_HOURS * _SEC_PER_HOUR,
                                            MAX_LAYER2_LIFETIME_HOURS * _SEC_PER_HOUR),
                            random.uniform(MIN_LAYER2_LIFETIME_HOURS * _SEC_PER_HOUR,
                                            MAX_LAYER2_LIFETIME_HOURS * _SEC_PER_HOUR))
        self.layer2.append(GuardNode(guard.fingerprint, now, expires))
        plog("INFO", "New layer2 guard: " + guard.fingerprint)

    def add_new_layer3(self, generator, excluded):
        guard = next(generator)
        while guard.fingerprint in map(lambda g: g.idhex, self.layer3) or \
                excluded.router_is_excluded(guard):
            guard = next(generator)

        now = time.time()
        expires = now + max(random.uniform(MIN_LAYER3_LIFETIME_HOURS * _SEC_PER_HOUR,
                                            MAX_LAYER3_LIFETIME_HOURS * _SEC_PER_HOUR),
                            random.uniform(MIN_LAYER3_LIFETIME_HOURS * _SEC_PER_HOUR,
                                            MAX_LAYER3_LIFETIME_HOURS * _SEC_PER_HOUR))
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
        # Trim layers in case params changed
        self.layer2 = self.layer2[:NUM_LAYER2_GUARDS]
        self.layer3 = self.layer3[:NUM_LAYER3_GUARDS]

        while len(self.layer2) < NUM_LAYER2_GUARDS:
            self.add_new_layer2(generator, excluded)

        while len(self.layer3) < NUM_LAYER3_GUARDS:
            self.add_new_layer3(generator, excluded)


def terminate_process(process: Process) -> None:
    if not isinstance(process, Process):
        return

    process.terminate()
    process.join()


class Vanguards:

    def __init__(
            self, tor_data_directory_path: str,
            control_port: int, control_password: str
            ) -> None:

        self.control_port = control_port
        self.control_password = control_password
        self.tor_data_directory_path  = tor_data_directory_path

    def _control_loop(self, state: VanguardState) -> str:
        try:
            controller = stem.control.Controller.from_port(
                "127.0.0.1", self.control_port
            )
        except stem.SocketError as e:
            return "failed: " + str(e)

        control.authenticate_any(controller, self.control_password)

        try:
            state.new_consensus_event(controller, None)
        except stem.DescriptorUnavailable as e:
            controller.close()
            plog("NOTICE", "Tor needs descriptors: " + str(e) + ". Trying again...")
            return "failed: " + str(e)

        controller.add_event_listener(
            functools.partial(
                rendguard.RendGuard.circ_event,
                state.rendguard, controller
            ),
            stem.control.EventType.CIRC
        )

        bandwidths = bandguards.BandwidthStats(controller)

        controller.add_event_listener(
            functools.partial(bandguards.BandwidthStats.circ_event, bandwidths),
            stem.control.EventType.CIRC
        )
        controller.add_event_listener(
            functools.partial(bandguards.BandwidthStats.orconn_event, bandwidths),
            stem.control.EventType.ORCONN
        )

        paths = pathverify.PathVerify(
            controller, True, NUM_LAYER1_GUARDS,
            NUM_LAYER2_GUARDS, NUM_LAYER3_GUARDS
        )

        controller.add_event_listener(
            functools.partial(pathverify.PathVerify.circ_event, paths),
            stem.control.EventType.CIRC
        )
        controller.add_event_listener(
            functools.partial(pathverify.PathVerify.circ_minor_event, paths),
            stem.control.EventType.CIRC_MINOR
        )
        controller.add_event_listener(
            functools.partial(pathverify.PathVerify.orconn_event, paths),
            stem.control.EventType.ORCONN
        )
        controller.add_event_listener(
            functools.partial(pathverify.PathVerify.guard_event, paths),
            stem.control.EventType.GUARD
        )
        controller.add_event_listener(
            functools.partial(pathverify.PathVerify.conf_changed_event, paths),
            stem.control.EventType.CONF_CHANGED
        )

        # After launch pathverify, we send a NEWNYM to get fresh circs and
        # vg-lite guards
        controller.signal("NEWNYM")

        # Thread-safety: We're effectively transferring controller to the event
        # thread here.
        controller.add_event_listener(
            functools.partial(
                VanguardState.new_consensus_event,
                state, controller
            ),
            stem.control.EventType.NEWCONSENSUS
        )
        controller.add_event_listener(
            functools.partial(
                VanguardState.signal_event,
                state, controller
            ),
            stem.control.EventType.SIGNAL
        )

        while controller.is_alive():
            time.sleep(1)

        return "closed"

    def _run_thread_worker(self, state: VanguardState, thread_id: Optional[int] = None) -> None:
        if thread_id is not None:
            plog("NOTICE", f"Thread {thread_id + 1} starting _control_loop.")

        reconnects = 0
        last_connected_at = None
        while True:
            ret = self._control_loop(state)
            if not last_connected_at:
                last_connected_at = time.time()

            # Try once per second but only tell the user every 10 seconds
            if ret == "closed" or reconnects % 10 == 0:
                if time.time() - last_connected_at > bandguards.CONN_MAX_DISCONNECTED_SECS:
                    plog("WARN", f"Tor daemon connection {ret} in thread {thread_id}. Trying again...")
                else:
                    plog("NOTICE", f"Tor daemon connection {ret} in thread {thread_id}. Trying again...")

            reconnects += 1
            time.sleep(1)

    def _thread_worker(self, state: VanguardState, thread_id: Optional[int] = None) -> None:
        no_keyboard_interrupt(self._run_thread_worker, state, thread_id)

    def run(self, threads: Optional[int] = None) -> None:
        if not isinstance(threads, int) or threads < 1:
            threads = 1

        state_file_path = os.path.join(self.tor_data_directory_path, "vanguards.state")

        plog("NOTICE", "Creating new vanguard state file at: " + state_file_path)
        state = VanguardState(state_file_path)

        state.enable_vanguards = True
        stem.response.events.PARSE_NEWCONSENSUS_EVENTS = False

        process_list: list[Process] = []

        for i in range(threads):
            if threads == 1:
                i = None

            process = Process(target = self._thread_worker, args=(state, i))
            process.start()

            atexit.register(terminate_process, process = process)

            process_list.append(process)

        for process in process_list:
            if not process.is_alive():
                continue

            process.join()

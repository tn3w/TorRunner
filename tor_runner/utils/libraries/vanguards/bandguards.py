"""
bandguards.py

Simple checks against bandwidth side channels


The Vanguards Onion Service Addon

This is an edited version of Vanguards that has been edited for use with TorRunner,
changes have not been verified for integrity by The Tor Project, Inc. or any other entity.

License: MIT https://github.com/mikeperry-tor/vanguards/blob/master/LICENSE
Source: https://github.com/mikeperry-tor/vanguards
"""

import time
import stem

from .logger import plog

############ BandGuard Options #################

# Kill a circuit if this many read+write bytes have been exceeded.
# Very loud application circuits could be used to introduce timing
# side channels.
# Warning: if your application has large resources that cannot be
# split up over multiple requests (such as large HTTP posts for eg:
# securedrop, or sharing large files via onionshare), you must set
# this high enough for those uploads not to get truncated!
CIRC_MAX_MEGABYTES = 0

# Kill circuits older than this many seconds.
# Really old circuits will continue to use old guards after the TLS connection
# has rotated, which means they will be alone on old TLS links. This lack
# of multiplexing may allow an adversary to use netflow records to determine
# the path through the Tor network to a hidden service.
CIRC_MAX_AGE_HOURS = 24 # 1 day

# Maximum size for an hsdesc fetch (including setup+get+dropped cells)
CIRC_MAX_HSDESC_KILOBYTES = 30

# Maximum number of bytes allowed on a service intro circ before close
CIRC_MAX_SERV_INTRO_KILOBYTES = 0

# Warn if Tor can't build or use circuits for this many seconds
CIRC_MAX_DISCONNECTED_SECS = 30

# Warn if Tor has no connections for this many seconds
CONN_MAX_DISCONNECTED_SECS = 15

############ Constants ###############
_CELL_PAYLOAD_SIZE = 509
_RELAY_HEADER_SIZE = 11
_RELAY_PAYLOAD_SIZE = _CELL_PAYLOAD_SIZE - _RELAY_HEADER_SIZE

# Because we have to map circuits to guard destroy events, we need.
# The event really should arrive in the same second, but let's
# give it until the next couple in case there is a scheduled events hiccup
_MAX_CIRC_DESTROY_LAG_SECS = 2

class BwCircuitStat:
    def __init__(self, circ_id, is_hs):
        self.circ_id = circ_id
        self.is_hs = is_hs
        self.is_service = 1
        self.is_hsdir = 0
        self.is_serv_intro = 0
        self.dropped_cells_allowed = 0
        self.purpose = None
        self.hs_state = None
        self.old_purpose = None
        self.old_hs_state = None
        self.in_use = 0
        self.built = 0
        self.created_at = time.time()
        self.read_bytes = 0
        self.sent_bytes = 0
        self.delivered_read_bytes = 0
        self.delivered_sent_bytes = 0
        self.overhead_read_bytes = 0
        self.overhead_sent_bytes = 0
        self.guard_fp = None
        self.possibly_destroyed_at = None

    def total_bytes(self):
        return self.read_bytes + self.sent_bytes

    def dropped_read_cells(self):
        return self.read_bytes / _CELL_PAYLOAD_SIZE - \
               (self.delivered_read_bytes + self.overhead_read_bytes) / _RELAY_PAYLOAD_SIZE


class BwGuardStat:
    def __init__(self, guard_fp):
        self.to_guard = guard_fp
        self.killed_conns = 0
        self.killed_conn_at = 0
        self.killed_conn_pending = False
        self.conns_made = 0
        self.close_reasons = {}  # key=reason val=count


class BandwidthStats:
    def __init__(self, controller):
        self.controller = controller
        self.circs = {}  # key=circid val=BwCircStat
        self.live_guard_conns = {}  # key=connid val=BwGuardStat
        self.guards = {}  # key=guardfp val=BwGuardStat
        self.circs_destroyed_total = 0
        self.no_conns_since = int(time.time())
        self.no_circs_since = None
        self.network_down_since = None
        self.max_fake_id = -1
        self.disconnected_circs = False
        self.disconnected_conns = False
        self._orconn_init(controller)
        self._network_liveness_init(controller)

    def _network_liveness_init(self, controller):
        if controller.get_info("network-liveness") != "up":
            self.network_down_since = int(time.time())

    def _orconn_init(self, controller):
        fake_id = 0
        for l in controller.get_info("orconn-status").split("\n"):
            if not len(l):
                continue

            self.orconn_event(
                stem.response.ControlMessage.from_str(
                    "650 ORCONN " + l + " ID=" + str(fake_id) + "\r\n", "EVENT"
                )
            )
            fake_id += 1

        self.max_fake_id = fake_id - 1

    def _fixup_orconn_event(self, event):
        guard_fp = event.endpoint_fingerprint
        fake_id = self.max_fake_id
        while fake_id >= 0:
            if (
                str(fake_id) in self.live_guard_conns
                and self.live_guard_conns[str(fake_id)].to_guard == guard_fp
            ):
                event.id = str(fake_id)
            fake_id -= 1

    def orconn_event(self, event):
        guard_fp = event.endpoint_fingerprint
        if guard_fp not in self.guards:
            self.guards[guard_fp] = BwGuardStat(guard_fp)

        if event.status == "CONNECTED":
            if self.disconnected_conns:
                disconnected_secs = event.arrived_at - self.no_conns_since
                plog("NOTICE", f"Reconnected to the Tor network after {str(disconnected_secs)} seconds.")

            self.live_guard_conns[event.id] = self.guards[guard_fp]
            self.guards[guard_fp].conns_made += 1
            self.no_conns_since = 0
            self.disconnected_conns = False

        elif event.status in ["CLOSED", "FAILED"]:
            if event.id not in self.live_guard_conns:
                self._fixup_orconn_event(event)

            if event.id in self.live_guard_conns:
                for c in self.circs.values():
                    if c.in_use and c.guard_fp == guard_fp:
                        c.possibly_destroyed_at = event.arrived_at
                        self.live_guard_conns[event.id].killed_conn_at = event.arrived_at

                        plog("INFO", "Marking possibly destroyed circ {} at {}".format(
                             c.circ_id, event.arrived_at))

                del self.live_guard_conns[event.id]
                if len(self.live_guard_conns) == 0 and not self.no_conns_since:
                    self.no_conns_since = event.arrived_at

            if event.status == "CLOSED":
                if event.reason not in self.guards[guard_fp].close_reasons:
                    self.guards[guard_fp].close_reasons[event.reason] = 0
                self.guards[guard_fp].close_reasons[event.reason] += 1

        plog("INFO", event.raw_content())

    def circuit_destroyed(self, event):
        self.circs_destroyed_total += 1
        guard_fp = event.path[0][0]
        if event.arrived_at - self.guards[guard_fp].killed_conn_at <= _MAX_CIRC_DESTROY_LAG_SECS:
            self.guards[guard_fp].killed_conn_at = 0
            self.guards[guard_fp].killed_conns += 1
            plog(
                "NOTICE",
                "The connection to guard " + guard_fp + " was closed with a live circuit.",
            )

        plog(
            "INFO",
            "The connection to guard " + guard_fp + " was closed with circuit " + event.id + " on it.",
        )

    def any_circuits_pending(self, except_id=None):
        for c in self.circs.values():
            if not c.built and c.circ_id != except_id:
                return True
        return False  # All circuits in use

    def circ_event(self, event):
        if event.status == stem.CircStatus.FAILED and not self.no_circs_since and self.any_circuits_pending(event.id):
            self.no_circs_since = event.arrived_at

        if event.status in [stem.CircStatus.FAILED, stem.CircStatus.CLOSED]:
            if event.id in self.circs:
                if self.circs[event.id].in_use and self.circs[event.id].possibly_destroyed_at:
                    if (
                        event.arrived_at - self.circs[event.id].possibly_destroyed_at
                        <= _MAX_CIRC_DESTROY_LAG_SECS
                        and event.remote_reason == "CHANNEL_CLOSED"
                    ):
                        self.circuit_destroyed(event)

                    else:
                        plog("INFO", "Circuit {} possibly destroyed, but outside of the time window ({} - {})".format(
                             event.id, event.arrived_at, self.circs[event.id].possibly_destroyed_at))

                plog("DEBUG", "Closed hs circ for " + event.raw_content())
                del self.circs[event.id]

            return

        if event.id not in self.circs:
            self.circs[event.id] = BwCircuitStat(
                event.id, event.hs_state or event.purpose[:2] == "HS"
            )

            if event.purpose.startswith("HS_CLIENT"):
                self.circs[event.id].is_service = 0
            elif event.purpose.startswith("HS_SERVICE"):
                self.circs[event.id].is_service = 1

            if event.purpose in ["HS_CLIENT_HSDIR", "HS_SERVICE_HSDIR"]:
                self.circs[event.id].is_hsdir = 1
            elif event.purpose == "HS_SERVICE_INTRO":
                self.circs[event.id].is_serv_intro = 1

            plog("DEBUG", "Added circ for " + event.raw_content())

        self.circs[event.id].purpose = event.purpose
        self.circs[event.id].hs_state = event.hs_state

        if event.status in [stem.CircStatus.BUILT, "GUARD_WAIT"]:
            self.circs[event.id].built = 1

            if self.disconnected_circs:
                disconnected_secs = event.arrived_at - self.no_circs_since
                plog("NOTICE", f"Circuit use resumed after {str(disconnected_secs)} seconds.")
            self.no_circs_since = None
            self.disconnected_circs = False

            if event.purpose.startswith("HS_CLIENT") or event.purpose.startswith("HS_SERVICE"):
                self.circs[event.id].in_use = 1
                self.circs[event.id].guard_fp = event.path[0][0]
                plog(
                    "DEBUG", "Circ " + event.id +
                    f" now in-use. {self.circs[event.id].delivered_read_bytes} delivered bytes."
                )

        elif event.status == "EXTENDED":
            if self.disconnected_circs:
                disconnected_secs = event.arrived_at - self.no_circs_since
                plog("NOTICE", f"Circuit use resumed after {str(disconnected_secs)} seconds.")

            self.no_circs_since = None
            self.disconnected_circs = False

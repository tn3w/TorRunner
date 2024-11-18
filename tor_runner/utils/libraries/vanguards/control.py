"""
control.py

The Vanguards Onion Service Addon

This is an edited version of Vanguards that has been edited for use with TorRunner,
changes have not been verified for integrity by The Tor Project, Inc. or any other entity.

License: MIT https://github.com/mikeperry-tor/vanguards/blob/master/LICENSE
Source: https://github.com/mikeperry-tor/vanguards
"""

import sys
import getpass

import stem

from .logger import plog

__version__ = "0.4.0-dev1"
_CLOSE_CIRCUITS = True

def authenticate_any(controller, passwd=""):
    try:
        controller.authenticate()
    except stem.connection.MissingPassword:
        if passwd == "":
            passwd = getpass.getpass("Controller password: ")

        try:
            controller.authenticate(password=passwd)
        except stem.connection.PasswordAuthFailed:
            plog("NOTICE", "Unable to authenticate, password is incorrect")
            sys.exit(1)
    except stem.connection.AuthenticationFailure as exc:
        plog("NOTICE", "Unable to authenticate:", exc)
        sys.exit(1)

    plog("NOTICE", "Vanguards {} connected to Tor {} using stem {}".format(
         __version__, controller.get_version(), stem.__version__))

def get_consensus_weights(consensus_filename):
    parsed_consensus = next(stem.descriptor.parse_file(
        consensus_filename,
        document_handler=stem.descriptor.DocumentHandler.BARE_DOCUMENT))

    assert parsed_consensus.is_consensus
    return parsed_consensus.bandwidth_weights

def try_close_circuit(controller, circ_id):
    if controller._logguard:
        controller._logguard.dump_log_queue(circ_id, "Pre")

    if _CLOSE_CIRCUITS:
        try:
            controller.close_circuit(circ_id)
            plog("INFO", "We force-closed circuit " + str(circ_id))
        except stem.InvalidRequest as e:
            plog("INFO", "Failed to close circuit " + str(circ_id) + ": " + str(e.message))

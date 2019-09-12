
from . lib.utils import get_class
from . lib.utils import get_attributes
from . lib.utils import parse_apic_version
from . lib.utils import pretty_print
import logging
import re

# module level logging
logger = logging.getLogger(__name__)

class VerifySoftwareVersion(object):
    """ Verify that the fabric is currently running a recommended version of code. More details
        on the long-lived and recommended released can be found on cisco.com:
        https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/recommended-release/b_Recommended_Cisco_ACI_Releases.html
    """
    MINIMUM_VERSION = "3.2(7f)"
    def execute_check(self):
        # check current version against minimum recommended version
        self.success = False
        min_version = parse_apic_version(self.MINIMUM_VERSION)
        if min_version is None:
            self.details = "failed to parse minimum version %s" % self.MINIMUM_VERSION
            return
        for obj in get_class(self.session, "firmwareCtrlrRunning"):
            attr = get_attributes(obj)
            if obj is None:
                self.details = "failed to read or parse firmwareCtrlrRunning"
                return
            version = parse_apic_version(attr["version"])
            if version is None:
                self.details = "failed to parse APIC version %s" % attr["version"]
                return

            # will check major/min/build and ignore patch for version check for now
            min_matched = True
            if version["major"] < min_version["major"]:
                min_matched = False
            elif version["major"] == min_version["major"]:
                if version["minor"] < min_version["minor"]:
                    min_matched = False
                elif version["minor"] == min_version["minor"]:
                    min_matched = (version["build"] >= min_version["build"])
            if not min_matched:
                self.details = "current version %s is below the minimum version of code %s. " % (
                                    attr["version"], self.MINIMUM_VERSION)
                self.details+= "Please see the upgrade Matrix tool to plan an upgrade."
                return
            else:
                self.details = "version %s meets minimum recommended value" % attr["version"]
                self.success = True
                return

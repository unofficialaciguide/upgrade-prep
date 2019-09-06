
from . lib.utils import format_seconds
from . lib.utils import get_class
from . lib.utils import get_attributes
from . lib.utils import parse_timestamp
import logging
import time

# module level logging
logger = logging.getLogger(__name__)

class ConfigExportCheck(object):
    """ A recent configuration export is recommended for recovery steps prior to any upgrade. In
        general, it is best practice to regular take configuration backups of your fabric. Ensure
        that you have a remote copy of the export incase data is lost on the APIC.
    """
    LAST_EXPORT = 86400 * 3     # within 3 days
    def execute_check(self):
        # execute check can set self.details with any details to display to user and set
        # self.success to boolean indicating whether it passed/failed. Note, self.session is set
        # by the executor and always available during execute_check
        qtf = 'and(eq(configJob.type,"export"))'
        orderBy = 'configJob.lastStepTime|desc'
        for export in get_class(self.session, "configJob", queryTargetFilter=qtf, orderBy=orderBy):
            if export is None:
                self.details = "failed to read configJob objects"
                self.success = False
                return
            else:
                attr = get_attributes(export)
                if attr is None or len(attr) == 0:
                    self.details = "failed to parse configJob attributes!"
                    self.success = False
                    return
                if attr["operSt"] == "success":
                    # check that 
                    delta = time.time() - parse_timestamp(attr["executeTime"])
                    if delta > self.LAST_EXPORT:
                        self.detail = "Last export %s is too old: %s. " % (attr["fileName"],
                                format_seconds(delta))
                        self.detail+= "Generate a more recent config export before proceeding"
                        self.success = False
                        return
                    else:
                        self.details = "Found a recent config export, ensure that a remote copy "
                        self.details+= "also exists:\n%s" % attr["fileName"]
                        self.success = True
                        return
        self.details = "No config export found, please create one before proceeding with an upgrade"
        self.success = False


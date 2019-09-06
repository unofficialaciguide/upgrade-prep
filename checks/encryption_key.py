
from . lib.utils import get_attributes
import logging

# module level logging
logger = logging.getLogger(__name__)

class EncryptionKeyCheck(object):
    """ EncryptionKey is strongly recommended to include passwords and other fields in the
        configuration snapshot and exports. This smooths out the process of importing the
        configuation.
    """
    def execute_check(self):
        # execute check must always return a bool representing whether check passed. Further details
        # can be included in self.details which may be printed based on user preference.
        key_configured = get_attributes(
            session=self.session,
            dn="uni/exportcryptkey",
            attribute="keyConfigured"
        )
        if key_configured is None:
            self.details = "pkiExportEncryptionKey object not found"
        elif key_configured == "yes":
            self.success = True
        else:
            self.details = "Encryption key not configured"
        return self.success


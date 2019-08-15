


from utils import build_query_filters
from utils import offline_collect
from utils import offline_extract
from utils import setup_logger
from utils import get_cmd
from utils import get_class


import argparse
import logging
import subprocess
import sys
import traceback

import json
import os
import re
import shutil
import uuid

logger = logging.getLogger(__name__)

REQUIRED_CLASSES = [
    #global aes encryption
    ("pkiExportEncryptionKey", {}),
    #config export job
    ("configJob", {"queryTargetFilter": "and(eq(configJob.type,'export'))",
                   "orderBy": "configJob.lastStepTime|desc"}),
    #apic cluster health
    ("infraWiNode", {}),
    #faults
    ("faultInfo", {}),
    #Running firmware
    ("firmwareRunning", {})
]

class upgrade_rdy(object):
    """ This will check a variety of options to determine if there are any blockers
    to a succesful upgrade.
    """
    def __init__(self, offline=None, tmp_dir="/tmp", enforce=None):
        self.offline_mode = False
        self.offline_filename = offline
        self.offline_dir = None
        self.offline_files = {}
        self.export_date = None
        self.export_status = None
        self.encryption = None
        self.version = None

        if self.offline_filename is not None:
            self.offline_mode = True
            self.offline_dir = os.path.abspath("%s/%s" % (tmp_dir, uuid.uuid4()))
            os.makedirs(self.offline_dir)
            keys = [c[0] for c in REQUIRED_CLASSES]
            logger.info("extracting offline files %s", self.offline_filename)
            self.offline_files = offline_extract(self.offline_filename, keys,
                                            offline_dir=self.offline_dir)

    def stream_offline_class(self, classname, **kwargs):
        """ stream results of classname and optional kwargs. If running in offline mode this walks
            through each file (ignoring the filters) or yields None if not found
        """
        if classname not in self.offline_files or len(self.offline_files[classname])==0:
            logger.error("classname '%s' not found in offline files", classname)
            yield None
        else:
            for fname in self.offline_files[classname]:
                with open(fname, "r") as f:
                    data = json.load(f)
                    if type(data) is dict and "imdata" in data:
                        data = data["imdata"]
                    for obj in data:
                        yield obj

    def stream_class(self, classname, **kwargs):
        """ returns an iterator from online data or offline data for provided classname.
            this function will return just the 'attributes' merged with 'children' along with
            classname so calling function doesn't have to repeat this action.
        """
        method = None
        if self.offline_mode:
            method = self.stream_offline_class
        else:
            method = get_class
            kwargs["stream"] = True
        for obj in method(classname, **kwargs):
            if type(obj) is dict and len(obj)>0:
                cname = obj.keys()[0]
                if "attributes" in obj[cname]:
                    attr = obj[cname]["attributes"]
                    if "children" in obj[cname] and len(obj[cname]["children"])>0:
                        attr["children"] = obj[cname]["children"]
                    attr["classname"] = cname
                    yield attr
                else:
                    logger.warn("object %s missing 'attributes': %s", classname, obj)
            else:
                logger.warn("invalid return object of class %s: %s", classname, obj)

    def export_check(self):
        logger.debug("checking export status")

        for obj in self.stream_class("pkiExportEncryptionKey"):

            if "yes" in obj["keyConfigured"]:
                self.encryption = True
            else:
                self.encryption = False
            #print self.encryption


        for obj in self.stream_class("configJob"):
            print obj
            if 'success' in obj['details']:
                print obj['executeTime']
            pass









if not hasattr(subprocess, "check_output"):
    m = """
    When executing from the APIC, you must use the python2.7 library:
        /usr/bin/python2.7 %s
    """ % __file__
    sys.exit(m)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--offline",
        action="store",
        dest="offline",
        default=None,
        help="""path to offline data bundle when executing analysis in offline mode """
    )
    parser.add_argument(
        "--offlineHelp",
        action="store_true",
        dest="offlineHelp",
        help="print further offline help instructions"
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        choices=["debug", "info", "warn"],
        default="info"
    )

    args = parser.parse_args()
    setup_logger(logger, args.debug)
    setup_logger(logging.getLogger("upgrade_prep"), args.debug)
    setup_logger(logging.getLogger("utils"), args.debug)

    if args.offlineHelp:

        curls = []
        for c in REQUIRED_CLASSES:
            cname = c[0]
            opts = ""
            if len(c[1])>0:
                opts = list((" --data-urlencode \"%s\" " % (opt) for opt in build_query_filters(list=True,**c[1] )))
                query = "  icurl -G \"localhost:7777/api/class/%s.json\" %s > /tmp/off_%s.json ;" % (
                                cname,"".join(opts),cname)

            else:
                query = "  icurl -G \"localhost:7777/api/class/%s.json\" > /tmp/off_%s.json ;" % (
                                cname,cname)

            curls.append(query)
        if len(curls)>0:
            curls = [""] + curls + [""]

        offline = """
  When executing in offline mode, ensure that all required data is present in
  input tar file. Use the below bash script to collect all the required info
  in the supported format.
  Once all commands have completed, the final tar file can be found at:
    /tmp/offline_data.tgz

  # executed within bash shell
  bash -c '
  %s

  # compress and combine files
  rm /tmp/offline_data.tgz ;
  tar -zcvf /tmp/offline_data.tgz /tmp/off_* ;
  rm /tmp/off_* ;
  '
        """ % ("\n".join(curls))
        print(offline)

    else:
        try:
            check = upgrade_rdy(offline = args.offline)
            check.export_check()
            print "Goodbye"
        except KeyboardInterrupt as e:
            print("\nBye!\n")
            sys.exit(1)
        except Exception as e:
            logger.error("An error occurred: %s", e)
            logger.debug("Traceback:\n%s", traceback.format_exc())
            sys.exit(1)
        finally:
            pass


from .lib.utils import print_table
from importlib import import_module
import logging
import re
import time
import traceback

# module level logging
logger = logging.getLogger(__name__)

ALL_CHECKS = [
    # list of tuples containing package and module that has execute_check function
    ("encryption_key", "EncryptionKeyCheck"),
    ("config_export", "ConfigExportCheck"),
]

# moduleNotFoundError present in 3.6 only
try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

class CheckExecutor(object):
    def __init__(self, session):
        self.session = session

    def execute_all_checks(self):
        """ import and execute each check within local package printing the results to the user
            based on user output preference
        """
        headers = [
            {"name": "Check", "length": 25},
            {"name": "Description", "length": 50},
            {"name": "Pass/Fail", "length": 10},
            {"name": "Pass/Fail Reason", "length": 50},
        ]
        results = []
        total_checks = 0
        total_pass = 0
        total_fail = 0
        total_time = 0
        start_time = time.time()
        for (package, classname) in ALL_CHECKS:
            try:
                ts = time.time()
                # force relative import from this package (checks) always
                if not re.search("^\.", package):
                    package = ".%s" % package
                check = getattr(import_module(package, "checks"), classname)()
                setattr(check, "session", self.session)
                setattr(check, "success", False)
                setattr(check, "details", "")
                # set a description attribute from doc string if not present
                if not hasattr(check, "description") or len(check.description) == 0:
                    if len(check.__doc__) > 0:
                        setattr(check, "description", check.__doc__)
                    else:
                        setattr(check, "description", "")
                # force description to be single line
                check.description = " ".join(check.description.strip().split())
                if hasattr(check, "execute_check"):
                    # will read check.success or return value from execute_check, preferring return
                    # value if not None
                    total_checks+=1
                    try:
                        success = check.execute_check()
                        if success is not None:
                            check.success = success
                        success = check.success
                        if success:
                            total_pass+=1
                        else:
                            total_fail+=1
                        results.append([
                            "%s\ntime: %0.3f" % (classname, time.time() - ts),
                            check.description,
                            #"pass" if success else "\033[1;37;41m FAIL",
                            "Pass" if success else "FAIL",
                            check.details,
                        ])
                    except Exception as e:
                        logger.error("exeception occurred executing check %s: %s", classname, e)
                        logger.debug("Traceback:\n%s", traceback.format_exc())
                else:
                    logger.error("%s missing required execute_check function", classname)
            except AttributeError as e:
                logger.error("classname %s not found in package %s", classname, package)
                logger.debug("Traceback:\n%s", traceback.format_exc())
            except ModuleNotFoundError as e:
                logger.error("package %s not found", package)
            except Exception as e:
                logger.error("exception executing check %s", classname)
                logger.debug("Traceback:\n%s", traceback.format_exc())

        total_time = time.time() - start_time
        print_table(headers, results)
        print("Total checks: %s" % total_checks)
        print("Total pass  : %s" % total_pass)
        print("Total fail  : %s" % total_fail)
        print("Total time  : %0.3f" % total_time)



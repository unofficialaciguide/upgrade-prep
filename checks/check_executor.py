
from .lib.utils import format_seconds
from .lib.utils import print_table
from .lib.utils import terminal_refresh
from importlib import import_module
import logging
import re
import sys
import threading
import time
import traceback

# module level logging
logger = logging.getLogger(__name__)

ALL_CHECKS = [
    # list of tuples containing package and module that has execute_check function
    ("cluster_health", "ClusterHealth"),
    ("config_export", "ConfigExportCheck"),
    ("encryption_key", "EncryptionKeyCheck"),
    ("fd_vnid_check", "FdVnidCheck"),
    ("verify_faults", "VerifyFaults"),
    ("verify_software_version", "VerifySoftwareVersion"),
]

# moduleNotFoundError present in 3.6 only
try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

class CheckExecutor(object):
    def __init__(self, session, debug_enabled=False):
        self.session = session
        self.debug_enabled = debug_enabled

        # print progress at regular interval
        self.progress_thread = None
        self._exit = False
        self.current_check = 0
        self.current_check_name = "-"
        self.total_checks = len(ALL_CHECKS)
        self.executed_checks = 0
        self.total_pass = 0
        self.total_fail = 0
        self.start_time = 0
        self.results = []

    def execute_all_checks(self):
        """ wrapper to execute all configured checks """
        try:
            self.start_time = time.time()
            self.progress_thread = threading.Thread(target=self.print_status)
            self.progress_thread.daemon =True
            self.progress_thread.start()
            self._execute_all_checks()
        finally:
            self._exit = True
            self.progress_thread.join()

    def _execute_all_checks(self):
        """ import and execute each check within local package printing the results to the user
            based on user output preference
        """
        for (package, classname) in ALL_CHECKS:
            self.current_check+=1
            self.current_check_name = classname
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
                    try:
                        success = check.execute_check()
                        if success is not None:
                            check.success = success
                        success = check.success
                        if success:
                            self.total_pass+=1
                        else:
                            self.total_fail+=1
                        self.results.append([
                            "%s\ntime: %0.3f" % (classname, time.time() - ts),
                            check.description,
                            #"pass" if success else "\033[1;37;41m FAIL",
                            "Pass" if success else "FAIL",
                            check.details,
                        ])
                    except Exception as e:
                        logger.debug("Traceback:\n%s", traceback.format_exc())
                        # add to results as an internal failure
                        self.total_fail+=1
                        self.results.append([
                            "%s\ntime: %0.3f" % (classname, time.time() - ts),
                            check.description,
                            "FAIL",
                            "Internal failure during check execution: %s" % e,
                        ])
                    # completed check
                    self.executed_checks+=1
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

    def print_status(self):
        """ print the progress status for user at regular interval once checks start. Use a
            background thread so user has real-time progress.
            check (x/y): <check-name>
            [ ..... ] %s, time: <total-time>
        """
        print_count = 0
        while True:
            ts = time.time()
            runtime = format_seconds(ts - self.start_time, milli=False)
            progress = ((1.0*self.current_check - 1)/self.total_checks)*100.0
            if self._exit:
                # force progress to 100% when completed
                progress = 100.0
            pc = int(0.5 * progress)
            rows = [
                "Progress (%s/%s), Executing: %s" % (self.current_check,
                                                    self.total_checks, self.current_check_name),
                "[%s%s] %0.2f%%, %s" % ('='*pc, ' '*(50 - pc), progress, runtime)
            ]
            # if debugging was enabled then do not execute terminal refresh
            if not self.debug_enabled:
                if print_count == 0:
                    sys.stdout.write("\n" * (len(rows) + 2))
                terminal_refresh(rows+[""])
                print_count+=1
            if self._exit:
                # hard stop...
                self.print_results()
                return
            else:
                time.sleep(0.25)

    def print_results(self):
        """ print the final results to the user """
        total_time = time.time() - self.start_time
        headers = [
            {"name": "Check", "length": 25},
            {"name": "Description", "length": 50},
            {"name": "Pass/Fail", "length": 10},
            {"name": "Pass/Fail Reason", "length": 70},
        ]
        print("RESULTS")
        print_table(headers, self.results)
        print("Total checks: %s" % self.executed_checks)
        print("Total pass  : %s" % self.total_pass)
        print("Total fail  : %s" % self.total_fail)
        print("Total time  : %0.3f" % total_time)
        print("")


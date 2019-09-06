""" This will check a variety of options to determine if there are any blockers to a succesful
    upgrade. It will support direct execution on the APIC or remotely through API. By default
    the script assumes it is executing on APIC but will try to auto-detect if appropriate
    arguments are not provided.  Use --help for more help.
"""
from checks.lib.utils import OnApicSession
from checks.lib.utils import get_cmd
from checks.lib.utils import get_user_input
from checks.lib.utils import setup_logger
from checks.check_executor import CheckExecutor

import argparse
import logging
import re
import sys
import traceback

logger = logging.getLogger(__name__)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        choices=["debug", "info", "warn", "error"],
        default="debug",
        help="debugging level",
    )
    parser.add_argument(
        "--mode",
        dest="mode",
        choices=["on-apic", "remote", "auto"],
        default="auto",
        help="""specify whether script is executing directly on the apic, connecting remotely which
            requires credentials and hostname, or auto-detected which will prompt the user for any
            required information.
            """,
    )
    parser.add_argument(
        "--username",
        dest="username",
        help="APIC username when executing in remote mode",
    )
    parser.add_argument(
        "--password",
        dest="password",
        help="APIC password when executing in remote mode",
    )
    parser.add_argument(
        "--hostname",
        dest="hostname",
        help="APIC hostname when executing in remote mode",
    )
    args = parser.parse_args()
    setup_logger(logger, args.debug)
    setup_logger(logging.getLogger("lib"), args.debug)
    setup_logger(logging.getLogger("checks"), args.debug)

    apic_session = OnApicSession()
    try:
        if args.mode == "auto":
            # we can execute 'which icurl' and if icurl is present then assume we're on-apic
            logger.debug("auto-detecting whether script is running on apic or remotely")
            if get_cmd("which icurl", ignore_error=True) is not None:
                logger.debug("script is executing on-apic")
                args.mode = "on-apic"
            else:
                logger.debug("icurl not found, assuming script is executing remotely")
                args.mode = "remote"
        if args.mode == "remote":
            # on-demand import of session as there is no need to import when executing on APIC
            from checks.lib.session import Session
            # we need to ensure user has provided hostname/username/password.
            args.hostname = get_user_input(args.hostname, "Enter apic hostname")
            args.username = get_user_input(args.username, "Enter apic username")
            args.password = get_user_input(args.password, "Enter apic password", password=True)
        
            # create APIC session object. hostname needs to be remapped to url but we will support
            # user provided url or just IP/hostname. Assumes https by default
            url = args.hostname
            if not re.search("^http", url.lower()):
                url = "https://%s" % args.hostname
            url = re.sub("[/]+$", "", url)
            # create/validate session to APIC
            logger.info("connecting to APIC %s", url)
            apic_session = Session(url, args.username, pwd=args.password)
            if not apic_session.login():
                logger.warn("please try again with correct credentials and hostname")
                sys.exit(1)

        executor = CheckExecutor(session=apic_session)
        executor.execute_all_checks()

    except Exception as e:
        logger.error("An error occurred: %s", e)
        logger.debug("Traceback:\n%s", traceback.format_exc())
    except KeyboardInterrupt as e:
        print("\nBye!\n")
        sys.exit(1)
    finally:
        if apic_session is not None:
            apic_session.close()

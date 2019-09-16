
from . lib.utils import get_class
from . lib.utils import get_attributes
from . lib.utils import pretty_print
import logging

# module level logging
logger = logging.getLogger(__name__)

class VerifyFaults(object):
    """ Major/Critical faults should be addressed prior to upgrading """

    def execute_check(self):
        # count the number of major/minor faults and list per fault code for user
        self.success = False
        qtf = 'or(eq(faultInfo.severity,"major"),eq(faultInfo.severity,"critical"))'
        # let's index faults by type (major/critical), then by fault code, and contain count
        faults = {
            "major": {},
            "critical": {},
        }
        for obj in get_class(self.session, "faultInfo", queryTargetFilter=qtf):
            attr = get_attributes(obj)
            if attr is None:
                self.details = "failed to read or parse faultInfo objects"
                return
            if attr['severity'] in faults:
                if attr['code'] not in faults[attr['severity']]:
                    faults[attr['severity']][attr['code']] = 0
                faults[attr['severity']][attr['code']]+=1

        # set the counts for simplicity
        major_count = len(faults['major'])
        critical_count = len(faults['critical'])

        fmt = "{0:<10} {1:<10} {2}"
        rows = [fmt.format("FaultCode", "Type", "Count")]
        rows.append(fmt.format("-"*10, "-"*10, "-"*10))
        # let's do sorted critical first and then sorted major second
        for severity in ['critical', 'major']:
            for code, count in sorted(faults[severity].items(),
                    key=lambda x: (x[1], x[0]), reverse=True):
                        rows.append(fmt.format(code, severity, count))

        if major_count > 0 or critical_count > 0:
            self.details = "One or more major/critical faults are present and should be addressed "
            self.details+= "or accounted for before continuing with the upgrade.\n\n"
            self.details+= "Critical Faults: %s\n" % critical_count
            self.details+= "Major Faults   : %s\n\n" % major_count
            self.details+= "\n".join(rows)
        else:
            self.details = "No major or critical faults present"
            self.success = True



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
        major_count = 0
        critical_count = 0
        faults = {} # indexed by fault code
        for obj in get_class(self.session, "faultInfo", queryTargetFilter=qtf):
            attr = get_attributes(obj)
            if attr is None:
                self.details = "failed to read or parse faultInfo objects"
                return
            if attr['severity'] == "critical":
                critical_count+=1
            elif attr['severity'] == "major":
                major_count+=1
            if attr['code'] not in faults:
                faults[attr['code']] = 0
            faults[attr['code']]+= 1
        
        fmt = "{0:<10} {1:<10}"
        rows = [fmt.format("FaultCode", "Count")]
        rows.append(fmt.format("-"*10, "-"*10))
        links = []
        for code, count in faults.items():
            links.append('%s/doc/html/FAULT-%s.html' % (self.session.api, code))
            rows.append(fmt.format(code, count))

        if major_count > 0 or critical_count > 0:
            self.details = "One or more major/critical faults are present and should be addressed "
            self.details+= "or accounted for before continuing with the upgrade.\n\n"
            self.details+= "Critical Count: %s\n" % critical_count
            self.details+= "Major Count   : %s\n\n" % major_count
            self.details+= "\n".join(rows)
            #self.details+= "\n\nMore info can be found here:\n"
            #self.details+= "\n".join(links)
        else:
            self.details = "No major or critical faults present"
            self.success = True


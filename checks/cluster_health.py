
from . lib.utils import get_class
from . lib.utils import get_attributes
from . lib.utils import pretty_print
import logging
import re

# module level logging
logger = logging.getLogger(__name__)

class ClusterHealth(object):
    """ Cluster must be in a healthy state for a successful upgrade. This check ensures that all
        APICs are fully fit
    """
    def execute_check(self):
        # loop through infraWiNode to get state of cluster from all APICs
        self.success = False
        fit_count = 0
        not_fit_count = 0
        regex = "topology/pod-[0-9]+/node-(?P<local>[0-9]+)/av/node-(?P<remote>[0-9]+)"
        fmt = "{0:<10} {1:<10} {2}"
        rows = [fmt.format("localApic", "ViewOfApic", "Health")]
        rows.append(fmt.format("-"*10, "-"*10, "-"*10))
        for obj in get_class(self.session, "infraWiNode", orderBy="infraWiNode.dn"):
            attr = get_attributes(obj)
            if attr is None:
                self.details = "failed to read or parse infraWiNode objects"
                return
            r1 = re.search(regex, attr["dn"])
            if r1 is None:
                self.details = "failed to parse infraWiNode dn %s" % attr["dn"]
                return
            if attr["health"] != 'fully-fit':
                not_fit_count+=1
            else:
                fit_count+= 1
            rows.append(fmt.format(
                "%s" % r1.group("local"),
                "%s" % r1.group("remote"),
                attr["health"],
            ))
        if not_fit_count > 0:
            self.details = "Cluster is not healthy, please correct cluster health before proceeding"
            self.details+= " with any upgrades.\n\n"
            self.details+= "\n".join(rows)
        elif fit_count == 0:
            self.details = "Unable to determine cluster health"
        else:
            self.details = "Cluster is healthy"
            self.success = True



"""

cluster_health_url = base_url + "node/class/infraWiNode.json"
cluster_health_req = apic.get(cluster_health_url, verify=False)


#print out view of cluster health from each apic
apic_health = [['APIC', 'View Of', 'Health']]
for node in json.loads(cluster_health_req.content)['imdata']:
    local_apic = node['infraWiNode']['attributes']['dn'].split('/')[2].split('-')[1]
    foreign_apic = node['infraWiNode']['attributes']['id']
    health = node['infraWiNode']['attributes']['health']
    apic_health.append([local_apic, foreign_apic, health])
print("*"*20 + "APIC Cluster Health" + "*"*20)
print("All APICs should see all other APICs as 'Fully Fit'")
apic_healthy = False
for row in apic_health[1:]:
    if 'fully-fit' in row[2]:
        apic_healthy = True
    else:
        print(tabulate(apic_health, headers='firstrow'))
        break
if not apic_healthy:
    print('Please determine the cause for the APIC Cluster not being fully-fit before proceeding with any upgrades.')
else:
    print('The APIC Cluster is fully-fit and safe to proceed with an upgrade.')

print("\n")
"""


from . lib.utils import get_class
from . lib.utils import get_attributes
import logging
import re
import traceback

# module level logging
logger = logging.getLogger(__name__)

# overwrite range to xrange for this check for py2/py3 compatibility
try:
    range = xrange
except NameError as e:
    pass

class FdVnidCheck(object):
    """ This check ensures that all nodes in the fabric have allocated the same EPG VNID for a
        given EPG + vlan-encap. If there is a difference between VNID encap it can cause EPM sync
        failures between nodes within a vpc domain triggering intermittent connectivity to endpoints
        on that EPG. This may also cause bridging loops if the user extends STP within the EPG as
        BPDUs will be dropped due to the inconsistency. 
    """

    def build_vlan_vnid_map(self):
        """ APIC guarantees unique VNID encap for each vlan block. This function will be a dict
            of vnid id to corresponding vlan namespace.  Generally this should be <4000 entries 
            but if customer reused full vlan range on multiple vlan pools then this could scale 
            a bit. Assuming we're under ~100K, which would be a gross misconfiguration in the fabric,
            this method should be sufficient.
            NOTE, this is for vlan only, this does not check vxlan vnid ranges
        """
        logger.debug("building vlan vnid map")
        self.vnid_map = {}
        for obj in get_class(self.session, "stpAllocEncapBlkDef"):
            attr = get_attributes(obj)
            try:
                if "vlan" in attr["from"] and "vlan" in attr["to"]:
                    pool = re.sub("/from-[^/]+$", "", attr["encapBlk"])
                    base = int(attr["base"])
                    start_vlan = int(re.sub("vlan-","", attr["from"]))
                    end_vlan = int(re.sub("vlan-","", attr["to"]))
                    for vnid in range(base, base + (end_vlan - start_vlan) + 1):
                        if vnid in self.vnid_map:
                            logger.warn("duplicate vnid %s from %s and %s", vnid, pool,
                                    self.vnid_map[vnid])
                        else:
                            self.vnid_map[vnid] = pool
                else:
                    logger.debug("skipping vxlan pool %s", attr["dn"])
            except Exception as e:
                logger.warn("failed to parse stpAllocEncapBlkDef: %s", e)
                logger.debug("Traceback:\n%s", traceback.format_exc())
        logger.debug("size of vnid map: %s", len(self.vnid_map))

    def execute_check(self):
        # execute check can set self.details with any details to display to user and set
        # self.success to boolean indicating whether it passed/failed. Note, self.session is set
        # by the executor and always available during execute_check
        """ after vlan_vnid map has been built, walk through vlanCktEp and build epg map which is
            in the format below. Highlight any epg/encap that has more than one vnid allocated.
            {
                "epg": {
                    "vlan-encap": {
                        "vnid": [list of nodes using this vnid]
                    }
                },
            }
        """
        logger.debug("executing FD check")
        self.vnid_map = {}
        self.epg_map = {}

        # build vnid mapping
        self.build_vlan_vnid_map()

        # execute check
        node_reg = re.compile("topology/pod-[0-9]+/node-(?P<node>[0-9]+)")
        for obj in get_class(self.session, "vlanCktEp", orderBy="vlanCktEp.dn"):
            attr = get_attributes(obj)
            r1 = node_reg.search(attr["dn"])
            if r1 is not None:
                if len(attr["epgDn"]) > 0 and "vlan-" in attr["encap"]:
                    epg = attr["epgDn"]
                    vnid = int(re.sub("vxlan-","", attr["fabEncap"]))
                    vlan = attr["encap"]
                    if epg not in self.epg_map:
                        self.epg_map[epg] = {}
                    if vlan not in self.epg_map[epg]: 
                        self.epg_map[epg][vlan] = {}
                    if vnid not in self.epg_map[epg][vlan]:
                        self.epg_map[epg][vlan][vnid] = []
                    self.epg_map[epg][vlan][vnid].append(r1.group("node"))
                else:
                    logger.debug("skipping %s/%s with no epgDn set", obj["dn"], obj["encap"])

        # need a small table to display to the user, will be a tuple that is
        # (encap-vlan, vnid, epg-name, pool-name)
        issues = []
        total_count = 0
        # build list of epg/encaps that have more than one vnid allocated
        for epg in self.epg_map:
            for vlan in self.epg_map[epg]:
                total_count+=1
                if len(self.epg_map[epg][vlan])>1:
                    # try to extract epg_name 
                    epg_name = epg
                    r1 = re.search("/epg-(?P<name>.+)", epg_name)
                    if r1 is not None:
                        epg_name = r1.group("name")
                    for vnid in self.epg_map[epg][vlan]:
                        pool = "vlanns-?"
                        if vnid in self.vnid_map:
                            pool = self.vnid_map[vnid]
                            # try to extract just pool name instead of full dn
                            r1 = re.search("vlanns-\[(?P<name>[^]]+)\]", pool)
                            if r1 is not None:
                                pool = r1.group("name")
                        issues.append((vlan, vnid, epg_name, pool))

        grammar = "vlan encap" if total_count==1 else "vlan encaps"
        if len(issues) > 0:
            self.success = False
            fail_grammar = "inconsistency" if len(issues)==1 else "inconsistencies"
            self.details = "%s FD %s found across %s %s.\n" % (len(issues), fail_grammar,
                                total_count, grammar)
            self.details+= "NOTE, there are valid designs where users intentionally force different "
            self.details+= "VNID allocation to isolate STP domains. Please review any "
            self.details+= "inconsistencies found and validate if they are intentional.\n\n"

            fmt = "{0:<9} {1:<8} {2:<20} {3}"
            rows = [fmt.format("EncapVlan", "Vnid", "EpgName", "VlanPool")]
            rows.append(fmt.format("-"*9, "-"*8, "-"*20, "-"*20))
            for i in issues:
                rows.append(fmt.format(*i))
            self.details+= "\n".join(rows)
        else:
            self.success = True
            self.details = "No FD inconsistencies found across %s %s" % (total_count, grammar)


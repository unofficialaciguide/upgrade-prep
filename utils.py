###############################################################################
#
# lib functions
#
###############################################################################

import logging
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tarfile
import traceback
import uuid
import requests

logger = logging.getLogger(__name__)


class apicApi(object):
    def __init__(self, username, password=None, request=None):

        logged_in = False

        if username is not None and password is not None:
            self.session = requests.Session()



def setup_logger(logger, level):
    logging_level = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARNING,
    }.get(level, logging.DEBUG)
    logger.setLevel(logging_level)
    logger_handler = logging.StreamHandler(sys.stdout)

    fmt ="%(asctime)s.%(msecs).03d||%(levelname)s||"
    fmt+="%(filename)s:%(lineno)d||%(message)s"
    logger_handler.setFormatter(logging.Formatter(
        fmt=fmt,
        datefmt="%Z %Y-%m-%dT%H:%M:%S")
    )
    logger.addHandler(logger_handler)

    # remove previous handlers if present
    for h in list(logger.handlers): logger.removeHandler(h)
    logger.addHandler(logger_handler)

def pretty_print(js):
    """ try to convert json to pretty-print format """
    try:
        return json.dumps(js, indent=4, separators=(",", ":"))
    except Exception as e:
        return "%s" % js

def get_cmd(cmd):
    """ return output of shell command, return None on error"""
    try:
        logger.debug("get_cmd: %s", cmd)
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        logger.warn("error executing command: %s", e)
        return None

def offline_extract(tgz, offline_keys, offline_dir="/tmp/"):
    """ extract files from tar archive matching list of provided keys. Will return dict indexed by
        keys with list of files that were extracted and matched the key. Note, key is assumed to be
        a regex which can match multiple files.
    """

    offline_files = {}
    for k in offline_keys:
        offline_files[k] = []

    # force odir to real directory (incase 'file' is provided as offline_dir)
    odir = os.path.abspath(offline_dir)
    try:
        t = tarfile.open(tgz, "r:gz")
        for m in t.getmembers():
            # check for files matching offline_keys
            for key in offline_keys:
                if re.search(key, m.name):
                    offline_files[key].append("%s/%s" % (odir, m.name))
                    t.extract(m, path=odir)
                    logger.debug("extracting %s/%s" % (odir, m.name))

    except Exception as e:
        logger.error("Failed to extract content from offline tar file")
        logger.debug("traceback:\n%s", traceback.print_exc())
        sys.exit(1)

    return offline_files

def offline_collect(tmp_dir="/tmp", required_classes=[], buffer_size=75000):
    """ collect all required data for offline analysis. Page the results limiting the count to the
        provided buffer_size. tar all collected files into user current directory and then cleanup
        tmp directory.
    """
    # create a temporary working directory within provided tmp directory
    tmp = "%s/%s" % (tmp_dir, uuid.uuid4())
    os.makedirs(tmp)

    def save_data(data, cname, page):
        fname = os.path.abspath("%s/%s_page%s.json" % (tmp, cname, page))
        logger.debug("saving class %s, page %s, objects %s to %s", cname, page, len(data), fname)
        with open(fname, "w") as f:
            json.dump(data, f)

    try:
        # collect required data and save to disk
        for c in required_classes:
            page = 0
            buf = []
            cname = c[0]
            opts = {}
            if len(c)> 0: opts = c[1]
            logger.info("collecting data for %s", cname)
            for obj in get_class(cname, stream=True, **opts):
                buf.append(obj)
                if len(buf) >= buffer_size:
                    save_data(buf, cname, page)
                    buf = []
                    page+= 1
            # safe whatever is left in the buffer. We also want to include empty results on the
            # first page so the file is found when executing in offline mode
            if len(buf) > 0 or (len(buf)==0 and page ==0):
                save_data(buf, cname, page)

        # tar result and save to current working directory
        tarfile = os.path.abspath("%s/coop_offline.tgz" % os.getcwd())
        cmd = "tar -zcf %s %s/*" % (tarfile, tmp)
        if get_cmd(cmd) is None:
            logger.error("failed to bundle offline data")
        else:
            print("offline data: %s" % tarfile)

    except Exception as e:
        logger.error("An error occurred during collection: %s", e)
        logger.debug("Traceback:\n%s", traceback.format_exc())

    finally:
        # always try to cleanup tmp directory
        shutil.rmtree(tmp)


def icurl(url, limit=None, page=0, page_size=75000):
    """ perform icurl for object/class based on relative dn and
        return json object.  Returns None on error
    """

    # build icurl command
    url_delim = "?"
    if "?" in url: url_delim="&"

    count_received = 0
    count_yield = 0
    # walk through pages until return count is less than page_size
    while 1:
        turl = "%s%spage-size=%s&page=%s" % (url, url_delim, page_size, page)
        logger.debug("icurl: %s",  turl)
        tstart = time.time()
        try:
            resp = get_cmd("icurl -s 'http://127.0.0.1:7777/%s'" % turl)
        except Exception as e:
            logger.warn("exception occurred in get request: %s", traceback.format_exc())
            yield None
            return
        logger.debug("response time: %f", time.time()-tstart)
        if resp is None:
            logger.warn("failed to get data: %s" % url)
            yield None
            return
        try:
            js = json.loads(resp)
            if "imdata" not in js or "totalCount" not in js:
                logger.error("failed to parse js reply: %s", pretty_print(js))
                yield None
                return
            count_received+= len(js["imdata"])
            logger.debug("time: %0.3f, results count: %s/%s", time.time() - tstart, count_received,
                    js["totalCount"])
            for obj in js["imdata"]:
                count_yield+=1
                if (limit is not None and count_yield >= limit):
                    logger.debug("limit(%s) hit or exceeded", limit)
                    return
                yield obj
            if len(js["imdata"])<page_size or count_received >= int(js["totalCount"]):
                #logger.debug("all pages received")
                return
            page+= 1
        except ValueError as e:
            logger.error("failed to decode resp: %s", resp)
            yield None
            return

def get_dn(dn, **kwargs):
    # get a single dn.  Note, with advanced queries this may be list as well
    # for now, always return single value
    opts = build_query_filters(**kwargs)
    url = "/api/mo/%s.json%s" % (dn,opts)
    ret = []
    for obj in icurl(url):
        if obj is None:
            return None
        return obj
    # empty non-None object implies valid empty response
    return {}

def get_class(classname, limit=None, stream=False, remote=False, **kwargs):
    """ perform class query. If stream is set to true then this will act as an iterator yielding the
        next result. If the query failed then the first (and only) result of the iterator will be
        None.
    """
    opts = build_query_filters(**kwargs)
    url = "/api/class/%s.json%s" % (classname, opts)
    if stream:
        return icurl(url, limit=limit)
    elif remote:
        pass
    else:
        ret = []
        for obj in icurl(url, limit=limit):
            if obj is None:
                return None
            ret.append(obj)
        return ret

def build_query_filters(list=False, **kwargs ):
    """
        queryTarget=[children|subtree]
        targetSubtreeClass=[mo-class]
        queryTargetFilter=[filter]
        rspSubtree=[no|children|full]
        rspSubtreeInclude=[attr]
        rspPropInclude=[all|naming-only|config-explicit|config-all|oper]
    """
    queryTarget         = kwargs.get("queryTarget", None)
    targetSubtreeClass  = kwargs.get("targetSubtreeClass", None)
    queryTargetFilter   = kwargs.get("queryTargetFilter", None)
    rspSubtree          = kwargs.get("rspSubtree", None)
    rspSubtreeInclude   = kwargs.get("rspSubtreeInclude", None)
    rspSubtreeClass     = kwargs.get("rspSubtreeClass", None)
    rspPropInclude      = kwargs.get("rspPropInclude", None)
    orderBy             = kwargs.get("orderBy", None)

    opts = ""
    if queryTarget is not None:
        opts+= "&query-target=%s" % queryTarget
    if targetSubtreeClass is not None:
        opts+= "&target-subtree-class=%s" % targetSubtreeClass
    if queryTargetFilter is not None:
        opts+= "&query-target-filter=%s" % queryTargetFilter
    if rspSubtree is not None:
        opts+= "&rsp-subtree=%s" % rspSubtree
    if rspSubtreeInclude is not None:
        opts+= "&rsp-subtree-include=%s" % rspSubtreeInclude
    if rspSubtreeClass is not None:
        opts+= "&rsp-subtree-class=%s" % rspSubtreeClass
    if rspPropInclude is not None:
        opts+= "&rsp-prop-include=%s" % rspPropInclude
    if orderBy is not None:
        opts+= "&order-by=%s" % orderBy

    if list:
        return opts.split('&')[1:]
    if len(opts)>0: opts = "?%s" % opts.strip("&")

    return opts

def get_mac_value(mac):
    """ takes mac string and returns 48-bit integer. this will support the following formats:
            E                   (single integer in hex format)
            E.E.E
            EE-EE-EE-EE-EE-EE
            EE.EE.EE.EE.EE.EE
            EEEE.EEEE.EEEE
        returns 0 on error
    """
    mac = "%s" % mac
    # either matches mac_reg or able to cast with base 16
    r1 = mac_reg.search(mac)
    if r1 is not None:
        o1 = int(r1.group("o1"),16) << 32
        o2 = int(r1.group("o2"),16) << 16
        o3 = int(r1.group("o3"),16)
        return o1+o2+o3
    try: return int(re.sub("[.\-:]","",mac),16)
    except Exception as e:
        logger.warn("failed to convert mac '%s' to integer: %s", mac, e)
        return 0

def get_ip_prefix(ip):
    """ receives ipv4 or ipv6 string with or without mask, determines if the address is ipv4 or ipv6
        then returns result of get_ipv4_prefix or get_ipv6_prefix
    """
    if ":" in ip:
        return get_ipv6_prefix(ip)
    return get_ipv4_prefix(ip)

ipv4_prefix_reg = "^(?P<o0>[0-9]+)\.(?P<o1>[0-9]+)\.(?P<o2>[0-9]+)\."
ipv4_prefix_reg+= "(?P<o3>[0-9]+)(/(?P<m>[0-9]+))?$"
ipv4_prefix_reg = re.compile(ipv4_prefix_reg)
def get_ipv4_prefix(ipv4):
    """ takes ipv4 string with or without prefix present and returns tuple:
            (address, mask) where addr and mask are 32-bit ints
        if no mask is present, the /32 is assumed
        mask is '1-care' format.  For example:
            /0  = 0x00000000
            /8  = 0xff000000
            /16 = 0xffff0000
            /24 = 0xffffff00
            /32 = 0xffffffff
        returns (None,None) on error
    """
    r1 = ipv4_prefix_reg.search(ipv4)
    if r1 is None:
        logger.warn("address %s is invalid ipv4 address", ipv4)
        return (None, None)
    if r1.group("m") is not None: mask = int(r1.group("m"))
    else: mask = 32
    oct0 = int(r1.group("o0"))
    oct1 = int(r1.group("o1"))
    oct2 = int(r1.group("o2"))
    oct3 = int(r1.group("o3"))
    if oct0 > 255 or oct1 > 255 or oct2 > 255 or oct3 > 255 or mask > 32:
        logger.warn("address %s is invalid ipv4 address", ipv4)
        return (None, None)

    addr = (oct0 << 24) + (oct1 << 16) + (oct2 << 8) + oct3
    mask = (~(pow(2,32-mask)-1)) & 0xffffffff
    return (addr, mask)

ipv6_prefix_reg = re.compile("^(?P<addr>[0-9a-f:]{2,40})(/(?P<m>[0-9]+))?$", re.IGNORECASE)
def get_ipv6_prefix(ipv6):
    """ takes ipv6 string with or without prefix present and returns tuple:
            (address, mask) where addr and mask are 128-bit ints
        if no mask is present, the /128 is assumed
        mask is '1-care' format.  For example:
            /0  = 0x00000000 00000000 00000000 00000000
            /24 = 0xffffff00 00000000 00000000 00000000
            /64 = 0xffffffff ffffffff 00000000 00000000
            /128= 0xffffffff ffffffff ffffffff ffffffff
        returns (None,None) on error
    """
    r1 = ipv6_prefix_reg.search(ipv6)
    if r1 is None:
        logger.warn("address %s is invalid ipv6 address", ipv6)
        return (None, None)
    if r1.group("m") is not None: mask = int(r1.group("m"))
    else: mask = 128

    upper = []
    lower = []
    # split on double colon to determine number of double-octects to pad
    dc_split = r1.group("addr").split("::")
    if len(dc_split) == 0 or len(dc_split)>2:
        logger.warn("address %s is invalid ipv6 address", ipv6)
        return (None, None)
    if len(dc_split[0])>0:
        for o in dc_split[0].split(":"): upper.append(int(o,16))
    if len(dc_split)==2 and len(dc_split[1])>0:
        for o in dc_split[1].split(":"): lower.append(int(o,16))
    # ensure there are <=8 total double-octects including pad
    pad = 8 - len(upper) - len(lower)
    if pad < 0 or pad >8:
        logger.warn("address %s is invalid ipv6 address", ipv6)
        return (None, None)

    # sum double-octects with shift
    addr = 0
    for n in (upper + [0]*pad + lower): addr = (addr << 16) + n
    mask = (~(pow(2,128-mask)-1)) & 0xffffffffffffffffffffffffffffffff
    return (addr, mask)

###############################################################################
#
# lib functions
#
###############################################################################

from textwrap import TextWrapper
import dateutil.parser
import datetime
import logging
import getpass
import json
import re
import subprocess
import sys
import time

# overwrite input for python2 support
try:
    input = raw_input
except Exception as e:
    pass

# module level logging
logger = logging.getLogger(__name__)

# static queue thresholds and timeouts
SESSION_MAX_TIMEOUT = 120   # apic timeout hardcoded to 90...
SESSION_LOGIN_TIMEOUT = 10  # login should be fast

def setup_logger(logger, level):
    """ common logging format to stdout """

    logger.setLevel({
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARNING,
        "error": logging.ERROR,
    }.get(level.lower(), logging.DEBUG))
    logger_handler = logging.StreamHandler(sys.stdout)

    if logger.level <= logging.DEBUG:
        fmt = "%(asctime)s.%(msecs).03d||%(levelname).3s||%(filename)s:%(lineno)d||%(message)s"
    else:
        fmt = "[%(asctime)s.%(msecs).03d] %(levelname).4s %(message)s"
    logger_handler.setFormatter(logging.Formatter(
        fmt=fmt,
        datefmt="%Z %Y-%m-%dT%H:%M:%S")
    )
    logger.addHandler(logger_handler)

    # remove previous handlers if present
    for h in list(logger.handlers):
        logger.removeHandler(h)
    logger.addHandler(logger_handler)

def get_user_input(current_value, msg, password=False, padding=25):
    # get/validate user input and return value
    input_msg = "{0:<{1}}: ".format(msg, padding)
    input_prompt = getpass.getpass if password else input
    while current_value is None or len(current_value) == 0:
        current_value = input_prompt(input_msg)
        # strip characters if not a password
        if not password:
            current_value = current_value.strip()
    return current_value

def get_cmd(cmd, ignore_error=False):
    """ return output of shell command, return None on error"""
    try:
        logger.debug("get_cmd: %s", cmd)
        # check_output in 2.7 only, apic may be on 2.6 if executing on-apic
        if hasattr(subprocess, "check_output"):
            # execute command
            data = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        else:
            # apic may not support check_output, use communicate
            cmd = re.sub("2> /dev/null", "", cmd)
            p = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            data, err = p.communicate()
        return data
    except subprocess.CalledProcessError as e:
        if not ignore_error:
            logger.warn("error executing command: %s", e)
        return None

###############################################################################
#
# REST/connectivity functions
#
###############################################################################

class OnApicSession(object):
    """ dummy class to force _get to use icurl when executing on apic """
    def close(self):
        pass

def _get(session, url, timeout=None, limit=None, page_size=75000):
    """ handle session request and perform basic data validation.
        this module always returns a generator of the results. If there is an error the first item
        in the iterator (or on the received page) will be None.
    """
    if isinstance(session, OnApicSession):
        icurl(url, timeout=timeout, limit=limit, page_size=page_size)
        return
    page = 0
    if timeout is None:
        timeout = SESSION_MAX_TIMEOUT

    url_delim = "?"
    if "?" in url:
        url_delim="&"

    count_received = 0
    count_yield = 0
    # walk through pages until return count is less than page_size
    while True:
        turl = "%s%spage-size=%s&page=%s" % (url, url_delim, page_size, page)
        logger.debug("host:%s, timeout:%s, get:%s", session.hostname, timeout, turl)
        tstart = time.time()
        try:
            resp = session.get(turl, timeout=timeout)
        except Exception as e:
            logger.warn("exception occurred in get request: %s", e)
            yield None
            return
        if resp is None or not resp.ok:
            logger.warn("failed to get data: %s", url)
            yield None
            return
        try:
            js = resp.json()
            if "imdata" not in js or "totalCount" not in js:
                logger.warn("failed to parse js reply: %s", pretty_print(js))
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
            logger.warn("failed to decode resp: %s", resp.text)
            yield None
            return
    yield None
    return

def icurl(url, timeout=None, limit=None, page_size=75000):
    """ perform icurl for object/class based on relative dn and
        return json object.  Returns None on error
    """
    page = 0
    if timeout is None:
        timeout = SESSION_MAX_TIMEOUT

    # build icurl command
    url_delim = "?"
    if "?" in url:
        url_delim="&"

    count_received = 0
    count_yield = 0
    # walk through pages until return count is less than page_size
    while True:
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

def build_query_filters(**kwargs):
    """
        queryTarget=[children|subtree]
        targetSubtreeClass=[mo-class]
        queryTargetFilter=[filter]
        rspSubtree=[no|children|full]
        rspSubtreeClass=[mo-class]
        rspSubtreeInclude=[attr]
        rspPropInclude=[all|naming-only|config-explicit|config-all|oper]
        orderBy=[attr]
    """
    queryTarget         = kwargs.get("queryTarget", None)
    targetSubtreeClass  = kwargs.get("targetSubtreeClass", None)
    queryTargetFilter   = kwargs.get("queryTargetFilter", None)
    rspSubtree          = kwargs.get("rspSubtree", None)
    rspSubtreeClass     = kwargs.get("rspSubtreeClass", None)
    rspSubtreeInclude   = kwargs.get("rspSubtreeInclude", None)
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
    if rspSubtreeClass is not None:
        opts+= "&rsp-subtree-class=%s" % rspSubtreeClass
    if rspSubtreeInclude is not None:
        opts+= "&rsp-subtree-include=%s" % rspSubtreeInclude
    if rspPropInclude is not None:
        opts+= "&rsp-prop-include=%s" % rspPropInclude
    if orderBy is not None:
        opts+= "&order-by=%s" % orderBy

    if len(opts)>0: opts = "?%s" % opts.strip("&")
    return opts

def get_dn(session, dn, timeout=None, **kwargs):
    # get a single dn.  Note, with advanced queries this may be list as well
    # for now, always return single value
    opts = build_query_filters(**kwargs)
    url = "/api/mo/%s.json%s" % (dn,opts)
    ret = []
    for obj in _get(session, url, timeout=timeout):
        if obj is None:
            return None
        ret.append(obj)
    if len(ret)>0:
        return ret[0]
    else:
        # empty non-None object implies valid empty response
        return {}

def get_class(session, classname, timeout=None, limit=None, stream=True, **kwargs):
    # perform class query.  If stream is set to true then this will act as an iterator yielding the
    # next result. If the query failed then the first (and only) result of the iterator will be None
    opts = build_query_filters(**kwargs)
    url = "/api/class/%s.json%s" % (classname, opts)
    if stream:
        return _get(session, url, timeout=timeout, limit=limit)
    ret = []
    for obj in _get(session, url, timeout=timeout, limit=limit):
        if obj is None:
            return None
        ret.append(obj)
    return ret

def get_parent_dn(dn):
    # return parent dn for provided dn
    # note this is not currently aware of complex dn including prefixes or sub dn...
    t = dn.split("/")
    t.pop()
    return "/".join(t)

def get_attributes(session=None, dn=None, attribute=None, data=None):
    """ get single attribute from a DN.
        This is a relatively common operation to extract just a single value or
        just parse the result and get the attribute list.

        if data is provided, then this function assumes a list of objects or
        raw result from APIC query - for both cases, it assumes all objects are
        of the same set and only returns list of attribute objects.  Note,
        if 'attribute' is set then will only return single result of first
        object with attribute.

        else, session and dn are required and this function will perform APIC
        query and then return attribute dict.  If 'attribute' is also set, then
        just raw value of the corresponding attribute for that dn is returned

        return None on error or if dn is not found
    """
    if data is None:
        #logger.debug("get attributes '%s' for dn '%s'", attribute, dn)
        data = get_dn(session, dn)
        if data is None or type(data) is not dict or len(data)==0:
            logger.debug("return object for %s is None or invalid", dn)
            return

    # handle case raw 'imdata' dict was received
    if type(data) is dict:
        if "imdata" in data:
            data = data["imdata"]

    # always treat remaining result as list of objects
    ret = []
    if type(data) is not list:
        data = [data]
    for obj in data:
        if type(obj) is not dict or len(obj)==0:
            logger.warn("unexpected format for obj: %s" % obj)
            continue
        cname = obj.keys()[0]
        if "attributes" not in obj[cname]:
            logger.debug("%s does not contain attributes: %s", cname, obj)
            continue
        # add children into 'attributes' so caller functions can pick up child nodes as well
        if "children" in obj[cname]:
            obj[cname]["attributes"]["children"] = obj[cname]["children"]
        if attribute is not None:
            # only ever return first value matched when attribute is set
            if attribute in obj[cname]["attributes"]:
                return obj[cname]["attributes"][attribute]
        else:
            ret.append(obj[cname]["attributes"])

    if attribute is not None:
        # user request a specific attribute but it was not found, return None
        return None
    elif dn is not None and len(ret)==1:
        # if dn was set, then caller assumes get_dn execute and only one result
        # is present, so don't return list.
        return ret[0]
    return ret

def get_fabric_version(session):
    # return dict indexed by device role with current running version. Roles will be either
    # 'controller' or 'switch'. Dict will contain list of {node, version} objects
    ret = {}
    reg = re.compile("topology/pod-[0-9]+/node-(?P<node>[0-9]+)/")
    data = []
    data1 = get_class(session, "firmwareCtrlrRunning")
    data2 = get_class(session, "firmwareRunning")
    if data1 is not None and len(data1)>0:
        data += data1
    else:
        logger.warn("failed to get firmwareCtrlrRunning")
    if data2 is not None and len(data2)>0:
        data += data2
    else:
        logger.warn("failed to get firmwareRunning")

    # walk through version objects and add to ret indexed based on type
    for obj in data:
        attr = obj[obj.keys()[0]]["attributes"]
        if "dn" in attr and "type" in attr and ("version" in attr or "peVer" in attr):
            r1 = reg.search(attr["dn"])
            if r1 is not None:
                if attr["type"] not in ret:
                    ret[attr["type"]] = []
                ret[attr["type"]].append({
                    "node":int(r1.group("node")),
                    "version": attr["peVer"] if "peVer" in attr else attr["version"]
                })
            else:
                logger.warn("failed to parse node id from firmware dn: %s", attr["dn"])
        else:
            logger.warn("invalid firmware object: %s", attr)
    return ret

def parse_apic_version(version):
    # receive string code version and return dict with major, minor, build, and patch
    # for example:  2.3.1f
    #   major: 2
    #   minor: 3
    #   build: 1
    #   patch: f
    # return None if unable to parse version string

    reg ="(?P<M>[0-9]+)[\-\.](?P<m>[0-9]+)[\.\-\(](?P<p>[0-9]+)\.?(?P<pp>[a-z0-9]+)\)?"
    r1 = re.search(reg, version)
    if r1 is None: return None
    return {
        "major": int(r1.group("M")),
        "minor": int(r1.group("m")),
        "build": int(r1.group("p")),
        "patch": r1.group("pp"),
    }

###############################################################################
#
# Print/Parsing functions
#
###############################################################################

def pretty_print(js):
    """ try to convert json to pretty-print format """
    try:
        return json.dumps(js, indent=4, sort_keys=True, separators=(",", ":"))
    except Exception as e:
        return "%s" % js

def print_table(hdrs, data):
    """ receive a list of hdrs and list of data representing each row to print. Hdrs contain the
        following information: [{
            "name": "<string>",         name for the column header
            "length": int,              column length.  Must be greater than 0...
        }]
    """
    tw = TextWrapper()
    # only difficult thing here is wrapping the cell if it exceeds the row length, and it could be
    # extended in multiple cells in the same row so we need to determine the longest cell...
    def get_row_string(column_widths, row_data, fmt_separator="|"):
        # receive a list of ints representing each column width and a list of text data representing
        # data for each column and return single string line.
        fmt = []
        cols = []
        for index, width in enumerate(column_widths):
            fmt.append("{%s:<%s}" % (index, width))
            if index<len(row_data):
                #text = " ".join(row_data[index].strip().split())
                text = row_data[index]
                tw.width = width
                # to honor original user's return characters, we need to wrap each individual line
                wraps = []
                for line in text.split("\n"):
                    wraps+= tw.wrap(line.strip())
                cols.append(wraps)
            else:
                cols.append([""])
        fmt = "%s%s%s" % (fmt_separator, (" %s " % fmt_separator).join(fmt), fmt_separator)
        # expand all columns to the max length column
        max_col = max([len(c) for c in cols])
        for c in cols:
            c+= [""]*(max_col - len(c))
        #logger.debug("fmt: %s", fmt)
        #logger.debug("columns:%s max length:%s\n%s", len(cols), max_col, cols)
        # build final result string which is one or more lines of merged cells
        results = []
        for index in range(0, max_col):
            # grab this index from all columns to create a single row
            row = [c[index] for c in cols]
            results.append(fmt.format(*row))
        return "\n".join(results)

    final_rows = []
    column_widths = [h.get("length", 5) for h in hdrs]
    separator = ["-"*h.get("length", 5) for h in hdrs]
    separator_string = get_row_string(column_widths, separator, fmt_separator="+")
    final_rows.append(separator_string)
    final_rows.append(get_row_string(column_widths, [h.get("name", "") for h in hdrs]))
    final_rows.append(separator_string)
    for row in data:
        final_rows.append(get_row_string(column_widths, row))
        final_rows.append(separator_string)
    print("\n".join(final_rows))

def parse_timestamp(ts_str):
    """ return float unix timestamp for timestamp string """
    dt = dateutil.parser.parse(ts_str)
    return (time.mktime(dt.timetuple()) + dt.microsecond/1000000.0)

def format_timestamp(timestamp, msec=False):
    """ format timestamp to datetime string """

    datefmt="%Y-%m-%dT%H:%M:%S"
    try:
        t= datetime.datetime.fromtimestamp(int(timestamp)).strftime(datefmt)
        if msec:
            if timestamp == 0: t = "%s.000" % t
            else: t="{0}.{1:03d}".format(t, int((timestamp*1000)%1000))
        t = "%s%s" % (t, current_tz_string())
        return t
    except Exception as e:
        return timestamp

def format_seconds(s, milli=True):
    """ format raw seconds to days hh:mm:ss.mmm """
    sec = s % 60
    hours = int(s / 3600)
    mins = int((s - hours * 3600) / 60)
    days = int(hours / 24)
    if milli:
        sec_str = "{0:02d}.{1:03d}".format(int(sec), int((sec*1000)%1000))
    else:
        sec_str = "{0:02d}".format(int(sec))
    if days > 0:
        hours = hours - days * 24
        return "%s days %s:%s" % (days, "{0:02.0f}:{1:02.0f}".format(hours, mins, sec), sec_str)
    else:
        return "%s:%s" % ("{0:02.0f}:{1:02.0f}".format(hours, mins, sec), sec_str)



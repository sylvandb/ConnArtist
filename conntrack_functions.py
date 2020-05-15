#!/usr/bin/env python3
# vi: sw=4 sts=4 ts=4 si ci et
import subprocess
import json
import datetime
import os

# TODO:
#  node weight as bytes???
#  link weight???
#  save conntrack unparsed???
#  more protocols - which???
#  weights in general: probably 5 is too many, 3? big, significant, exists

def _get_conntrack():
    # in /etc/sudoers add: ALL ALL= (root) NOPASSWD: /usr/sbin/conntrack -L
    p = subprocess.run(["sudo", "/usr/sbin/conntrack", "-L"], check=True, capture_output=True)
    l = p.stdout.decode().split("\n")
    return l


DIRORIG = 0
DIRRESP = 1
DIRBOTH = 2

def _parse_conntrack(conntrack, mode='IP'):
    # D3 wants:
    # out = {
    #   'nodes': [],
    #   'links': [],
    # }
    # node = {
    #   'id':      '',    # ip
    #   'group':   {num}, # direction: 0, 1, 2(both)
    #   'srcIPs':  [],    # node id's
    #   'dstIPs':  [],    # node id's
    #   'srcPORT': [],    # strings
    #   'dstPORT': [],    # strings
    # }
    # link = {
    #   'source': '',    # node id
    #   'target': '',    # node id
    #   'value':  {num}, # protocol number
    #   'weight': {num}, # bigger more significant
    # }

    nodes = {}
    def _add_node(node_id, IPPs, direction):
        try:
            node = nodes[node_id]
        except KeyError:
            nodes[node_id] = {
                'id'     : node_id,
                'group'  : direction,
                'srcIPs' : [IPPs[0]],
                'dstIPs' : [IPPs[1]],
                'srcPORT': [IPPs[2]],
                'dstPORT': [IPPs[3]],
            }
        else:
            if node['group'] != direction:
                node['group'] = DIRBOTH
            node['srcIPs' ].append(IPPs[0])
            node['dstIPs' ].append(IPPs[1])
            node['srcPORT'].append(IPPs[2])
            node['dstPORT'].append(IPPs[3])

    links = {}
    def _add_link(src_id, tgt_id, protocol):
        key = src_id + '-' + tgt_id + '-' + str(protocol)
        try:
            links[key]['weight'] += 1
        except KeyError:
            links[key] = {
                'source': cli_id,
                'target': srv_id,
                'value' : protocol,
                'weight': 1
            }

    html_frags = []

    for split_line in (l.split() for l in conntrack if l):
        if not split_line:
            break

        # protocol differences
        # protoname, protonum, (ip/ports/other), (ip/ports/other)
        # where ip/ports is indices for:
        #   request  srcip, dstip, srcport, dstport
        #   response srcip, dstip, srcport, dstport
        # the ports only tcp/udp, otherwise other info
        if split_line[0] == 'tcp':
            Magic = ('TCP', 2, (4, 5, 6, 7), (10, 11, 12, 13))
        elif split_line[0] == 'udp':
            Magic = ('UDP', 1, (3, 4, 5, 6), (9, 10, 11, 12))
        elif split_line[0] == 'icmp':
            Magic = ('ICMP', 0, (3, 4, 5, 6, 7), (10, 11, 12, 13, 14))
        else:
            # TODO: unrecognized protocols
            # if using netlink the IPs would probably be readable
            print('Unrecognized:', split_line)
            continue

        # skip [UNREPLIED] etc. states inserted before responder entries
        rspsrc = 0
        try:
            while split_line[Magic[3][rspsrc]][:4] != 'src=':
                rspsrc += 1
        except IndexError:
            print('Rsp IP fail:', split_line)
            continue
        else:
            if rspsrc:
                mt = tuple(m + rspsrc for m in Magic[3])
                Magic = Magic[:3] + (mt,)

        IPPs = []
        try:
            # request
            IPPs.extend(split_line[n].split('=')[1] for n in Magic[2])
            # response
            IPPs.extend(split_line[n].split('=')[1] for n in Magic[3])
        except:
            print('IP fail:', split_line)
            continue

        if len(IPPs) == 8:
            # host:port
            html_frags.extend([Magic[0], " req src: ", IPPs[0], ':', IPPs[2], "<br/>\n"])
            html_frags.extend([Magic[0], " req dst: ", IPPs[1], ':', IPPs[3], "<br/>\n"])
            html_frags.extend([Magic[0], " rsp src: ", IPPs[4], ':', IPPs[6], "<br/>\n"])
            html_frags.extend([Magic[0], " rsp dst: ", IPPs[5], ':', IPPs[7], "<br/>\n"])
        else:
            # host and ???
            n = len(IPPs) // 2
            html_frags.extend([Magic[0], " req src: ", IPPs[0], "<br/>\n"])
            html_frags.extend([Magic[0], " req dst: ", IPPs[1], "<br/>\n"])
            html_frags.extend([Magic[0], " req oth: ", str(IPPs[2:n]), "<br/>\n"])
            html_frags.extend([Magic[0], " rsp src: ", IPPs[0+n], "<br/>\n"])
            html_frags.extend([Magic[0], " rsp dst: ", IPPs[1+n], "<br/>\n"])
            html_frags.extend([Magic[0], " rsp oth: ", str(IPPs[2+n:]), "<br/>\n"])
            IPPs = [IPPs[0], IPPs[1], 'NA', 'NA']
        html_frags.append("<br/>\n")

        if 'IP' in mode:
            cli_id = IPPs[0]
            srv_id = IPPs[1]
        elif 'PORT' in mode:
            cli_id = IPPs[2]
            srv_id = IPPs[3]
            if IPPs[2] == 'NA':
                print("mode mismatch: %s w/%s, %s" % (mode, Magic, IPPs))
        else:
            print("bad mode: %s w/%s, %s" % (mode, Magic, IPPs))
            continue

        _add_node(cli_id, IPPs, DIRORIG)
        _add_node(srv_id, IPPs, DIRRESP)
        _add_link(cli_id, srv_id, Magic[1])

    return {'nodes': list(nodes.values()), 'links': list(links.values())}, html_frags


# Copies the json generated from the conntrack data to a archive folder for recall if need be
_lastFileName = None
def _archiveJSON(currJSON, mode):
    # Check if output is same as most recent file -- don't output if same
    global _lastFileName

    if not _lastFileName:
        try:
            _lastFileName = sorted(os.listdir('app/static/PrevSnapshots'))[-1]
        except IndexError:
            pass

    if _lastFileName:
        with open('app/static/PrevSnapshots/' + _lastFileName, 'r') as prevFile:
            if prevFile.read() == currJSON:
                currJSON = None

    if currJSON:
        _lastFileName = "conntrackData-" + datetime.datetime.now().strftime("%m-%d-%Y_%H-%M-%S") + "_" + str(mode) +  ".json"
        with open('app/static/PrevSnapshots/' + _lastFileName, 'w') as outfile:
            outfile.write(currJSON)



def conntrack_parse(mode):
    mode = str(mode).strip()
    d3data, html = _parse_conntrack(_get_conntrack(), mode)
    currJSON = json.dumps(d3data)

    if 'PORT' in mode:
        with open('app/static/conntrack_data_port.json', 'w') as outfile:
            outfile.write(currJSON)
    else:
        with open('app/static/conntrack_data.json', 'w') as outfile:
            outfile.write(currJSON)

    _archiveJSON(currJSON, mode)
    return ''.join(html)




if __name__ == "__main__":
    import sys
    ctd = None

    if 'save' in sys.argv:
        print(json.dumps(_get_conntrack(), indent=2))
        sys.exit()

    if 'load' in sys.argv:
        with open(sys.argv[2], 'r') as f:
            ctd = json.load(f)
        del sys.argv[1:3]
        # fall through

    if 'parse' in sys.argv:
        mode = sys.argv[2]
        print('--- ERR ---')
        d3_out, html_out = _parse_conntrack(ctd or _get_conntrack(), mode)
        print('--- JSON ---')
        print(json.dumps(d3_out, indent=2))
        print('--- HTML ---')
        print(''.join(html_out))
        print('--- EOF ---')
        sys.exit()

    # default
    l = ctd or _get_conntrack()
    print(l)
    print(len(l))

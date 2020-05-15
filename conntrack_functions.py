#!/usr/bin/env python3
# vi: sw=4 sts=4 ts=4 si ci et
import subprocess
import json
import datetime
import socket
import os


def _get_conntrack():
    p = subprocess.run(["sudo", "/usr/sbin/conntrack", "-L"], check=True, capture_output=True)
    l = p.stdout.decode().split("\n")
    return l


def _parse_conntrack(mode, conntrack):
    #print("MODE: " + mode)

    string_return = []
    json_output = {
        "nodes": [],
        "links": []
    }
    IP_seen = []

    for split_line in (l.split() for l in conntrack if l):
        if not split_line:
            break

        # protocol differences
        # protoname, (ip/ports), magic value???
        # where ip/ports is indices: client srcip, dstip, srcprt, dstprt; server srcip, dstip, srcprt, dstprt
        if split_line[0] == "tcp":
            Magic = ('TCP', 2, (4, 5, 6, 7, 10, 11, 12, 13))
        elif split_line[0] == "udp":
            Magic = ('UDP', 1, (3, 4, 5, 6, 9, 10, 11, 12))
        else:
            # TODO: unrecognized protocol
            # if using netlink the IPs would probably be readable
            print('Unrecognized:', split_line)
            continue
        if not split_line[Magic[2][4]][:4] == 'src=': # catch [UNREPLIED]
            mt = Magic[2][:4] + tuple(m + 1 for m in Magic[2][4:])
            Magic = Magic[:2] + (mt,)

        try:
            IPPs = [split_line[n].split('=')[1] for n in Magic[2]]
        except:
            print('IP fail:', split_line)
            continue

        string_return.extend([Magic[0], " client src: ", IPPs[0], "<br/>\n"])
        string_return.extend([Magic[0], " client dst: ", IPPs[1], "<br/>\n"])
        string_return.extend([Magic[0], " client src: ", IPPs[2], "<br/>\n"])
        string_return.extend([Magic[0], " client dst: ", IPPs[3], "<br/>\n"])

        string_return.extend([Magic[0], " server src: ", IPPs[4], "<br/>\n"])
        string_return.extend([Magic[0], " server dst: ", IPPs[5], "<br/>\n"])
        string_return.extend([Magic[0], " server src: ", IPPs[6], "<br/>\n"])
        string_return.extend([Magic[0], " server dst: ", IPPs[7], "<br/>\n"])

        if "IP" in mode:
            destinationURL = ""
            destURL = ""
            try:
                destinationURL = "Unknown"
                #destinationURL = socket.gethostbyaddr(IPPs[1])[0]
            except:
                destinationURL = "Unknown"
            try:
                destinationURL = "Unknown"
                #destURL = socket.gethostbyaddr(IPPs[0])[0]
            except:
                destURL = "Unknown"

            if IPPs[0] not in IP_seen:
                json_output["nodes"].append(
                {"id":IPPs[0],
                "group":0,
                "srcIPs":[IPPs[0]],
                "dstIPs":[IPPs[1]],
                "srcPORT":[IPPs[2]],
                "dstPORT":[IPPs[3]],
                "URLs":[destinationURL],
                "URL":destURL})
                IP_seen.append(IPPs[0])
            else:
                for node in json_output["nodes"]:
                    if node["id"] == IPPs[0]:
                        if node["group"] == 1:
                            node["group"] = 2
                        node["srcIPs"].append(IPPs[0])
                        node["dstIPs"].append(IPPs[1])
                        node["srcPORT"].append(IPPs[2])
                        node["dstPORT"].append(IPPs[3])
                        node["URLs"].append(destinationURL)

            if IPPs[1] not in IP_seen:
                json_output["nodes"].append(
                {"id":IPPs[1],
                "group":1,
                "srcIPs":[IPPs[0]],
                "dstIPs":[IPPs[1]],
                "srcPORT":[IPPs[2]],
                "dstPORT":[IPPs[3]],
                "URLs":[destinationURL],
                "URL":destinationURL})
                IP_seen.append(IPPs[1])
            else:
                for node in json_output["nodes"]:
                    if node["id"] == IPPs[1]:
                        if node["group"] == 0:
                            node["group"] = 2
                        node["srcIPs"].append(IPPs[0])
                        node["dstIPs"].append(IPPs[1])
                        node["srcPORT"].append(IPPs[2])
                        node["dstPORT"].append(IPPs[3])
                        node["URLs"].append(destinationURL)

            linkExists = False
            for link in json_output["links"]:
                if link["source"] == IPPs[0] and link["target"] == IPPs[1]:
                    link["weight"] = link["weight"] + 1
                    linkExists = True

            if not linkExists:
                json_output["links"].append(
                {"source":IPPs[0],
                "target":IPPs[1],
                "value":Magic[1],
                "weight":1})

        elif "PORT" in mode:
            destinationURL = ""
            try:
                destinationURL = "Unknown"
                #destinationURL = socket.gethostbyaddr(IPPs[1])[0]
            except:
                destinationURL = "Unknown"

            if IPPs[2] not in IP_seen:
                json_output["nodes"].append(
                {"id":IPPs[2],
                "group":0,
                "SourceIP":IPPs[0],
                "DestinationIP":IPPs[1],
                "DestinationURL":destinationURL,
                "srcIPs":[IPPs[0]],
                "dstIPs":[IPPs[1]],
                "srcPORT":[IPPs[2]],
                "dstPORT":[IPPs[3]],
                "URLs":[destinationURL]})
                IP_seen.append(IPPs[2])
            else:
                for node in json_output["nodes"]:
                    if node["id"] == IPPs[2]:
                        if node["group"] == 1:
                            node["group"] = 2
                        node["srcIPs"].append(IPPs[0])
                        node["dstIPs"].append(IPPs[1])
                        node["srcPORT"].append(IPPs[2])
                        node["dstPORT"].append(IPPs[3])
                        node["URLs"].append(destinationURL)

            if IPPs[3] not in IP_seen:
                json_output["nodes"].append(
                {"id":IPPs[3],
                "group":1,
                "SourceIP":IPPs[0],
                "DestinationIP": IPPs[1],
                "DestinationURL":destinationURL,
                "srcIPs":[IPPs[0]],
                "dstIPs":[IPPs[1]],
                "srcPORT":[IPPs[2]],
                "dstPORT":[IPPs[3]],
                "URLs":[destinationURL]})
                IP_seen.append(IPPs[3])
            else:
                for node in json_output["nodes"]:
                    if node["id"] == IPPs[3]:
                        if node["group"] == 0:
                            node["group"] = 2
                        node["srcIPs"].append(IPPs[0])
                        node["dstIPs"].append(IPPs[1])
                        node["srcPORT"].append(IPPs[2])
                        node["dstPORT"].append(IPPs[3])
                        node["URLs"].append(destinationURL)

            linkExists = False
            for link in json_output["links"]:
                if link["source"] == IPPs[2] and link["target"] == IPPs[3]:
                    link["weight"] = link["weight"] + 1
                    linkExists = True

            if not linkExists:
                json_output["links"].append(
                {"source":IPPs[2],
                "target":IPPs[3],
                "value":Magic[1],
                "weight":1})

        string_return.append("<br/>\n")

        # Generate json that D3 likes
        # json_output = {}
        # json_output["nodes"] = []

        # json_output["nodes"].append(
        #   {"id":"REPLACE",
        #   "group":"REPLACE"})

        # json_output["links"] = []

        # json_output["links"].append(
        #   {"source":"REPLACE",
        #   "target":"REPLACE",
        #   "value":"REPLACE"})

    return json_output, string_return


def conntrack_parse(mode):
    mode = str(mode).strip()
    json_output, string_return = _parse_conntrack(mode, _get_conntrack())

    if "PORT" in mode:
        with open('app/static/conntrack_data_port.json', 'w') as outfile:
            json.dump(json_output, outfile)
    else:
        with open('app/static/conntrack_data.json', 'w') as outfile:
            json.dump(json_output, outfile)

    archiveJson(json_output, mode)

    return ''.join(string_return)


# Copies the json generated from the conntrack data to a archive folder for recall if need be
lastFileName = None
def archiveJson(json_output, mode):
    # Check if output is same as most recent file -- don't output if same
    global lastFileName
    same = False

    if not lastFileName:
        try:
            lastFileName = os.listdir('app/static/PrevSnapshots')[-1]
        except IndexError:
            pass

    if lastFileName:
        with open('app/static/PrevSnapshots/' + lastFileName, "r") as prevFile:
            prevJSON = prevFile.read()
        same = prevJSON == json_output

    if not same:
        lastFileName = "conntrackData-" + datetime.datetime.now().strftime("%m-%d-%Y_%H-%M-%S") + "_" + str(mode) +  ".json"
        with open('app/static/PrevSnapshots/' + lastFileName, 'w') as outfile:
            json.dump(json_output, outfile)




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

    if 'parse' in sys.argv:
        mode = sys.argv[2]
        json_out, str_out = _parse_conntrack(mode, ctd or _get_conntrack())
        print('---')
        print(json_out)
        print('---')
        print(''.join(str_out))
        print('---')
    else:
        l = ctd or _get_conntrack()
        print(l)
        print(len(l))

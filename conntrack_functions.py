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

        if split_line[0] == "tcp":
            string_return.extend(["TCP client src: ", split_line[4].split("=")[1], "<br/>\n"])
            string_return.extend(["TCP client dst: ", split_line[5].split("=")[1], "<br/>\n"])
            string_return.extend(["TCP client src: ", split_line[6].split("=")[1], "<br/>\n"])
            string_return.extend(["TCP client dst: ", split_line[7].split("=")[1], "<br/>\n"])

            try:
                string_return.extend(["TCP server src: ", split_line[8].split("=")[1], "<br/>\n"])
                string_return.extend(["TCP server dst: ", split_line[9].split("=")[1], "<br/>\n"])
                string_return.extend(["TCP server src: ", split_line[10].split("=")[1], "<br/>\n"])
                string_return.extend(["TCP server dst: ", split_line[11].split("=")[1], "<br/>\n"])
            except:
                print(split_line)
                continue

            if ("IP" in mode):
                destinationURL = ""
                destURL = ""
                try:
                    destinationURL = "Unknown"
                    #destinationURL = socket.gethostbyaddr(split_line[5].split("=")[1])[0]
                except:
                    destinationURL = "Unknown"
                try:
                    destinationURL = "Unknown"
                    #destURL = socket.gethostbyaddr(split_line[4].split("=")[1])[0]
                except:
                    destURL = "Unknown"

                if (split_line[4].split("=")[1] not in IP_seen):
                    json_output["nodes"].append(
                    {"id":split_line[4].split("=")[1],
                    "group":0,
                    "srcIPs":[split_line[4].split("=")[1]],
                    "dstIPs":[split_line[5].split("=")[1]],
                    "srcPORT":[split_line[6].split("=")[1]],
                    "dstPORT":[split_line[7].split("=")[1]],
                    "URLs":[destinationURL],
                    "URL":destURL})
                    IP_seen.append(split_line[4].split("=")[1])
                else:
                    for node in json_output["nodes"]:
                        if node["id"] == split_line[4].split("=")[1]:
                            if node["group"] == 1:
                                node["group"] = 2
                            node["srcIPs"].append(split_line[4].split("=")[1])
                            node["dstIPs"].append(split_line[5].split("=")[1])
                            node["srcPORT"].append(split_line[6].split("=")[1])
                            node["dstPORT"].append(split_line[7].split("=")[1])
                            node["URLs"].append(destinationURL)

                if (split_line[5].split("=")[1] not in IP_seen):
                    json_output["nodes"].append(
                    {"id":split_line[5].split("=")[1],
                    "group":1,
                    "srcIPs":[split_line[4].split("=")[1]],
                    "dstIPs":[split_line[5].split("=")[1]],
                    "srcPORT":[split_line[6].split("=")[1]],
                    "dstPORT":[split_line[7].split("=")[1]],
                    "URLs":[destinationURL],
                    "URL":destinationURL})
                    IP_seen.append(split_line[5].split("=")[1])
                else:
                    for node in json_output["nodes"]:
                        if node["id"] == split_line[5].split("=")[1]:
                            if node["group"] == 0:
                                node["group"] = 2
                            node["srcIPs"].append(split_line[4].split("=")[1])
                            node["dstIPs"].append(split_line[5].split("=")[1])
                            node["srcPORT"].append(split_line[6].split("=")[1])
                            node["dstPORT"].append(split_line[7].split("=")[1])
                            node["URLs"].append(destinationURL)

                linkExists = False
                for link in json_output["links"]:
                    if link["source"] == split_line[4].split("=")[1] and link["target"] == split_line[5].split("=")[1]:
                        link["weight"] = link["weight"] + 1
                        linkExists = True

                if not linkExists:
                    json_output["links"].append(
                    {"source":split_line[4].split("=")[1],
                    "target":split_line[5].split("=")[1],
                    "value":2,
                    "weight":1})

                #json_output["links"].append(
                #{"source":split_line[4].split("=")[1],
                #"target":split_line[5].split("=")[1],
                #"value":1})

            elif ("PORT" in mode):
                destinationURL = ""
                try:
                    destinationURL = "Unknown"
                    #destinationURL = socket.gethostbyaddr(split_line[5].split("=")[1])[0]
                except:
                    destinationURL = "Unknown"

                if (split_line[6].split("=")[1] not in IP_seen):
                    json_output["nodes"].append(
                    {"id":split_line[6].split("=")[1],
                    "group":0,
                    "SourceIP":split_line[4].split("=")[1],
                    "DestinationIP":split_line[5].split("=")[1],
                    "DestinationURL":destinationURL,
                    "srcIPs":[split_line[4].split("=")[1]],
                    "dstIPs":[split_line[5].split("=")[1]],
                    "srcPORT":[split_line[6].split("=")[1]],
                    "dstPORT":[split_line[7].split("=")[1]],
                    "URLs":[destinationURL]})
                    IP_seen.append(split_line[6].split("=")[1])
                else:
                    for node in json_output["nodes"]:
                        if node["id"] == split_line[6].split("=")[1]:
                            if node["group"] == 1:
                                node["group"] = 2
                            node["srcIPs"].append(split_line[4].split("=")[1])
                            node["dstIPs"].append(split_line[5].split("=")[1])
                            node["srcPORT"].append(split_line[6].split("=")[1])
                            node["dstPORT"].append(split_line[7].split("=")[1])
                            node["URLs"].append(destinationURL)

                if (split_line[7].split("=")[1] not in IP_seen):
                    json_output["nodes"].append(
                    {"id":split_line[7].split("=")[1],
                    "group":1,
                    "SourceIP":split_line[4].split("=")[1],
                    "DestinationIP":split_line[5].split("=")[1],
                    "DestinationURL":destinationURL,
                    "srcIPs":[split_line[4].split("=")[1]],
                    "dstIPs":[split_line[5].split("=")[1]],
                    "srcPORT":[split_line[6].split("=")[1]],
                    "dstPORT":[split_line[7].split("=")[1]],
                    "URLs":[destinationURL]})
                    IP_seen.append(split_line[7].split("=")[1])
                else:
                    for node in json_output["nodes"]:
                        if node["id"] == split_line[7].split("=")[1]:
                            if node["group"] == 0:
                                node["group"] = 2
                            node["srcIPs"].append(split_line[4].split("=")[1])
                            node["dstIPs"].append(split_line[5].split("=")[1])
                            node["srcPORT"].append(split_line[6].split("=")[1])
                            node["dstPORT"].append(split_line[7].split("=")[1])
                            node["URLs"].append(destinationURL)

                linkExists = False
                for link in json_output["links"]:
                    if link["source"] == split_line[6].split("=")[1] and link["target"] == split_line[7].split("=")[1]:
                        link["weight"] = link["weight"] + 1
                        linkExists = True

                if not linkExists:
                    json_output["links"].append(
                    {"source":split_line[6].split("=")[1],
                    "target":split_line[7].split("=")[1],
                    "value":2,
                    "weight":1})

                #json_output["links"].append(
                #{"source":split_line[6].split("=")[1],
                #"target":split_line[7].split("=")[1],
                #"value":1})



        elif split_line[0] == "udp":
            string_return.extend(["UDP client src: ", split_line[3].split("=")[1], "<br/>\n"])
            string_return.extend(["UDP client dst: ", split_line[4].split("=")[1], "<br/>\n"])
            string_return.extend(["UDP client src: ", split_line[5].split("=")[1], "<br/>\n"])
            string_return.extend(["UDP client dst: ", split_line[6].split("=")[1], "<br/>\n"])

            # Need try/except for weird case where we get MAC values in UDP, no idea what causes it
            try:
                string_return.extend(["UDP client src: ", split_line[7].split("=")[1], "<br/>\n"])
                string_return.extend(["UDP client dst: ", split_line[8].split("=")[1], "<br/>\n"])
                string_return.extend(["UDP client src: ", split_line[9].split("=")[1], "<br/>\n"])
                string_return.extend(["UDP client dst: ", split_line[10].split("=")[1], "<br/>\n"])
            except:
                print(split_line)
                continue



            if "IP" in mode:
                destinationURL = ""
                destURL = ""
                try:
                    destinationURL = "Unknown"
                    #destinationURL = socket.gethostbyaddr(split_line[4].split("=")[1])[0]
                except:
                    destinationURL = "Unknown"
                try:
                    destinationURL = "Unknown"
                    #destURL = socket.gethostbyaddr(split_line[3].split("=")[1])[0]
                except:
                    destURL = "Unknown"

                if (split_line[3].split("=")[1] not in IP_seen):
                    json_output["nodes"].append(
                    {"id":split_line[3].split("=")[1],
                    "group":0,
                    "srcIPs":[split_line[3].split("=")[1]],
                    "dstIPs":[split_line[4].split("=")[1]],
                    "srcPORT":[split_line[5].split("=")[1]],
                    "dstPORT":[split_line[6].split("=")[1]],
                    "URLs":[destinationURL],
                    "URL":destURL})
                    IP_seen.append(split_line[3].split("=")[1])
                else:
                    for node in json_output["nodes"]:
                        if node["id"] == split_line[3].split("=")[1]:
                            if node["group"] == 1:
                                node["group"] = 2
                            node["srcIPs"].append(split_line[3].split("=")[1])
                            node["dstIPs"].append(split_line[4].split("=")[1])
                            node["srcPORT"].append(split_line[5].split("=")[1])
                            node["dstPORT"].append(split_line[6].split("=")[1])
                            node["URLs"].append(destinationURL)

                if (split_line[4].split("=")[1] not in IP_seen):
                    json_output["nodes"].append(
                    {"id":split_line[4].split("=")[1],
                    "group":1,
                    "srcIPs":[split_line[3].split("=")[1]],
                    "dstIPs":[split_line[4].split("=")[1]],
                    "srcPORT":[split_line[5].split("=")[1]],
                    "dstPORT":[split_line[6].split("=")[1]],
                    "URLs":[destinationURL],
                    "URL":destinationURL})
                    IP_seen.append(split_line[4].split("=")[1])
                else:
                    for node in json_output["nodes"]:
                        if node["id"] == split_line[4].split("=")[1]:
                            if node["group"] == 0:
                                node["group"] = 2
                            node["srcIPs"].append(split_line[3].split("=")[1])
                            node["dstIPs"].append(split_line[4].split("=")[1])
                            node["srcPORT"].append(split_line[5].split("=")[1])
                            node["dstPORT"].append(split_line[6].split("=")[1])
                            node["URLs"].append(destinationURL)

                linkExists = False
                for link in json_output["links"]:
                    if link["source"] == split_line[3].split("=")[1] and link["target"] == split_line[4].split("=")[1]:
                        link["weight"] = link["weight"] + 1
                        linkExists = True

                if not linkExists:
                    json_output["links"].append(
                    {"source":split_line[3].split("=")[1],
                    "target":split_line[4].split("=")[1],
                    "value":1,
                    "weight":1})

            elif "PORT" in mode:
                destinationURL = ""
                try:
                    destinationURL = "Unknown"
                    #destinationURL = socket.gethostbyaddr(split_line[4].split("=")[1])[0]
                except:
                    destinationURL = "Unknown"

                if (split_line[5].split("=")[1] not in IP_seen):
                    json_output["nodes"].append(
                    {"id":split_line[5].split("=")[1],
                    "group":0,
                    "SourceIP":split_line[3].split("=")[1],
                    "DestinationIP":split_line[4].split("=")[1],
                    "DestinationURL":destinationURL,
                    "srcIPs":[split_line[3].split("=")[1]],
                    "dstIPs":[split_line[4].split("=")[1]],
                    "srcPORT":[split_line[5].split("=")[1]],
                    "dstPORT":[split_line[6].split("=")[1]],
                    "URLs":[destinationURL]})
                    IP_seen.append(split_line[5].split("=")[1])
                else:
                    for node in json_output["nodes"]:
                        if node["id"] == split_line[5].split("=")[1]:
                            if node["group"] == 1:
                                node["group"] = 2
                            node["srcIPs"].append(split_line[3].split("=")[1])
                            node["dstIPs"].append(split_line[4].split("=")[1])
                            node["srcPORT"].append(split_line[5].split("=")[1])
                            node["dstPORT"].append(split_line[6].split("=")[1])
                            node["URLs"].append(destinationURL)

                if (split_line[6].split("=")[1] not in IP_seen):
                    json_output["nodes"].append(
                    {"id":split_line[6].split("=")[1],
                    "group":1,
                    "SourceIP":split_line[3].split("=")[1],
                    "DestinationIP": split_line[4].split("=")[1],
                    "DestinationURL":destinationURL,
                    "srcIPs":[split_line[3].split("=")[1]],
                    "dstIPs":[split_line[4].split("=")[1]],
                    "srcPORT":[split_line[5].split("=")[1]],
                    "dstPORT":[split_line[6].split("=")[1]],
                    "URLs":[destinationURL]})
                    IP_seen.append(split_line[6].split("=")[1])
                else:
                    for node in json_output["nodes"]:
                        if node["id"] == split_line[6].split("=")[1]:
                            if node["group"] == 0:
                                node["group"] = 2
                            node["srcIPs"].append(split_line[3].split("=")[1])
                            node["dstIPs"].append(split_line[4].split("=")[1])
                            node["srcPORT"].append(split_line[5].split("=")[1])
                            node["dstPORT"].append(split_line[6].split("=")[1])
                            node["URLs"].append(destinationURL)

                linkExists = False
                for link in json_output["links"]:
                    if link["source"] == split_line[5].split("=")[1] and link["target"] == split_line[6].split("=")[1]:
                        link["weight"] = link["weight"] + 1
                        linkExists = True

                if not linkExists:
                    json_output["links"].append(
                    {"source":split_line[5].split("=")[1],
                    "target":split_line[6].split("=")[1],
                    "value":1,
                    "weight":1})

                #json_output["links"].append(
                #{"source":split_line[5].split("=")[1],
                #"target":split_line[6].split("=")[1],
                #"value":2,
                #"weight":1})
        else:
            continue

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

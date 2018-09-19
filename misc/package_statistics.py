#!/usr/bin/env python3
import os
import sys
import re
import gzip
import urllib.request
from collections import Counter


def main():
    # if no args, print help and exit
    if len(sys.argv) == 1:
        print("Include architecture as an argument\n")
        print("Example:")
        print(os.path.basename(__file__) + " amd64")
        exit()

    # generate the stats dictionary
    stats = get_stats(download_contents_file(sys.argv[1]))

    # use collections counter for top 10
    print("{0:<32} {1:>8}".format(*("Package", "Count")))
    for package in Counter(stats).most_common(10):
        print("{0:<32} {1:>8}".format(*package))


# takes the arch as an argument and returns the unzipped contents
# returned data is a list with one line per indice
def download_contents_file(arch):
    baseURL = "http://ftp.uk.debian.org/debian/dists/stable/main/"
    filename = "Contents-" + arch + ".gz"

    # if there is an error, exit
    try:
        response = urllib.request.urlopen(baseURL + filename)
    except urllib.error.HTTPError:
        print("Probably invalid arch: try again")
        exit()

    # gunzip, decode, and split by lines to return line list
    return gzip.decompress(response.read()).decode("utf-8").split("\n")


# takes the file_content list (arg) and parses them
# returns dictionary like {"package name": "file count"}
def get_stats(file_content):
    stats = {}
    for line in file_content:
        re_object = re.search(r'^(\S+)\s+(\S+)$', line)

        if re_object:
            for package in re_object.group(2).split(","):
                # if package already in dict, increment, if not set to 1
                if package in stats:
                    stats[package] += 1
                else:
                    stats[package] = 1

    return stats


if __name__ == "__main__":
    main()
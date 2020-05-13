import argparse
import os
import math

global parser

def average(lst):
    if len(lst) == 0:
        return -1
    return round(float(sum(lst))/len(lst), 2)

def stdev(lst):
    if len(lst) == 0:
        return -1
    avg = average(lst)
    mid = []
    for e in lst:
        err = e - avg
        mid.append(err * err)
    var = average(mid)
    return round(math.sqrt(var), 2)

def sort_by_time(p):
    return p[2]

def sort_by_idx(p):
    return p[0]

def seed_analysis(idir, mode):
    tlst = []
    clst = []
    for f in os.listdir(idir):
        if "time" in f and mode in f:
            tlst.append(f)
        elif "cpu" in f and mode in f:
            clst.append(f)

    oft = open("{}_{}_time.csv".format(idir, mode), "w")
    ofc = open("{}_{}_cpu.csv".format(idir, mode), "w")

    tresult = []
    ttotal = len(tlst)
    terr = 0
    for fname in tlst:
        f = open("{}/{}".format(idir, fname), "r")

        lst = []
        times = {}
        for line in f:
            tmp = line.strip().split(", ")
            idx = int(tmp[0])
            time = int(tmp[2])
            lst.append((int(tmp[0]), tmp[1], int(tmp[2])))
            times[tmp[1]] = int(tmp[2])
        f.close()
        try:
            tresult.append((times["SEED_LT_SERVER_AFTER_TLS_ACCEPT"] - times["SEED_LT_SERVER_BEFORE_TLS_ACCEPT"]))
        except:
            terr = terr + 1
            continue

    cresult = []
    ctotal = len(clst)
    cerr = 0
    for fname in clst:
        f = open("{}/{}".format(idir, fname), "r")

        lst = []
        times = {}
        for line in f:
            tmp = line.strip().split(", ")
            idx = int(tmp[0])
            time = int(tmp[2])
            lst.append((int(tmp[0]), tmp[1], int(tmp[2])))
            times[tmp[1]] = int(tmp[2])
        f.close()
        try:
            cresult.append((times["SEED_LT_SERVER_AFTER_TLS_ACCEPT"] - times["SEED_LT_SERVER_BEFORE_TLS_ACCEPT"]))
        except:
            cerr = cerr + 1

    time = "Elapsed Time: {} / Stdev: {} / Total: {} / Errors: {}\n".format(average(tresult), stdev(tresult), ttotal, terr)
    cpu = "CPU Time: {} / Stdev: {} / Total: {} / Errors: {}\n".format(average(cresult), stdev(cresult), ctotal, cerr)

    oft.write(time)
    ofc.write(cpu)

    print (time)
    print (cpu)

    oft.close()
    ofc.close()

def client_analysis(idir, mode):
    tlst = []
    clst = []
    for f in os.listdir(idir):
        if "time" in f and mode in f:
            tlst.append(f)
        elif "cpu" in f and mode in f:
            clst.append(f)

    oft = open("{}_{}_time.csv".format(idir, mode), "w")
    ofc = open("{}_{}_cpu.csv".format(idir, mode), "w")

    tresult = []
    ttotal = len(tlst)
    terr = 0
    for fname in tlst:
        f = open("{}/{}".format(idir, fname), "r")

        lst = []
        times = {}
        for line in f:
            tmp = line.strip().split(", ")
            idx = int(tmp[0])
            time = int(tmp[2])
            lst.append((int(tmp[0]), tmp[1], int(tmp[2])))
            times[tmp[1]] = int(tmp[2])
        f.close()
        try:
            tresult.append((times["SEED_LT_CLIENT_AFTER_TLS_CONNECT"] - times["SEED_LT_CLIENT_BEFORE_TLS_CONNECT"]))
        except:
            terr = terr + 1
            continue

    cresult = []
    ctotal = len(clst)
    cerr = 0
    for fname in clst:
        f = open("{}/{}".format(idir, fname), "r")

        lst = []
        times = {}
        for line in f:
            tmp = line.strip().split(", ")
            idx = int(tmp[0])
            time = int(tmp[2])
            lst.append((int(tmp[0]), tmp[1], int(tmp[2])))
            times[tmp[1]] = int(tmp[2])
        f.close()
        try:
            cresult.append((times["SEED_LT_CLIENT_AFTER_TLS_CONNECT"] - times["SEED_LT_CLIENT_BEFORE_TLS_CONNECT"]))
        except:
            cerr = cerr + 1
            continue

    time = "Elapsed Time: {} / Stdev: {}\n".format(average(tresult), stdev(tresult), ttotal, terr)
    cpu = "CPU Time: {} / Stdev: {} / Total: {} / Errors: {}\n".format(average(cresult), stdev(cresult), ctotal, cerr)

    oft.write(time)
    ofc.write(cpu)

    print (time)
    print (cpu)

    oft.close()
    ofc.close()


def main():
    args = parser.parse_args()
    idir = args.input
    role = args.role
    mode = args.mode

    if role == "seed":
        seed_analysis(idir, mode)
    elif role == "client":
        client_analysis(idir, mode)
    else:
        print ("invalid role")
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze the log file')
    parser.add_argument('--input', required=True, help='input directory')
    parser.add_argument('--role', required=True, help='seed/client')
    parser.add_argument('--mode', required=True, help='vanila/seed')
    main()

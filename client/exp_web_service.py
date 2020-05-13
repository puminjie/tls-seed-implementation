import argparse
import os

global parser

def execute_client(domains):
    f = open(domains, "r")

    for line in f:
        tmp = line.strip().split(",")
        url = tmp[1]
        dom = url[8:]

        slash = question = -1
        if '/' in dom:
            slash = dom.index('/')
        if '?' in dom:
            question = dom.index('?')

        if slash < 0 and question < 0:
            content = "/"
        elif slash > 0 and question < 0:
            content = dom[slash:]
            dom = dom[:slash]
        elif slash < 0 and question > 0:
            content = dom[question:]
            dom = dom[:question]
        elif slash > 0 and question > 0:
            if slash < question:
                content = dom[slash:]
                dom = dom[:slash]
            else:
                content = dom[question:]
                dom = dom[:question]

        os.system("./client -h {} -p 443 -c {} -m vanila".format(dom, content))

    f.close()

def main():
    args = parser.parse_args()
    domains = args.input
    
    execute_client(domains)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web service experiment")
    parser.add_argument('--input', required=True, help='Domain list')
    main()

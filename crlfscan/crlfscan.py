#!/usr/bin/python3
# coding: utf-8
# -*- coding: utf-8 -*-


try:
    import multiprocessing.shared_memory as shm
    from multiprocessing import shared_memory
except NameError:
    pass
except ImportError:
    pass


import threading
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
import argparse
import requests
import os
from requests.exceptions import HTTPError
from requests.exceptions import ConnectionError
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from apscheduler.schedulers.background import BackgroundScheduler
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    concurrent = 600 * 1000
    scheduler = BackgroundScheduler()

    def ascii():

            print("""

     ██████╗██████╗ ██╗     ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔════╝██╔══██╗██║     ██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║     ██████╔╝██║     █████╗      ███████╗██║     ███████║██╔██╗ ██║
    ██║     ██╔══██╗██║     ██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║
    ╚██████╗██║  ██║███████╗██║         ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

                @sabarishh4ck3r        #created = sabarish

            """)

    ascii()

    proxy = {'http': 'http://127.0.0.1:8080'}

    gen_headers = {'User-Agent':'Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201',
                    'Accept-Language':'en-US;',
                    'Accept-Encoding': 'gzip, deflate',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;',
                    'Connection':'close'}

    parser = argparse.ArgumentParser(description="scanning a crlf bugs")
    parser.add_argument("-f", "--file", help="to give a list of urls")
    parser.add_argument('-d', '--domain', help='to give a single domain')
    parser.add_argument("-t", '--threads', help='to boost a request speed')
    parser.add_argument('-m', '--multiplex', help='specific to different proxy default local proxy')
    parser.add_argument('-v', '--verbose', help='to print the all request')
    args = parser.parse_args()

#    if (os.path.isfile(args.file)):
#            run(args.file)
#    else:
#            print ("No Such file")


    def payload():
        with open('payloads.txt', 'r') as f:
            line = f.readlines()
            return line

    default_payload = payload()  

    # Protocol either 'http://' or 'https://'
    def crlf(subdomain, pay):

        for payload in pay:

            try:
                jam = ("{}{}".format(subdomain, payload))
    #            print(len(he))
                urls= jam.strip()
                r = requests.get(urls , headers=gen_headers, verify=False, timeout=9, allow_redirects=False)
                #print(r)
                print(r.url)
                #print(r.cookies.keys())
                if r.headers["crlfs"]:
                    print(colored("[ * ] vulnerable bounty conform: ", 'red') + r.url,payload)
                if 'crlfs' in r.cookies.get_dict() and\
                    'sabarishh4ck3r' in r.cookies.get_dict().values():
                    print(colored("[ * ] vulnerable bounty conform: ", 'red') + r.url,payload)
                for name in r.cookies.keys():
                    if "crlfs" in name:
                        print("VULNERABLE: {}/{}".format(subdomain, payload))
                for role in r.cookies:
                    if "crlfs" in role:
                        print("VULNERABLE: {}/{}".format(subdomain, payload))                 
    #                    os.system("echo %s/%s >> crlf-results.txt" % (subdomain, payload))	
                    #os.system("echo %s/%s >> crlf-results.txt" % (subdomain, payload))	    
            except ConnectionError:
                pass
            except HTTPError:
                pass
            except Exception as e:
                pass
    
    if args.verbose:
        pass

    def run(file):
        with open(file, "r") as f:
            for subdomain in f:
                subdomain = subdomain.split()[0]
                print ("Scanning: %s " % subdomain)
                executor.submit(crlf, subdomain, default_payload)
    try:
        executor = ThreadPoolExecutor(1000)
    except threading:
        pass
    except RuntimeError:
        pass
    try:
        if args.threads:
            executor = ThreadPoolExecutor(args.threads)
        else:
            executor = ThreadPoolExecutor(1000)
    except TypeError:
        pass
    except RuntimeError:
        pass

    if args.domain:
        print ("Scanning: %s " % args.domain)
        executor.submit(crlf, args.domain, default_payload)

    scheduler.start()

    if args.multiplex:
        executor.submit(crlf, args.domain, default_payload, args)

    try:
        q = range(concurrent)
        for t in q:
            t = Thread(target=payload)
            t.daemon = True
            t.start()
    except TypeError:
        pass
    except RuntimeError:
        pass
    except RuntimeWarning:
        pass
    except KeyboardInterrupt:
        quit()
    except AttributeError:
        pass
    except OSError:
        pass

    if args.file:
        run(args.file)
    #                    os.system("echo %s/%s >> crlf-results.txt" % (subdomain, payload))	
                    #os.system("echo %s/%s >> crlf-results.txt" % (subdomain, payload))	    

if __name__ == "__main__":
    main()
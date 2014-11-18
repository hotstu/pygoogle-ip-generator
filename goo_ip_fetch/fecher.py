'''
Created on Oct 5, 2014

@author: foo
'''
import os
import sys
import random
import ssl
import socket
import time
from queue import Queue
from threading import Thread


DATE_FORMAT = '%Y/%m/%d %H:%M:%S'

class Fecher:
    """
    randomly generate avaliable google ip aginst GFW,inspired by gogo-tester & txthing/google-hosts
    """
    def __init__(self, server_name=None, limit=50):
        self.server_name = server_name
        self.limit = limit
        
    def random_ip_gen(self):
        file_size = os.stat('googleIPpool.dat').st_size
        print(file_size)
        with open('googleIPpool.dat', 'rb') as f:
            for i in range(self.limit):
                position = random.randrange(file_size)
                f.seek(position)  # go to random position
                f.readline()  # drop it since it's broken
                random_line = f.readline()
                if len(random_line) == 0:  # we have hit the end
                    f.seek(0)
                    random_line = f.readline()
                random_line = random_line.decode().strip()
                tem = random_line.split('.')
                tem_range = tem[-1].split('-')
                if len(tem_range) != 2:
                    print("==========badinput===========")
                    print(random_line)
                    continue
                min = 1 if tem_range[0] == 0 else int(tem_range[0])
                max = 254 if tem_range[1] == 255 else int(tem_range[1])
                tem[-1] = str(random.randrange(min, max + 1))
                ip = '.'.join(tem)
                print(i, position, ip)
                yield ip

class GoHandler:
    def __init__(self, address, timeout=None, domain_filter=None, result_queue=None):
        """
        @param domain_filter: if set,example:youtube.com, will only return the ip which 
        cert's DNS field matchs it, this may helpful if the IP is add to a hosts file,
        the browser will not warn cert err.
        """
        self.address = address
        self.timeout = timeout
        self.domain_filter = domain_filter
        self.result_queue = result_queue
     
    def do(self):
        if self.timeout:
            socket.setdefaulttimeout(self.timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.create_default_context()
        context.check_hostname = False
        #if check_hostname = ture, server_hostname can't be none
        ssl_sock = context.wrap_socket(sock)
        try:
            start_time = time.time()
            ssl_sock.connect(self.address)
            cert = ssl_sock.getpeercert(binary_form=False)
            ssl_sock.close()
            end_time = time.time()
            if self.domain_filter != None:
                self._check_name(cert, self.domain_filter)
            time_cost = '{:.6f}'.format(end_time - start_time)
            print("{1}:connect to {0} Success!!".format(self.address[0], time_cost))
            if self.result_queue:
                self.result_queue.put((self.address[0], time_cost))
        except ssl.SSLError as err:
            print("{2}:connect to {1} SSLError: {0}"
                  .format(err, self.address[0], time.strftime(DATE_FORMAT,time.localtime())))
        except ssl.CertificateError as err:
            print("{2}:connect to {1} CertificateError: {0}"
                  .format(err, self.address[0], time.strftime(DATE_FORMAT,time.localtime())))
        except socket.timeout:
            print("{2}:connect to {1} timeout err: timeout in {0} seconds"
                  .format(self.timeout, self.address[0], time.strftime(DATE_FORMAT,time.localtime())))
            
    def _check_name(self, cert, domain):
        subject_altname = cert.get('subjectAltName',{})
        domains = ";".join([i[1] for i in subject_altname if i[0] == "DNS"])
        if domain not in domains:
            raise ssl.CertificateError("not match domain %s" % domain)
            
def do_work():
    while True:
        ip = q.get()
        g = GoHandler((ip, 443), timeout=6, domain_filter="android.com", result_queue=result)
        try:
            g.do()
        except:
            print(ip,'unexpected Exception')

def do_result():
    while True:
        r = result.get()
        if r:
            with open('avalable_googleip.txt','a') as f:
                f.writelines("%s  %s\n" % r)

def main():
    with open('avalable_googleip.txt','a') as f:
        f.writelines('============%s=================\n' % time.strftime(DATE_FORMAT,time.localtime()))
    global q
    q = Queue(50)
    global result
    result = Queue(10)
    for i in range(10):
        t = Thread(target=do_work)
        t.daemon = True
        t.start()
    file_writer = Thread(target=do_result)
    file_writer.daemon = True
    file_writer.start()
    ips = Fecher(None, 200)
    try:
        for ip in ips.random_ip_gen():
            q.put(ip)
        q.join()
    except KeyboardInterrupt:
        sys.exit(1)


def test():
    h = GoHandler(("foxmail.com",443), 6, "qq.com")
    h.do()

if __name__ == '__main__':
    main()











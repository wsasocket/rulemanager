# 自动生成webtroj库

from urllib.parse import urlparse
import requests
import re
import os

NETSOURCE = {
    'MalwareURL': r'https://www.threatweb.com/access/Malware-URLs-High_Confidence_BL.txt',
    'PhishingURL': r'https://www.threatweb.com/access/Phishing-URLs-High_Confidence_BL.txt'
}
LOCALSOURCE = {
    'MalwareURL': r'C:\Snort\Malware-URLs-High_Confidence_BL.txt',
    'PhishingURL': r'C:\Snort\Phishing-URLs-High_Confidence_BL.txt'
}


def getHost(url):
    """获取主机域名或者IP"""
    parts = urlparse(url)
    if len(parts) < 3:  # 应当至少包含协议，主机，路径三部分
        return None
    return parts.hostname


def readURLFromFile(file):
    """从文件中读取数据"""
    hosts = set()
    with open(file) as fp:
        for line in fp:
            h = getHost(line.strip('\n\r\t'))
            if h:
                hosts.add(h)
    print(f'{file=}:{len(hosts)}')
    return hosts


def readURLFromStream(stream):
    """从数据流中读取数据"""
    hosts = set()
    for line in stream.split('\n'):
        h = getHost(line.strip('\n\r\t'))
        if h:
            hosts.add(h)
    print(f'Net:{len(hosts)}')
    return hosts


def gatherURL(originalSRC: dict):
    """ From Net gather malware URL and phishing URL,return list of urls netloc(domain/ip)"""
    # 要求数据以行为单位
    hosts = set()
    for v in originalSRC.values():
        if v.startswith('http'):
            stream = requests.get(v)
            hosts = hosts.union(readURLFromStream(stream.text))
        elif os.path.isfile(v):
            # 下载的文件
            # hosts = hosts.union(readURLFromFile(v))
            hosts = hosts.union(readURLFromFile(v))

    return hosts


def lookupDomain(hosts: set):
    pass


if __name__ == "__main__":
    h = gatherURL(NETSOURCE)
    print(len(h))
    with open('webtrojan.sig', 'w') as fp:
        for i in h:
            fp.write(f'{i}\n')

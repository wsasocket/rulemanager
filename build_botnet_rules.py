import re
from hashlib import md5
from requests import get as GET
from abc import ABCMeta, abstractmethod
from urllib.parse import urlparse
# from io import StringIO
from datetime import date
import requests
blasklist = r'botnet_ip_reputation_2020-01-16_22_13.txt'
threatweb_info = {
    'BotnetIP': 'Botnet-IPs-High_Confidence_BL.txt',
    'MalwareDomain': 'Malware-Domains-High_Confidence_BL.txt',
    'MalwareIP': 'Malware-IPs-High_Confidence_BL.txt',
    'MalwareURL': 'Malware-URLs-High_Confidence_BL.txt',
    'PhishingURL': 'Phishing-URLs-High_Confidence_BL.txt'
}
blasklist_url = r'https://www.threatweb.com/access'


class BlackListBuilder(metaclass=ABCMeta):

    def __init__(self, response):
        self.response = response
        # self.buffer = StringIO()
        self._dataset = set()
        self._init_data()
        self._sid = 0
        self._update = date.today().isoformat()

    def _init_data(self):
        if not isinstance(self.response, str):
            raise TypeError('Intenet Data Type Error')
        # write to buffer
        lines = self.response.split('\n')
        for l in lines:
            r = self.filter(l)
            if r is not None:
                self._dataset.add(r)

    @property
    def sid(self) -> int:
        return self._sid

    @sid.setter
    def sid(self, value: int):
        if not isinstance(value, int):
            raise TypeError('Sid should be Integer')
        self._sid = value

    def builder(self, **kwargs):
        t = self.template()
        return t.format(**kwargs)

    def save(self, filename=None):
        # self.buffer.seek(0)
        o = None
        if filename is not None:
            o = open(filename, 'w')

        # for bl in self.buffer.readlines():
        for bl in self._dataset:
            bl = bl.strip('\n')
            m = md5()
            m.update(bl.encode())
            hash_val = m.hexdigest()
            hash_val = hash_val[:6].upper()
            rule = self.builder(bl=bl, sid=self._sid,
                                hash=hash_val, update=self._update)
            self._sid += 1
            if filename:
                o.write(f'{rule}\n')
            else:
                print(rule)

        if o is not None:
            o.close()
        # self.buffer.close()

    @abstractmethod
    def template(self) -> str:
        # 在继承类中必须完备的接口
        # 返回一个规则的模板
        pass

    @abstractmethod
    def filter(self, item):
        # 在继承类中必须完备的接口
        # 返回需要的数据，比如IP或者域名
        pass


class BotnetBuilder(BlackListBuilder):
    def template(self) -> str:
        return 'alert ip $HOME_NET any -> {bl} any (msg:"[Botnet] IP Reputation {hash}"; metadata:update {update}; classtype:trojan-activity; priority:4; sid:{sid}; rev:1;)'

    def filter(self, item) -> str:
        pattern = r'(\d+\.\d+\.\d+\.\d+)'
        r = re.match(pattern, item)
        if r:
            return r.group()
        else:
            return None

    # def foo(self):
    #     return self.__class__


class MalwareIPBuilder(BlackListBuilder):

    def template(self) -> str:
        return 'alert ip $HOME_NET any -> {bl} any (msg:"[Malware] IP Reputation {hash}"; metadata:update {update}; classtype:trojan-activity; priority:4; sid:{sid}; rev:1;)'

    def filter(self, item) -> str:
        pattern = r'(\d+\.\d+\.\d+\.\d+)'
        r = re.match(pattern, item)
        if r:
            return r.group()
        else:
            return None


class MalwareURLBuilder(BlackListBuilder):

    def template(self) -> str:
        return 'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"[Malware] Domain Reputation detect {hash}"; content:"{bl}"; metadata:update {update}; classtype:trojan-activity; priority:4; sid:{sid}; rev:1;)'

    def filter(self, item) -> str:
        url_part = urlparse(item)
        if len(url_part.netloc) < 3:
            return None
        return url_part.netloc
        # rebuild DNS request pattern
        # dns = url_part.netloc.split('\.')
        # print(dns)
        # return dns


class MalwareDomainBuilder(BlackListBuilder):

    def template(self) -> str:
        return 'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"[Malware] Domain Reputation detect {hash}"; content:"{bl}"; metadata:update {update}; classtype:trojan-activity; priority:4; sid:{sid}; rev:1;)'

    def filter(self, item) -> bytearray:
        blacklist = ['/', '\\', '?', '&', '=', '\'', '"', '<', '>']
        for b in blacklist:
            if b in item:
                return None
        dns = item.split('.')
        dns_request = str()
        for d in dns:
            dns_request += '|{:02x}|'.format(len(d))
            dns_request += d
        dns_request += '|00|'
        # rebuild DNS request pattern
        # dns = url_part.netloc.split('\.')
        # print(dns)
        return dns_request


if __name__ == "__main__":
    # sid = 630000
    # builder = BotnetBuilder("1.1.1.1")
    # builder = eval("BotnetBuilder")("1.1.1.1\n2.2.2.2\n1.1.1.1")
    # builder.sid = 630000
    # builder.save()
    url = '{}/{}'.format(blasklist_url, threatweb_info['MalwareDomain'])
    response = requests.get(url)
    builder = eval("MalwareDomainBuilder")(response.text)
    builder.sid = 640000
    builder.save("malaredomain.rules")

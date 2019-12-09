import sys
sys.path.append('/Library/Frameworks/Python.framework/Versions/3.7/lib/python3.7/site-packages')
import requests
from bs4 import BeautifulSoup
import re


class SecFocusInfo(object):
    # https://cve.mitre.org/cgi-bin/cvename.cgi?name={}
    # describe:
    # xpath = /html/body/div[1]/div[3]/div[2]/table/tbody/tr[4]/td
    def __init__(self, bid):
        self._affect = None
        self._credit = None
        self._detail = None
        self._title = None
        self._solution = None
        self.bid = None
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
        headers = {"User-Agent": user_agent}  # 请求头,headers是一个字典类型
        # se = requests.Session()
        url = 'https://www.securityfocus.com/bid/{}/info'.format(bid)
        # print(url)
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            raise ValueError('Url return code :{:d}'.format(r.status_code))
        # print(r.text)
        soup = BeautifulSoup(r.content, features="html.parser")
        divs = soup.select("#vulnerability > table > tr")

        for t in divs:
            td = t.select('td')
            if td:
                # print('----------')
                # print(td[1].get_text())
                if td[0].get_text().strip('\n ') == 'Vulnerable:':
                    self._affect = str()
                    for line in td[1].get_text().split('\n'):
                        line = line.strip('\n\t ')
                        if len(line) == 0:
                            continue
                        self._affect += line
                        if line == '+':
                            continue
                        else:
                            self._affect += '\n'

                if td[0].get_text().strip('\n ') == 'Credit:':
                    self._credit = str()
                    for line in td[1].get_text().split('\n'):
                        line = line.strip('\n\t ')
                        if len(line) == 0:
                            continue
                        self._credit += line
                        self._credit += '\n'
        # -----------------------------------------
        url = 'https://www.securityfocus.com/bid/{}/discuss'.format(bid)
        # print(url)
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            raise ValueError('Url return code :{:d}'.format(r.status_code))

        soup = BeautifulSoup(r.content, features="html.parser")
        divs = soup.select("#vulnerability > span")
        self._title = divs[0].text.strip('\n\t ')

        divs = soup.select("#vulnerability")
        self._detail = divs[0].text[len(self._title)+1:].strip('\n\t ')

        # -----------------------------------------
        url = 'https://www.securityfocus.com/bid/{}/solution'.format(bid)
        # print(url)
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            raise ValueError('Url return code :{:d}'.format(r.status_code))
        soup = BeautifulSoup(r.content, features="html.parser")
        divs = soup.select("#vulnerability")
        self._solution = divs[0].text[len(self._title)+1:].strip('\n\t ')
        if self._solution.startswith('Solution:'):
            self._solution = self._solution[9:].strip('\n\r\t ')
        # for i in divs:
        #     print(i)
        # print(self._title)


    @property
    def affect(self):
        return self._affect

    @property
    def credit(self):
        return self._credit

    @property
    def detail(self):
        return self._detail

    @property
    def summary(self):
        return self._title

    @property
    def solution(self):
        return self._solution
    #
    # @property
    # def get_bid(self):
    #     return self.bid

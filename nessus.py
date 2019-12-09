import sys
sys.path.append('/Library/Frameworks/Python.framework/Versions/3.7/lib/python3.7/site-packages')
import requests
from bs4 import BeautifulSoup
import re


class NessusInfo(object):

    def __init__(self, nessus_id):
        self._detail = None
        self._summary = None
        self._solution = None
        self._addition = None
        self._bid = None
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
                     "Chrome/51.0.2704.103 Safari/537.36"
        headers = {"User-Agent": user_agent}  # 请求头,headers是一个字典类型
        se = requests.Session()
        url = 'https://www.tenable.com/plugins/nessus/{}'.format(nessus_id)
        # print(url)
        r = se.get(url, headers=headers)
        if r.status_code != 200:
            raise ValueError('Url return code :{:d}'.format(r.status_code))
        # print(r.text)
        soup = BeautifulSoup(r.content, features="html.parser")
        section = soup.select(".col-md-8 > section")
        title = ['Synopsis', 'Description', 'Solution', 'See Also']
        for i, t in enumerate(section):
            if t.text.startswith(title[i]):
                if i == 0:
                    self._summary = t.text[len(title[i]):]
                if i == 1:
                    self._detail = t.text[len(title[i]):]
                if i == 2:
                    self._solution = t.text[len(title[i]):]
                if i == 3:
                    self._addition = t.text[len(title[i]):]

        section = soup.select(".col-md-4 > section > section")
        for s in section:
            title = s.select('p > strong')
            if title:
                if 'BID' in title[0].text:
                    self._bid = s.select('p > span')[0].text

    @property
    def detail(self):
        return self._detail

    @property
    def summary(self):
        return self._summary

    @property
    def solution(self):
        return self._solution

    @property
    def addition(self):
        return self._addition

    @property
    def bid(self):
        return self._bid

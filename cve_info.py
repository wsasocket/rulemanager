import sys
sys.path.append('/Library/Frameworks/Python.framework/Versions/3.7/lib/python3.7/site-packages')
import requests
from bs4 import BeautifulSoup
import re


class CVEInfo(object):
    # https://cve.mitre.org/cgi-bin/cvename.cgi?name={}
    # describe:
    # xpath = /html/body/div[1]/div[3]/div[2]/table/tbody/tr[4]/td
    def __init__(self, cve):
        self.info = None
        self.bid = None
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
        headers = {"User-Agent": user_agent}  # 请求头,headers是一个字典类型
        se = requests.Session()
        url = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name={}'.format(cve)
        # print(url)
        r = se.get(url, headers=headers)
        if r.status_code != 200:
            raise ValueError('Url return code :{:d}'.format(r.status_code))
        # print(r.text)
        soup = BeautifulSoup(r.content, features="html.parser")
        divs = soup.select("#GeneratedTable > table > tr")
        flag = 0
        for t in divs:
            if flag == 1:
                self.info = t.get_text().strip(' \n\r')
                break
            else:
                th = t.select('th')
                if th:
                    if th[0].text == 'Description':
                        flag = 1
                        continue
        pattern = r'BID:([\d]{2,10})'
        for t in divs:
            r = re.search(pattern, t.get_text().strip(' \n\r'))
            if r:
                self.bid = r.group(1)
                break


    @property
    def detail(self):
        return self.info

    @property
    def detail_cn(self):
        return self.info

    
    def get_bid(self):
        return self.bid

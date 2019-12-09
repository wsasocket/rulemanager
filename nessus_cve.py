# 页面解析方法使用 xpath+lxml
import sys
import requests
from lxml import etree
import re
'''
xpath('//a')：找到全局中所有的a标签
xpath('//a/text()  ')：获取a标签的文本值
xpath('//a/span')：a标签对象儿子下的span标签
xpath('//a[2]')：a标签找到后，返回的是一个列表，[n]列表的n位置的值
xpath('//a[@id]')：找全局中属性为id的a标签
xpath('//a[@id="i1"]')：找全局中属性id为i1的a标签
xpath('//a/@id')：取a标签的id的属性值
xpath('//a[@href="link.html"][@id="i1"]')：两个[]代表双条件，需要href="link.html“，且id="i1"的a标签
xpath('//a[contains(@href, "link")]')：a标签的href需要包含"link"字符
xpath('//a[starts-with(@href, "link")]')：a标签的href需要以"link"开头
xpath('//a[re:test(@id, "i\d+")]')：正则表达式的写法，需要有re:test
xpath('//a[re:test(@id, "i\d+")]/@href').extract()，正则表达式的写法案例
xpath(.//）在当前基础上往下找，需要加“.”，比如用在for循环中
#xpath('//a[contains(@href, "image")]/text()').re(r'Name:\s*(.*)')  用正则表达式
obj.extract()#列表中的每一个对象转化字符串==>返回一个列表
obj.extract_first() #列表中的每一个对象转化字符==>列表中的第一个元素
xpath('/html/body/ul/li/a/@href').extract()：一层层去找标签
原文: https://stackoverflow.com/questions/2755950/how-to-use-regular-expression-in-lxml-xpath
xpath("//a[starts-with(text(),'some text')]")
xpath("//a[re:match(text(), 're')]", namespaces={"re": "http://exslt.org/regular-expressions"})
---------------------
原文：https://blog.csdn.net/PbGc396Dwxjb77F2je/article/details/79766176
'''
class CVEInfo2(object):
    def __init__(self,cve):
        self._html = None
        self._bid = list()
        self._nessus_id = list()
        self._level = None
        self._description = None
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
                     "Chrome/51.0.2704.103 Safari/537.36"
        headers = {"User-Agent": user_agent}  # 请求头,headers是一个字典类型
        se = requests.Session()
        url = 'https://www.tenable.com/cve/{}'.format(cve)
        r = se.get(url, headers=headers)
        if r.status_code != 200:
            raise ValueError('Url return code :{:d}'.format(r.status_code))
        self._html = etree.HTML(r.text)
        self._parse()
    
    def _parse(self):
        bid_pattern = r'www.securityfocus.com/bid/(\d+)'
        level_xpath = '/html/body/div[1]/div/div[3]/div/div/div/p/span/text()'
        description_xpath = '/html/body/div[1]/div/div[3]/div/div/div/div/div/div[1]/div/div[1]/p[1]/text()'
        # p 下所有包含href的a标签
        reference_xpath = '/html/body/div[1]/div/div[3]/div/div/div/div/div/div[1]/div/div[1]/p/a[@href]'
        
        # Xpath不能跨越（不明确标注）任何节点，否则就不是路径了
        # '/html/body/div[1]/div/div[3]/div/div/div/div/div/div[3]/section/table/tbody/a[@href]'
        # 在上面的例子中，原本想获取表格中含有href属性的a标签的内容，但是tbody下面还有td tr等标签
        # 所以上面的例子就无法获取信息
        nessus_id_xpath = '/html/body/div[1]/div/div[3]/div/div/div/div/div/div[3]/section/table/tbody/tr'
        ref = self._html.xpath(reference_xpath)
        nessus = self._html.xpath(nessus_id_xpath)
        self._level = self._html.xpath(level_xpath)[0]
        self._description = self._html.xpath(description_xpath)[0]

        for i in ref:
            # print(i.text)
            r = re.search(bid_pattern,i.text)
            if r:
                self._bid.append(r.group(1))
        for row in nessus:
            col = row.xpath(r'.//td/a[re:test(text(), "\d+")][@href]',namespaces={"re": "http://exslt.org/regular-expressions"})
            # 上面的例子中，先取到了表格的行（tr）然后通过枚举每行中，在当前行中取列及每个单元中a标签，且有href属性，
            # 而且text()可以通过正则表达式进行过滤
            for id in col:
                # print(id.text)
                self._nessus_id.append(id.text)
        
        # print(self.bid)
        # print(self.nessus_id)
    
    @property
    def bid(self):
        return self._bid
    
    @property
    def nessus_id(self):
        return self._nessus_id

    @property
    def detail(self):
        return self._description

    @property
    def level(self):
        return self._level

# if __name__ == "__main__":
#     CVE = CVEInfo2('CVE-2018-0171')
#     print(CVE.detail)
#     print(CVE.level)
#     print(CVE.bid)
#     print(CVE.nessus_id)




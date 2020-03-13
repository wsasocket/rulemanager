from documents import Document
import os
import json
import sqlite3
import contextlib
import re
# {"CVE": "CVE-2019-16662",
#    "NIST": {
#       "CPEs": [
#           {"CPE": "cpe:2.3:a:rconfig:rconfig:3.9.2:*:*:*:*:*:*:*",
#           "FROM": "",
#           "UPTO": ""
#           }
#               ],
#       "CWEs": [
#           {"CODE": "CWE-78",
#           "DESC": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
#           "SOURCE": "NIST"
#           }],
#       "CVSS": {
#           "VERSION": "3.1",
#           "CVSS": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
#           "SCORE": 0
#           }
#       }
# }

sourceCNNVD = ''
sourceNVD = ''


class NewDocument(Document):
    def __init__(self, sid, path='./', *, pop=0):
        super().__init__(sid, path='./')
        self.keys_map = {'Summary': 'detail', 'Impact': 'threaten_type', 'Detailed Information': 'brief',
                         'Attack Scenarios': 'vuln_type', 'Ease of Attack': 'level', 'False Positives': 'cve',
                         'False Negatives': 'cnnvd', 'Corrective Action': 'bulletin', 'Contributors': 'N/A',
                         'Additional References': 'reference', 'Affected Systems': 'affect'}
        self._info_dict_EN['Contributors'] = self._info_dict['Contributors'] = pop

    def rebuild(self, cnnvd: dict, nvd: dict):
        for k, v in self.keys_map.items():
            with contextlib.suppress(KeyError):
                self._info_dict_EN[f'EN {k}'] = cnnvd[v] if v in cnnvd.keys(
                ) else nvd[v]
                self._info_dict[k] = cnnvd[v] if v in cnnvd.keys(
                ) else nvd[v]

    def build_default(self, type: str, / , *, ref=None):
        if ref:
            self._info_dict_EN['EN Additional References'] = self._info_dict["Additional References"] = '\n'.join(
                ref)

        if type == 'botnet':
            self._info_dict_EN['EN Summary'] = self._info_dict["Summary"] = '发现有Botnet的活动迹象'
            self._info_dict_EN['EN Detailed Information'] = self._info_dict[
                "Detailed Information"] = '发现有僵尸网络的活动迹象，可能是僵尸网络的通信连接，也可能是触发了僵尸网络域名或者IP的黑名单机制。具体情况请联系系统安全维护人员。'
        elif type == 'malware':
            self._info_dict_EN['EN Summary'] = self._info_dict["Summary"] = '发现有恶意软件的活动迹象'
            self._info_dict_EN['EN Detailed Information'] = self._info_dict[
                "Detailed Information"] = '发现有恶意软件的活动迹象，可能是木马、蠕虫、后门或者是可能存在令人反感的广告程序。具体情况请联系系统安全维护人员。'
        elif type == 'brute':
            self._info_dict_EN['EN Summary'] = self._info_dict["Summary"] = '发现有暴力攻击的活动迹象'
            self._info_dict["Detailed Information"] = self._info_dict_EN[
                'EN Detailed Information'] = '发现有暴力攻击的活动迹象，暴力攻击往往是渗透攻击的前奏，目的是为了获取口令或其他敏感信息。具体情况请联系系统安全维护人员。'

        else:
            self._info_dict_EN['EN Summary'] = self._info_dict["Summary"] = '发现有攻击行为的活动迹象'
            self._info_dict["Detailed Information"] = self._info_dict_EN['EN Detailed Information'] = '发现有攻击行为的活动迹象，具体情况请联系系统安全维护人员。'


class AbsDatabase():
    def __init__(self, path):
        self.db = list()
        self.dbfile = path
        if not os.path.isfile(path):
            raise(FileNotFoundError)

    def init_db(self):
        pass

    def query(self, cve):
        pass

    def close(self):
        pass


class NVDDatabase(AbsDatabase):

    def init_db(self):
        # json style
        with open(self.dbfile, 'r', encoding='utf8') as fp:
            for line in fp:
                tmp = dict()
                tmp = json.loads(line)
                self.db.append(tmp.copy())

    def query(self, cve):
        for i in self.db:
            if cve == i['CVE']:
                return i
        else:
            return None

    def close(self):
        pass


class CVEDatabase(AbsDatabase):
    # sqlite3 style
    def init_db(self):
        self.connection = sqlite3.connect(self.dbfile)
        self.cursor = self.connection.cursor()

    def query(self, cve):
        colmun = ('cve', 'cnnvd', 'detail', 'level', 'vuln_type', 'threaten_type', 'manufacturer',
                  'source', 'brief', 'bulletin', 'reference', 'affect', 'expose_date', 'reflash_date',)
        SQL = r'SELECT * FROM info WHERE cve=:1'
        res = self.cursor.execute(SQL, [cve])
        if res:
            return dict(zip(colmun, res.fetchone()))
        else:
            return None

    def close(self):
        self.cursor.close()
        self.connection.close()


def select_cve_for_sid(rule):
    """
    解析一条规则中的CVE,popularity,type信息，排序然后返回，如果没有CVE返回None,这时type必须不能为空"""
    sid = None
    _type = None
    pop = None
    refs = None
    pattern = r'sid:([\d]+);'
    sid = re.search(pattern, rule).group(1)

    pattern = r'cve,([\d]+\-[\d]+);'
    cve = re.findall(pattern, rule)
    if len(cve) > 1:
        cve.sort(reverse=True)
    if 'botnet' in rule.lower():
        _type = 'botnet'
    elif 'malware' in rule.lower():
        _type = 'malware'
    elif 'brute' in rule.lower():
        _type = 'brute'
    else:
        pattern = r'classtype:([^;]+)'
        _type = re.search(pattern, rule).group(1)

    pattern = r'reference:pop,([\d]);'
    pop = re.search(pattern, rule)

    pattern = r'reference:url,(.*?);'
    refs = re.findall(pattern, rule)

    return sid, pop.group(1) if pop is not None else None, [f'CVE-{x}' for x in cve], _type, refs


if __name__ == "__main__":
    # # 组合两个库中的信息
    # doc.rebuild(res1, res2)
    # doc.save()

    # cnnvd_db.close()

    # doc = NewDocument(10000)
    # doc.build_default("botnet", ref="https:sec.com.cn")
    # doc.save()
    demo1 = """alert udp $EXTERNAL_NET any -> $HOME_NET [696,7426] (msg:"SERVER-OTHER HP Network Node Manager ovopi.dll buffer overflow attempt"; flow:stateless; content:"|A9 02 00 00|-S"; depth:6; isdataat:20,relative; content:!"|3B|"; within:20; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop; reference:cve,2014-2624; reference:url,h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c04378450; classtype:attempted-admin; sid:32085; rev:4;)"""
    demo2 = """alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Generic HTTP Server HyperLink buffer overflow attempt"; flow:to_server,established; content:"GET /"; fast_pattern:only; urilen:>1450; metadata:policy max-detect-ips drop, service http; reference:bugtraq,13045; reference:bugtraq,14195; reference:bugtraq,36815; reference:bugtraq,37184; reference:cve,2002-0071; reference:cve,2004-0629; reference:cve,2004-0848; reference:cve,2005-0057; reference:cve,2005-0986; reference:cve,2007-0774; reference:cve,2007-6377; reference:cve,2009-0895; reference:cve,2011-1965; reference:cve,2013-5019; reference:cve,2014-3913; reference:cve,2016-6808; reference:cve,2017-17099; reference:url,technet.microsoft.com/en-us/security/bulletin/MS11-064; reference:url,www.exploit-db.com/exploits/42560/; classtype:attempted-user; sid:49838; rev:25;)"""
    demo3 = """alert tcp $HOME_NET 3306 -> $EXTERNAL_NET any (msg:"SCAN Potential MySQL Brute-Force attempt"; flow:from_server,established; content:"|FF 15 04|"; offset:4; depth:3; detection_filter:track by_dst, count 5, seconds 60; classtype:unsuccessful-user; sid:620010; rev:10;)"""
    demo4 = """alert ip $HOME_NET any -> 72.26.218.74 any (msg:"[Botnet] IP Reputation 511DD1"; metadata:update 20200116; classtype:trojan-activity; priority:4; reference:url,h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c04378450; reference:url,www2.hp.com; sid:630001; rev:1;)"""
    res1 = None
    res2 = dict()
    cnnvd_db = CVEDatabase(r'd:\work\cve.db')
    cnnvd_db.init_db()
    nvd_db = NVDDatabase(r'd:\work\data\nvd.txt')
    nvd_db.init_db()

    sid, pop, cves, rule_type, refs = select_cve_for_sid(demo4)
    # 有CVE的情况
    if sid and cves:
        for cve in cves:
            res1 = cnnvd_db.query(cve)
            if res1 is not None:
                break
        if res1 is None:
            print(f'[X] sid:{sid} can not get Correct Detail')
        else:
            doc = NewDocument(sid, pop=pop if pop is not None else 0)
            doc.rebuild(res1, res2)
            doc.save()
    elif sid and not cves:
        # if rule_type in ['botnet', 'malware', 'brute']:
        doc = NewDocument(sid, pop=pop if pop is not None else 0)
        doc.build_default(rule_type, ref=refs)
        doc.save()
    cnnvd_db.close()

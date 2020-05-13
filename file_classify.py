from nvdapi import NVDApi
from collections import defaultdict
from contextlib import suppress
import os
import re

RULE_FILES = {'1.0.x': {
    'Backdoor(trojan).rules': {"character": [r'classtype:trojan-activity'], 'class': '木马后门'},
    'DOS(DDOS).rules': {"character": [r'classtype:denial-of-service', r'classtype:attempted-dos', r'classtype:successful-dos'], 'class': '拒绝服务'},
    'Risk.rules': {"character": [r'classtype:unsuccessful-user', r'brute'], 'class': '潜在风险 包含暴力破解'},
    'Overflow.rules': {"CWE": ['CWE-119', 'CWE-122', 'CWE-121', 'CWE-120'], 'class': '缓冲区溢出'},
    'Sql.rules': {'character': [r'sql injection'], "CWE": ['89'], 'class': 'sql注入'},
    'Scan.rules': {'character': [r'classtype:attempted-recon'], 'class': '扫描刺探-固定骷髅文件'},
    'Rpc.rules': {"character": [r'cve,[\d]+\-[\d]+'], 'class': '漏洞攻击'},
    'Spy.rules': {'class': '间谍软件-先增加Botnet恶意域名'},
    'Virus(Worm).rules': {'class': '病毒-暂时空缺'},
    'white_list.rules': {},
    'black_list.rules': {},
    '0_day.rules': {},
    'file-identify.rules': {'character': [r'noalert']},
    'UserDefine.rules': {}
}
}


def classify(rule, nvdInstance, version='1.0.x'):
    for filename in RULE_FILES[version].keys():
        if 'character' in RULE_FILES[version][filename].keys():
            patterns = RULE_FILES[version][filename]['character']
            for pattern in patterns:
                if classifyByRegex(rule, pattern):
                    return filename
        if 'CWE' in RULE_FILES[version][filename].keys():
            cwes = RULE_FILES[version][filename]['CWE']
            if classifyByCWE(rule, cwes, nvdInstance):
                return filename
    return None


def classifyByRegex(rule: str, pattern: str) -> bool:
    r = re.search(pattern, rule, re.IGNORECASE)
    if r:
        return True
    return False


def classifyByCWE(rule, cwes: list, nvdinstance) -> bool:
    r = re.findall(r'cve,([\d]+\-[\d]+);', rule)
    if len(r) == 0:
        return False
    for cve in r:
        nvdinstance.search(f'CVE-{cve}')
        if nvdinstance.CWE is not None:
            for c in nvdinstance.CWE:
                if c in cwes:
                    return True
    return False


def saveToFile(filename, rule, filter=[r'SMTP_SERVERS', r'SIP_SERVERS', r'any any -> any any']):
    opMode = 'w'
    if os.path.isfile(filename):
        opMode = 'a'
    for pattern in filter:
        if re.search(pattern, rule):
            return False
    with open(filename, opMode) as fp:
        fp.write(rule)
    return True


if __name__ == "__main__":
    print("Init NVD Engine")
    nvd = NVDApi()
    nvd.load()
    d = defaultdict(int)
    print('Init rules file')
    for f in RULE_FILES['1.0.x'].keys():
        with suppress(FileNotFoundError):
            os.remove(f)
    print('Reading File')
    with open('1.0.2.209.txt') as fp:
        for line in fp:
            f = classify(line, nvd)
            if f is None:
                # print(line.strip('\n'))
                pass
            else:
                if saveToFile(f, line):
                    d[f] += 1

    print(d)

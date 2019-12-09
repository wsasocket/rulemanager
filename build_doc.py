import os
import sys
from getopt import getopt
from random import randint
from shutil import copy
from time import sleep

from cve_info import CVEInfo
from data_model import RuleSet
from documents import Document
from nessus import NessusInfo
from secfocus import SecFocusInfo
from trans import GoogleTranslate


def build_doc(doc_obj, spider, original_rule=None):
    cn = doc_obj.doc_CN
    en = doc_obj.doc_EN
    if isinstance(spider, SecFocusInfo):
        en['EN Affected Systems'] = spider.affect
        en['EN Summary'] = spider.summary
        en['EN Detailed Information'] = spider.detail
        en['EN Contributors'] = spider.credit
        en['EN Corrective Action'] = spider.solution
        en['EN Additional References'] = original_rule.ref

        cn['Affected Systems'] = spider.affect
        sleep(5 + randint(5, 15))
        cn['Summary'] = GoogleTranslate(spider.summary)
        sleep(5 + randint(6, 15))
        cn['Detailed Information'] = GoogleTranslate(spider.detail)
        sleep(5 + randint(7, 15))
        cn['Contributors'] = spider.credit
        sleep(5 + randint(8, 15))
        cn['Corrective Action'] = GoogleTranslate(spider.solution)
        sleep(5 + randint(9, 15))
        cn['Additional References'] = original_rule.ref

    if isinstance(spider, CVEInfo) and original_rule:
        en['EN Summary'] = original_rule.msg
        en['EN Detailed Information'] = spider.detail
        en['EN Additional References'] = original_rule.ref

        cn['Additional References'] = original_rule.ref
        cn['Summary'] = GoogleTranslate(original_rule.msg)
        cn['Detailed Information'] = GoogleTranslate(spider.detail)

    if isinstance(spider, NessusInfo) and original_rule:
        en['EN Corrective Action'] = spider.solution
        en['EN Summary'] = spider.summary
        en['EN Detailed Information'] = spider.detail
        en['EN Additional References'] = spider.addition

        cn['Corrective Action'] = GoogleTranslate(spider.solution)
        sleep(5 + randint(5, 15))
        cn['Summary'] = GoogleTranslate(spider.summary)
        sleep(5 + randint(5, 15))
        cn['Detailed Information'] = GoogleTranslate(spider.detail)
        sleep(5 + randint(5, 15))
        cn['Additional References'] = spider.addition
        sleep(5 + randint(5, 15))

    if not spider and original_rule:
        en['EN Summary'] = original_rule.msg
        sleep(5 + randint(5, 15))
        cn['Summary'] = GoogleTranslate(original_rule.msg)

        if original_rule.ref:
            en['EN Additional References'] = original_rule.ref
            sleep(5 + randint(5, 15))
            cn['Additional References'] = original_rule.ref

    doc_obj.save()


if __name__ == '__main__':
    filename = None
    save_path = './'
    opts, args = getopt(sys.argv[1:], "f:p:h", ["file=", "path=", "help"])
    if len(opts) == 0:
        opts = [('-h', '')]
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('build_doc -f xxx.rules [-p ./]')
            sys.exit(1)
        if opt in ('-f', '--file'):
            filename = arg
        if opt in ('-p', '--path'):
            save_path = arg

    if not os.path.isfile(filename):
        print('{} is NOT a File!'.format(filename))
        sys.exit(2)

    if not os.path.isdir(save_path):
        print('{} is NOT a Dir!'.format(filename))
        sys.exit(2)

    cves = dict()
    rs = RuleSet(filename)
    for r in rs:
        print('Sid:{}'.format(r.sid))
        doc = Document(r.sid, save_path)
        if not r.enable:
            continue
        if r.cve:
            print('\tSearch CVE : {}'.format(r.cve))
            if r.cve not in cves.keys():
                cves[r.cve] = r.sid
            else:
                copy('{:d}.txt'.format(cves[r.cve]), '{:d}.txt'.format(r.sid))
                print('sid:{} and sid:{} have same document'.format(cves[r.cve], r.sid))
                continue
            cve = CVEInfo(r.cve)
            _bid = cve.get_bid()
            if _bid:
                print('\tFind BugTraq id : {}  from CVE'.format(_bid))
                bid = SecFocusInfo(_bid)
                build_doc(doc, bid, r)
            else:
                build_doc(doc, cve, r)
        elif r.bid:
            print('\tSearch Bugtraq id : {}'.format(r.bid))
            bid = SecFocusInfo(r.bid)
            build_doc(doc, bid, r)
        elif r.nessus:
            print('\tSearch Nessus  id : {}'.format(r.nessus))
            nessus = NessusInfo(r.nessus)
            build_doc(doc, nessus, r)
        else:
            print('\tNo more info!')
            build_doc(doc, None, r)
        print(doc)
        doc.save()

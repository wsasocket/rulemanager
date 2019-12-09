import os
import re


class Document(object):
    DOC_CREATE = 0
    DOC_MODIFY = 1
    DOC_LOAD = 2
    DOC_SAVE = 3

    def __init__(self, sid, path='./'):
        self._sid = sid
        self._info_dict = {'Summary': '', 'Impact': '', 'Detailed Information': '',
                           'Attack Scenarios': '', 'Ease of Attack': '', 'False Positives': 'N/A',
                           'False Negatives': 'N/A', 'Corrective Action': '', 'Contributors': '',
                           'Additional References': '', 'Affected Systems': ''}
        self._info_dict_EN = {'EN Summary': '', 'EN Impact': '', 'EN Detailed Information': '',
                              'EN Attack Scenarios': '', 'EN Ease of Attack': '', 'EN False Positives': 'N/A',
                              'EN False Negatives': 'N/A', 'EN Corrective Action': '', 'EN Contributors': '',
                              'EN Additional References': '', 'EN Affected Systems': ''}
        self._status = -1
        self._doc_root = path

    def save(self):
        filename = os.path.join(self._doc_root, '{}.txt'.format(self._sid))
        with open(filename, 'w', encoding='gb18030') as fp:
            line = 'Rule:\n\n--\nSid:\n{}\n--\n'.format(self._sid)
            fp.write(line)
            for k in self._info_dict.keys():
                line = '{}\n{}\n--\n'.format(k, self._info_dict[k])
                fp.write(line)
            for k in self._info_dict_EN.keys():
                line = '{}\n{}\n--\n'.format(k, self._info_dict_EN[k])
                fp.write(line)
        self._status = Document.DOC_SAVE

    def __str__(self):
        line = 'Rule:\n\n--\nSid:\n{}\n--\n'.format(self._sid)
        for k in self._info_dict.keys():
            line += '{}\n{}\n--\n'.format(k, self._info_dict[k])
        for k in self._info_dict_EN.keys():
            line += '{}\n{}\n--\n'.format(k, self._info_dict_EN[k])
        return line

    @property
    def doc_CN(self):
        return self._info_dict

    @property
    def doc_EN(self):
        return self._info_dict_EN

    @property
    def sid(self):
        return self._sid

    @property
    def status(self):
        return self._status




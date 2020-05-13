# https://services.nvd.nist.gov/rest/json/cve/1.0/CVE-2020-0796
# use official API to get CVE more info
import requests
import json
from contextlib import suppress


class NVDApi(object):

    def __init__(self):
        self.url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/{CVE}'
        self.data = None
        self.localdata = list()
        self.save_to_file = None

    def load(self, file='nvd.json') -> int:
        if file is not None:
            # load data from file
            self.save_to_file = file
            with suppress(FileNotFoundError):
                with open(file) as fp:
                    for line in fp:
                        self.localdata.append(json.loads(line).copy())

    def search(self, cve):
        # search local db first
        for dbs in self.localdata:
            try:
                if dbs['result']['CVE_Items'][0]['cve']['CVE_data_meta']['ID'] == cve:
                    self.data = dbs
                    return 200
            except KeyError:
                print(dbs)
                exit(0)
        else:
            # search from nvd.nist.gov
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36',
                       'Content-Type': 'application/json;charset = utf-8'}
            r = requests.get(self.url.format(CVE=cve), headers=headers)
            if r.status_code == 200:
                self.data = r.json().copy()
            if self.data is not None and self.save_to_file is not None:
                with open(self.save_to_file, 'a') as fp:
                    fp.write('{}\n'.format(json.dumps(self.data)))
                    self.localdata.append(self.data.copy())
             # search result save into local file
            return r.status_code

    @property
    def CWE(self) -> list:
        if self.data is None:
            return None
        return_cwes = list()
        cwes = self.data["result"]["CVE_Items"][0]['cve']['problemtype']["problemtype_data"]
        for c in cwes:
            if "description" in c.keys():
                for i in c["description"]:
                    # print(i['value'])
                    return_cwes.append(i['value'])
        return return_cwes

    @property
    def CPE(self) -> list:
        if self.data is None:
            return None
        return_cpes = list()
        nodes = self.data["result"]["CVE_Items"][0]['configurations']['nodes']
        for cpes in nodes:
            if 'cpe_match' in cpes.keys():
                for cpe in cpes['cpe_match']:
                    if 'cpe23Uri' in cpe.keys():
                        return_cpes.append(cpe['cpe23Uri'])
        return return_cpes

    @property
    def Impact(self) -> str:
        # return severity
        if self.data is None:
            return None
        return self.data["result"]["CVE_Items"][0]['impact']['baseMetricV2']['severity']

    @property
    def Description(self) -> str:
        if self.data is None:
            return None
        return self.data["result"]["CVE_Items"][0]['cve']['description']["description_data"][0]['value']


if __name__ == "__main__":
    cves = list()
    nvd = NVDApi()
    nvd.load()
    # nvd.search('CVE-2020-0796')
    # print(nvd.CWE)
    # print(nvd.Description)
    # print(nvd.Impact)
    # print(nvd.CPE)
    for _, _, filenames in os.walk(r'd:\work\data\CNNVD_OK'):
        for i in filenames:
            cves.append(i[:-4])

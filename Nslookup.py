import asyncio
import re
import time
from nslookup import Nslookup
from io import StringIO

# https://realpython.com/async-io-python/#the-10000-foot-view-of-async-io
# domains = ["tlss.xiaoxinpro.xyz", 'baidu.com',
#            'tls.xiaoxinpro.xyz', 'jd.com', 'jetbrains.com']
# domains = ['vsdvzwt.mooo.com', 'vsdzee.dyndns.org', 'vsdvzwt.dyndns.org']


def loadDomains():
    domain_file = 'botnet-domains.rule'
    # _domains = list()
    with open(domain_file) as fp:
        for line in fp:
            r = re.search(r'->\s(.*?)\s', line)
            if r:
                yield(r.group(1))
    #             _domains.append(r.group(1))
    # return _domains


def skipFreeDomainServer(domain):
    freedomains = ['mooo.com', 'dynserv.com', 'yi.org', 'dyndns.org']
    for s in freedomains:
        if s in domain:
            return False
    return True


async def checkDomain(domain: str, buf: StringIO):

    # DNS servers default to cloudflare public DNS
    dns_query = Nslookup(dns_servers=["223.5.5.5", '8.8.8.8'])
    ips_record = dns_query.dns_lookup(domain)

    if len(ips_record.answer) > 0:
        # print(domain, True)
        buf.write(domain+'\n')

    # else:
    #     print(domain, False)
    # # print(ips_record.response_full, ips_record.answer)
    # soa_record = dns_query.soa_lookup(domain)
    # print(soa_record.response_full, soa_record.answer)


async def taskCheckDomain(domains: list, buf: StringIO):
    await asyncio.gather(*(checkDomain(d, buf) for d in domains))

if __name__ == "__main__":
    resultBuffer = StringIO()
    domains = loadDomains()
    domainList = list()
    start = time.perf_counter()
    count = 1
    for d in filter(skipFreeDomainServer, loadDomains()):
        # task = asyncio.create_task(checkDomain(d))
        domainList.append(d)
        if len(domainList) == 10:
            asyncio.run(taskCheckDomain(domainList, resultBuffer))
            domainList.clear()
            print(f"Task:{count} ~ {count+9}")
            count += 10
        # if count > 100:
        #     break

    with open('Botnet_ip.txt', 'w') as fp:
        resultBuffer.seek(0)
        r = resultBuffer.read()
        fp.write(r)
        resultBuffer.close()

    end = time.perf_counter() - start
    print(f"took {end:0.2f} seconds.")

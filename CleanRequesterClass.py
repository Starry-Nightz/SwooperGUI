import asyncio, threading, aiohttp, socket
from rich.progress import Progress
from ipaddress import ip_address as ip
from ipaddress import IPv4Address
from subprocess import run
import os
from pathlib import Path
from bs4 import BeautifulSoup as Bs

def floodfill(iprange:range,sections:int) -> list[range]:
    if(sections):
        count = iprange.stop - iprange.start
        minPerSection = count//sections
        extra = count - minPerSection*sections
        splitList = [(minPerSection+1) for i in range(extra)]
        splitList.extend([minPerSection]*(sections - extra))
        result = []

        last = iprange.start
        first = iprange.start

        for i in splitList:
            first += i 
            result.append(range(last,first))
            last += i
        return result
    else:
        return [iprange]

class StoppableThread(threading.Thread):
    """Thread class with a stop() method. The thread itself has to check
    regularly for the stopped() condition."""

    def __init__(self, group = None, target = None, name = None, args = ..., kwargs = None, *, daemon = None):
        super().__init__(group, target, name, args, kwargs, daemon=daemon)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

class Counter():
    def __init__(self,KnownTotal:int):
        self.knownTotal = KnownTotal
        self.known = 0
        self.unknown = 0
        self.none = 0
    def addKnown(self) -> None:
        self.known +=1
    def addUnknown(self) -> None:
        self.unknown +=1
    def addNone(self) -> None:
        self.none +=1
    def getTotalResolved(self) -> int:
        return self.known + self.unknown + self.none
    def getProgressNormalized(self) -> float:
        return (self.getTotalResolved() / self.knownTotal)

class IpBank():
    def __init__(self):
        self.ipDict = dict()

    def append(self,ipRange:range, ipOutList:list[str]) -> None:
        ipPlusOuts = [(key,value) for key, value in zip(ipRange,ipOutList) if value]
        self.ipDict.update(ipPlusOuts)
    def appendDict(self,ipDict:dict[str,str]) -> None:
        ipPlusOuts = [(key,value) for key, value in ipDict.items() if value]
        self.ipDict.update(ipPlusOuts)

    def get(self,ipAddress):
        return self.ipDict.get(int(ip(ipAddress)))
    def getIPDict(self):
        return self.ipDict
    def getIPsStr(self):
        ipNumtoStr = lambda x: str(ip(x))
        tmp = list(self.ipDict.keys())
        tmp.sort()
        return [ipNumtoStr(key) for key in tmp] 



class Scanner():
    def __init__(self, 
                startIp:str="127.0.0.1", 
                endIp:str=  "127.0.0.1", 
                threads:int=1,
                timeout:int=3,
                ipBank = IpBank()):
        self.ipRange = range(int(ip(startIp)),
                             int(ip(endIp)+1))
        #Inclusive
        self.threadsAlotted = threads
        self.timeout = timeout
        self.ipBank = ipBank
        self.counter = Counter(len(self.ipRange))
        self.spawnedThreads = []

    async def waitForCompletion(self):
        if len(self.spawnedThreads) == 0:
            return
        activeCount = 1
        while activeCount:
            #print(self.counter.getProgressNormalized()*100,end="\r")
            activeCount = sum([not thread.stopped() for thread in self.spawnedThreads])
            await asyncio.sleep(0)
    def threadsActive(self) -> int:
            return sum([not thread.stopped() for thread in self.spawnedThreads])

    async def runningOnThread(self,ipRange:range,ipBank:IpBank,counter:Counter,stopEvent:threading.Event = None, args:tuple=None) -> None:
        pass 

    async def threadHandler(self,stopEvent:threading.Event, runnerTask:asyncio.Task) -> None:
        while not stopEvent.is_set():
            await asyncio.sleep(0)
        runnerTask.cancel()

    def startAll(self):
        if len(self.spawnedThreads):
            return
        splitList =  floodfill(self.ipRange,self.threadsAlotted)
        for threadNum in range(self.threadsAlotted):
            _stop_event = threading.Event()

            runnerTask = asyncio.Task(self.runningOnThread(ipRange=splitList[threadNum], stopEvent=_stop_event))
            stopperTask = asyncio.Task(self.threadHandler(_stop_event,runnerTask))

            args = asyncio.Task(asyncio.wait([runnerTask, stopperTask], return_when=asyncio.FIRST_COMPLETED))

            thread = StoppableThread(group=None,
                                     target=asyncio.run,
                                     name=f"ScannerThread - {threadNum}",
                                     args=args,
                                     daemon=True
                                     )
            thread._stop_event = _stop_event
            thread.daemon = True
            self.spawnedThreads.append(thread)

    def stopAll(self):
        if len(self.spawnedThreads):
            [thread.stop() for thread in self.spawnedThreads]

##### SMB SCANNER STUFF ###

def dir_empty(dir_path:Path):
    try:
        return not next(os.scandir(dir_path.__str__()), None)
    except:
        return True

def getShares(ip:str) -> list[str]:
    winCMD = 'NET VIEW ' + '\\\\' + ip 
    netViewRaw = str(run(winCMD,capture_output=True).stdout).split("\\n")
    networkShares = []
    for line in netViewRaw:
        if "Disk" in line:
            networkShares.append(line.split("Disk")[0].rstrip())
    return [f"//{ip}/{shareName}" for shareName in networkShares]

def getValidPaths(shares:list[str]) -> list[Path]:
    validShares = []
    for share in shares:
        sharePath = Path(share)
        if not dir_empty(sharePath):
            validShares.append(sharePath)
    return validShares

def getInterestingFiles(paths:list[Path]) -> list[str]:
    files = []
    for path in paths:
        gen = path.rglob("*.xlxs")
        try:
            for item in gen:
                files.append(item)
                print(item)
        except:
            pass
    return files

def dumpSMBInfo(ips:list[str]):
    directories = []
    for ip in ips:
        t = getValidPaths(getShares(ip))
        directories.extend(t) 
        print(f"[{ip}] has been scanned")
    return directories

#### PORT SCANNER START ####

# async def scanPort(ipAd:str,port:int,counter:Counter,timeout) -> str:
#     try:
#         _reader, writer = await asyncio.wait_for(asyncio.open_connection(ipAd, port),timeout=timeout)
#         writer.close()
#         await writer.wait_closed()
#         counter.addKnown()
#         return f"Port Open : {port}"
#     except:
#         counter.addNone()
#         return None

async def scanPortTCP(ipAd:str,port:int,counter:Counter, timeout:float) -> str:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.setblocking(False)

    # 10056, GOOD
    # 10022, BAD

    s.connect_ex((ipAd,port))
    await asyncio.sleep(timeout)
    code = s.connect_ex((ipAd,port))
    s.close()
    del s
    match code:
        case 10056:
            counter.addKnown()
            return f"Port Open : {port}"
        case 0:
            counter.addKnown()
            return f"Port Open : {port}"
        case _:
            counter.addNone()
            return None

async def scanRangeTCP(ipRange:range,port:int,counter:Counter,timeout:float) -> list[str]:
    ipToStr = lambda x : str(ip(x))
    return await asyncio.gather(*[scanPortTCP(ipAd=ipToStr(x), port=port,counter=counter,timeout=timeout) for x in ipRange])
    

class SMBScanner(Scanner):
    def __init__(self, startIp: str = "127.0.0.1", endIp: str = "127.0.0.1", threads: int = 1, timeout: int = 3, ipBank=IpBank()):
        super().__init__(startIp, endIp, threads, timeout, ipBank)
        self.port = 445

    async def runningOnThread(self,ipRange:range,stopEvent:threading.Event = None) -> None:
        splitList = floodfill(ipRange, len(ipRange)//700)
        for rang in splitList:
            out = await scanRangeTCP(rang,self.port,counter=self.counter,timeout=self.timeout)
            self.ipBank.append(rang,out)
            #await asyncio.sleep(0)
        stopEvent.set()
        
#### IOT SCANNER START ####
        
async def scanRangeHTTP(ipRange:range,port:int,counter:Counter,timeout:float) -> list[str]:
    ipToStr = lambda x : str(ip(x))
    return await asyncio.gather(*[scanPortTCP(ipAd=ipToStr(x), port=port,counter=counter,timeout=timeout) for x in ipRange])
        
class SMBScanner(Scanner):
    def __init__(self, startIp: str = "127.0.0.1", endIp: str = "127.0.0.1", threads: int = 1, timeout: int = 3, ipBank=IpBank()):
        super().__init__(startIp, endIp, threads, timeout, ipBank)
        self.port = 445

    async def runningOnThread(self,ipRange:range,stopEvent:threading.Event = None) -> None:
        splitList = floodfill(ipRange, len(ipRange)//700)
        for rang in splitList:
            out = await scanRangeHTTP(rang,self.port,counter=self.counter,timeout=self.timeout)
            self.ipBank.append(rang,out)
        stopEvent.set()

####

async def waitWithProgressBar(scanObj:Scanner):
    with Progress(expand=True) as progress:
        progressTask = progress.add_task(f"[magenta]Running Scan of port {scanObj.port} ",total=1)
        while scanObj.threadsActive() > 0:
            progress.update(progressTask,completed=scanObj.counter.getProgressNormalized())
            await asyncio.sleep(0.2)

####



####

async def main():
    scan = SMBScanner(   
                            threads=12,
                            startIp=str(ip("10.30.0.0")),
                            endIp=str(ip("10.30.255.255")),
                            timeout=4.5
                            )
    scan.startAll()
    await waitWithProgressBar(scan)
    # #await scan.waitForCompletion()
    tmp = scan.ipBank.getIPDict()
    print(f"Found {len(tmp)} items")

    for key, value in tmp.items():
        print(f"{str(ip(key))} : {value}")

    print(f"{len(tmp)} addresses have been found")
    print("Now searching for Shares")

    #[print(x) for x in dumpSMBInfo(scan.ipBank.getIPsStr())]

if __name__ == "__main__":
    asyncio.run(main())
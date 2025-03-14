import os, pathlib
from csv import reader, writer

from ipaddress import ip_address as ip_addr

def ipSortFunc(listIn:list[list[str]]):
    ipToInt = lambda x : int(ip_addr(x))
    out = {ipAddr:stuff for ipAddr, stuff in listIn}
    out = [[ipAddr,out[ipAddr]] for ipAddr in sorted(out.keys(),key=ipToInt)]
    return out

def chunks(lst,sections:int) -> list[list]:
    '''returns N amount of sections'''
    n = int(len(lst)/sections + 0.5) 
    return [lst[i:i + n] for i in range(0, len(lst), n)]

def chunksPer(lst,n:int) -> list:
    '''returns sections of N amount'''
    return [lst[i:i + n] for i in range(0, len(lst), n)]

class FileManagerNEW():
    def __init__(self,filepath:str=None) -> None:
        AppFolder = pathlib.Path(os.path.dirname(__file__))
        self.LogsFolder = AppFolder.joinpath("Logs\\")
        self.filterText = ""
        self.filePath = filepath
        if not self.LogsFolder.is_dir():
            self.LogsFolder.mkdir()
        if filepath is not None:
            self.switchReqContext(filepath)
    
    def switchReqContext(self,currContext:str):
        self.filePath = self.LogsFolder.joinpath(fr"{currContext}")
        #print(self.filePath)
        if not self.filePath.is_file():
            self.makeNewFile()
        self.lines = 0
    
    def makeNewFile(self) -> None:
            assert self.filePath is not None
            with open(self.filePath, "w",newline='') as file:
               pass
    
    def dump(self, ipDict:dict[str, str]) -> None:
        assert self.filePath is not None
        loadedDict = self.load()
        loadedDict.update(ipDict)
        sortedKeys = sorted(loadedDict.keys(), key=lambda x : int(ip_addr(x)))
        loadedDict = {ipAddr : loadedDict[ipAddr] for ipAddr in sortedKeys}

        with open(self.filePath, "w",newline='') as file:
            csvWriter = writer(file)
            csvWriter.writerows([[ipAddr,responce] for ipAddr,responce in loadedDict.items()])
        self.lines = len(loadedDict)

    def load(self) -> dict:
        assert self.filePath is not None
        with open(self.filePath, "r") as file:
            csvReader = reader(file)
            out = {ipAddr : responce for ipAddr,responce in csvReader}
        self.lines = len(out)
        return out
    
    def getPagesWithFilterRows(self, pageSize:int=None) -> list[dict]:

        ipDict = self.load()
        rows = [(ipAddr, responce) for ipAddr,responce in ipDict.items()]
        filterText = self.filterText
        if filterText != None and filterText.lstrip() != "":
            rows = [(ipAddr, responce) for ipAddr,responce in rows if responce.find(filterText)]

        if pageSize > 0:
            return chunksPer(rows,pageSize)    
    
        return [rows,]
    def getPageCount(self,pageSize:int=9999):
        assert pageSize > 0
        e, a = divmod(self.lines,pageSize)
        return e + (a>0)

    def setFilter(self,filterText:str) -> None:
        filterText = filterText.rstrip().lstrip()
        self.filterText = filterText
        
    
if __name__ == "__main__":
    fm = FileManagerNEW("Test.csv")
    fm.dump({str(ip_addr(x)) : x for x in range(1000,2000)})
    e = fm.getPagesWithFilterRows(pageSize=256)
    [print(x) for x in e]
    #fm.dump(None)
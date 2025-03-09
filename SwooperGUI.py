from textual import on
from textual.app import App, ComposeResult
from textual.events import Mount
from textual.widgets import *
from textual.binding import Binding
from textual.box_model import *
from textual.containers import Horizontal,Vertical
import math, csv, os, time, threading, requests, ipaddress, asyncio, aiohttp
from bs4 import BeautifulSoup
import pyperclip 

intToIp = lambda x : str(ipaddress.ip_address(x))
ipToInt = lambda x : int(ipaddress.ip_address(x))

def ipSortFunc(listIn):
    out = []
    keepList = list(set(list(str(ipaddress.ip_address(item[0])) for item in listIn)))
    key = lambda item: ipaddress.ip_address(item[0])
    for row in listIn:
        if keepList.count(row[0]) > 0:
            out.append(row)
            keepList.remove(row[0])

    out.sort(key=key)
    return out

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

    def __init__(self,  *args, **kwargs):
        super(StoppableThread, self).__init__(*args, **kwargs)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

class Counter():
    def __init__(self,givenThreads) -> None:
        self.taskCounter = [0]*givenThreads
        self.unknownCount = 0
        self.knownCount = 0
        self.noneCount = 0

def getTitle(counter,html,index):
    counter.taskCounter[index] += 1
    parsed_html = BeautifulSoup(html, features="html.parser")
    if(parsed_html == None):
        counter.unknownCount += 1
        return "Unknown"
    else:
        try:
            testVar = parsed_html.find_all('title')[0]
            if( testVar!= None ):
                counter.knownCount += 1
                return testVar.get_text()
        except:
            counter.unknownCount += 1
            return "Unknown"

async def query(session:aiohttp.ClientSession, ip,index,counter:Counter):
    try:
        async with session.get("http://"+str(ipaddress.ip_address(ip))+'/') as responce:
            #if responce.status != 200:
            #    return "None"
            #print(responce.text())
            html = await responce.text()
            return getTitle(counter,html,index)
    except:
        counter.noneCount+=1
        return "None"

async def query_segmented(session:aiohttp.ClientSession, ipRange,index,counter:Counter,timeOut):
    tasks = []
    for ipNUM in ipRange:
        ip = str(ipaddress.ip_address(ipNUM))
        task = asyncio.create_task(query(session,ip,index,counter))
        tasks.append(task)
        await asyncio.sleep(0)
        #if ipNUM%100 == 0:
        #    await asyncio.sleep(timeOut)
    return await asyncio.gather(*tasks)

async def query_all(session:aiohttp.ClientSession, ipRange,index,counter:Counter):
    tasks = []
    for ipNUM in ipRange:
        ip = str(ipaddress.ip_address(ipNUM))
        task = asyncio.create_task(query(session,ip,index,counter))
        tasks.append(task)
    return await asyncio.gather(*tasks)

async def check_port(host, port:int, counter:Counter, timeout=1) -> str:
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        counter.knownCount+=1
        return f"Port Responded : {port}"
    except:
        counter.noneCount+=1
        return "None"
    
async def check_port_range(hosts:range, port:int, counter:Counter, timeout=1) -> list[str]:
    return await asyncio.gather(*[check_port(intToIp(ip),port,counter,timeout) for ip in hosts])

class Requester():
    def __init__(self, startIp:str="127.0.0.1", endIp:str="127.0.0.1", givenThreads:int=1,debug:RichLog = None,timeout:float = 3.0) -> None:
        self.running = False
        self.threadList = []
        self.givenThreads = givenThreads
        self.startIp = int(ipaddress.ip_address(startIp))
        self.endIp = int(ipaddress.ip_address(endIp))+1
        self.debug= debug
        self.timeOut = timeout

        self.taskCounter = Counter(givenThreads)
        self.rangeList = []
        self.resultList = [[]]*self.givenThreads

        self.splitList = [(self.endIp-self.startIp)//givenThreads]*givenThreads

        self.counter = Counter(self.givenThreads)

        for i in range(0,(self.endIp-self.startIp)%givenThreads):
            self.splitList[i] += 1
        temp = self.startIp

        for i in range(len(self.splitList)):
            before = temp
            temp += self.splitList[i]
            after = temp
            self.rangeList.append(range(before,after))

        for i in range(givenThreads):
            self.resultList[i] = [""]*self.splitList[i]
    
    async def waitForFinish(self):
        while len(self.threadList) > 0:
            #self.debug.write(self.running)
            #print(self.counter.taskCounter)
            for thread in self.threadList:
                #thread = StoppableThread
                if(not thread.is_alive()):
                    self.threadList.remove(thread)
            await asyncio.sleep(0.1)
        self.running = False
        #print(self.resultList)

    def stop(self):
        for thread in self.threadList:
            thread.stop()

class smbRequester(Requester):
    def timeFunction(self):
        return (self.timeOut*((self.endIp - self.startIp)/978))/self.givenThreads 
    
    async def getSMBStatus(self, ipRange:range,index) -> str:
        sections = floodfill(ipRange,(len(ipRange)//512))
        out = []
        for rang in sections:
            out.extend(await check_port_range(rang,445,counter=self.counter,timeout=self.timeOut))
            await asyncio.sleep(0)
        self.resultList[index] = out
    def start(self):
        for threadNUM in range(len(self.splitList)):
            x = StoppableThread(target=asyncio.run, 
                                args=tuple([self.getSMBStatus(self.rangeList[threadNUM],threadNUM)]),
                                name="IPTHREAD-"+str(threadNUM))
            self.threadList.append(x)
            self.threadList[threadNUM].daemon = True
            self.threadList[threadNUM].start()
        print(self.threadList)
        self.running = True
        asyncio.get_running_loop().create_task(self.waitForFinish())

class rtspRequester(Requester):
    def timeFunction(self):
        return (self.timeOut*((self.endIp - self.startIp)/978))/self.givenThreads 
    
    async def getRTSPStatus(self, ipRange:range,index) -> str:
        sections = floodfill(ipRange,(len(ipRange)//512))
        out = []
        for rang in sections:
            out.extend(await check_port_range(rang,554,counter=self.counter,timeout=self.timeOut))
        self.resultList[index] = out
    def start(self):
        for threadNUM in range(len(self.splitList)):
            x = StoppableThread(target=asyncio.run, 
                                args=tuple([self.getRTSPStatus(self.rangeList[threadNUM],threadNUM)]),
                                name="IPTHREAD-"+str(threadNUM))
            self.threadList.append(x)
            self.threadList[threadNUM].daemon = True
            self.threadList[threadNUM].start()
        print(self.threadList)
        self.running = True
        asyncio.get_running_loop().create_task(self.waitForFinish())

class printerRequester(Requester):
    def timeFunction(self):
        return (self.timeOut*((self.endIp - self.startIp)/978))/self.givenThreads 
    
    async def getPrinterStatus(self, ipRange:range,index) -> str:
        sections = floodfill(ipRange,(len(ipRange)//512))
        out = []
        for rang in sections:
            out.extend(await check_port_range(rang,9100,counter=self.counter,timeout=self.timeOut))
        self.resultList[index] = out
    def start(self):
        for threadNUM in range(len(self.splitList)):
            x = StoppableThread(target=asyncio.run, 
                                args=tuple([self.getPrinterStatus(self.rangeList[threadNUM],threadNUM)]),
                                name="IPTHREAD-"+str(threadNUM))
            self.threadList.append(x)
            self.threadList[threadNUM].daemon = True
            self.threadList[threadNUM].start()
        print(self.threadList)
        self.running = True
        asyncio.get_running_loop().create_task(self.waitForFinish())


class webRequesterV5(Requester):
    def timeFunction(self):
        return (self.timeOut * (self.endIp - self.startIp)/100)/self.givenThreads + 3
    
    async def getWebStatus(self, ipRange:range,index) -> str:
        timeout = aiohttp.ClientTimeout(3)
        #timeout = aiohttp.ClientTimeout(self.timeFunction())
        conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=conn,timeout=timeout,) as session:
            a = await query_segmented(session, ipRange,index,self.counter,self.timeOut)
            print(a)
            self.resultList[index] = a
    def start(self):
        for threadNUM in range(len(self.splitList)):
            x = StoppableThread(target=asyncio.run, 
                                args=tuple([self.getWebStatus(self.rangeList[threadNUM],threadNUM)]),
                                name="IPTHREAD-"+str(threadNUM))
            self.threadList.append(x)
            self.threadList[threadNUM].daemon = True
            self.threadList[threadNUM].start()
        print(self.threadList)
        self.running = True
        asyncio.get_running_loop().create_task(self.waitForFinish())

class webRequesterV4(Requester):
    def timeFunction(self):
        return math.log2(self.endIp - self.startIp) + self.timeOut
    
    async def getWebStatus(self, ipRange:range,index) -> str:
        timeout = aiohttp.ClientTimeout(self.timeFunction())
        conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=conn,timeout=timeout,) as session:
            self.resultList[index] = await query_all(session, ipRange,index,self.counter)
    def start(self):
        for threadNUM in range(len(self.splitList)):
            x = StoppableThread(target=asyncio.run, 
                                args=tuple([self.getWebStatus(self.rangeList[threadNUM],threadNUM)]),
                                name="IPTHREAD-"+str(threadNUM))
            self.threadList.append(x)
            self.threadList[threadNUM].daemon = True
            self.threadList[threadNUM].start()
        print(self.threadList)
        self.running = True
        asyncio.get_running_loop().create_task(self.waitForFinish())
  
class webRequesterV3(Requester):
    def timeFunction(self):
        return ((self.endIp - self.startIp)*self.timeOut)/self.givenThreads
    def getWebStatus(self,ipRange:range,index:int) -> str:
            start = ipRange.start
            for ip in ipRange:
                url = "http://"+str(ipaddress.ip_address(ip))+'/'
                try:
                    r = requests.get(url,timeout=self.timeOut)
                    self.resultList[index][ip - start] = getTitle(self.counter,r.text,index)
                except:
                    self.resultList[index][ip - start] = "None"
                    self.counter.noneCount += 1 

    def start(self):
        for threadNUM in range(self.givenThreads):
            x = StoppableThread(target=self.getWebStatus, 
                                args=tuple([self.rangeList[threadNUM],threadNUM]),
                                name="IPTHREAD-"+str(threadNUM))
            self.threadList.append(x)
            self.threadList[threadNUM].daemon = True
            self.threadList[threadNUM].start()
        self.running = True
        asyncio.get_running_loop().create_task(self.waitForFinish())



class FileManager():
    
    def __init__(self, filepath) -> None:
        self.filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)),filepath)
        self.lines = 0
        if not os.path.exists(self.filepath):
            with open(self.filepath, "w") as file:
                self.lines = 1
        self.filterText = ""
        self.getRowCount()

    def getRowCount(self):
        nameFilter = self.filterText.lower()
        with open(self.filepath,"r") as file:
            reader = csv.reader(file)
            if nameFilter.lower().rstrip() == "":
                self.lines = sum(1 for row in reader)
            else:
                self.lines = sum((1 if row[1].lower().find(nameFilter) != -1 else 0) for row in reader)
                
    def loadData(self,rowsPer,page):
        nameFilter = self.filterText
        if page > self.queryPageCount(rowsPer):
            page = 0
        with open(self.filepath,"r") as file:
            rows = []
            reader = csv.reader(file)

            nameFilter = nameFilter.lower()
            start = rowsPer*page
            end = rowsPer*(page+1)

            if nameFilter == "":
                for i in range(start):
                    try:
                        next(reader)
                    except StopIteration:
                        start = i-1
                i = 0

                while (i < end or i < start):
                    try:
                        row = next(reader)
                    except StopIteration:
                        break
                    i+= 1
                    rows.append(row)
            else:
                i = 0
                k = 0
                while (i < end and k < rowsPer):
                    try:
                        row = next(reader)
                    except StopIteration:
                        break
                    if(row[1].lower().find(nameFilter) != -1):
                        if(i >= start):
                            k+= 1
                            rows.append(row)
                        i+= 1

        return rows

    def queryPageCount(self,rowsPer):
        self.getRowCount()
        return int(math.ceil((self.lines/rowsPer))) + (1 if self.lines == 0 else 0)  
    def saveData(self,resultList,startIp):
        i = 0
        old = []
        new = []
        with open(self.filepath,"r",newline="") as file:
            reader = csv.reader(file)
            for row in reader:
                old.append(row)
        with open(self.filepath,"w",newline="") as file:
            writer = csv.writer(file)
            for rList in resultList:
                for val in rList:
                    ipAd = str(ipaddress.ip_address(startIp+i))
                    if(val == "None"):
                        pass
                    else:
                        new.append([ipAd,val])
                    i += 1
            old.extend(new)
            writer.writerows(ipSortFunc(old))

class ControlPanel(Static):

    def compose(self) -> ComposeResult:
        veryifyReg = "^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"
        ipReg = "[\d.]{0,15}"

        yield Horizontal(
            Input("127.0.0.1","127.0.0.0",id="startRange",restrict=ipReg,validate_on=["submitted"]),
            Input("127.0.0.255","127.0.0.255",id="endRange",restrict=ipReg,validate_on=["submitted"]),
            ProgressBar(total=1.0,show_bar=True,id="progressBar",show_eta=False),
            Select.from_values([1,2,],allow_blank=False,id="methodSelector"),
            id="inputPanel"
        )
        yield Horizontal(
            Button("Start",id="startButton"),
            Button("Stop",id="stopButton",variant="error"),
            Input("8","8",id="threadCount",type="number",restrict=ipReg),
            ProgressBar(total=1.0,show_bar=True,id="timeLeft"),
            Input("3","3",id="timeOut",type="number",restrict="[\d]{0,2}"),
            Button("Clear Console",id="clearButton"),
            )
        yield RichLog(id="consoleLog",highlight=True, markup=True)

    def on_mount(self,event:Mount) -> None:
        global theFilemanager
        self.fileManager = theFilemanager
        self.req = None
        self.consoleLog = self.query_one(RichLog)
        self.startRange, self.endRange = ["127.0.0.0","127.0.0.255"]
        selector = self.query_one(Select)
        selections = []
        requesterTypes = Requester.__subclasses__()
        for i in range(len(requesterTypes)):
            selections.append([requesterTypes[i].__name__,i])
        selector.set_options(tuple(selections))
        ##
        log = self.query_one(RichLog)
        log.border_title = "Console Log : "
        ##
        startRangeInput = self.query_one("#startRange")
        startRangeInput.border_title = "Start IP"
        ##
        endRangeInput = self.query_one("#endRange")
        endRangeInput.border_title = "End IP"
        ##
        methodSelector = self.query_one("#methodSelector")
        methodSelector.border_title = "Scan Method"
        ##
        methodSelector = self.query_one("#threadCount")
        methodSelector.border_title = "Threads"
        ##
        methodSelector = self.query_one("#timeOut")
        methodSelector.border_title = "Timeout"
        ##
        self.progress_timer = self.set_interval(1 / 2, self.make_progress, pause=True)
        ##

    def make_progress(self) -> None:
        #self.req = webRequesterV4()
        progressBar = self.query_one("#progressBar")
        timeLeft = self.query_one("#timeLeft")
        progressBar.update(total=(self.req.endIp - self.req.startIp), 
                           progress=sum(self.req.counter.taskCounter))
        timeLeft.advance(0.5)
        #self.consoleLog.write(self.req.running)
        if(self.req.running == False):
            self.query_one("#startButton").display = True
            self.query_one("#stopButton").display = False
            self.progress_timer.reset()
            self.progress_timer.pause()
            progress = self.query_one("#progressBar")
            progress.update(progress=0)
            timeLeft = self.query_one("#timeLeft")
            timeLeft.update(progress=0)
            self.consoleLog.write("[bold #00FF00]SCAN COMPLETE, dumping IPs to: [IPlog.csv]")
            self.consoleLog.write("[bold #00FF00]Process took {0} seconds".format(time.time() - self.timeStart ))
            
            
            self.fileManager.saveData(self.req.resultList,self.req.startIp)
            self.consoleLog.write("")
            self.consoleLog.write("[bold #00FF00]# Known :{0}".format(self.req.counter.knownCount))
            self.consoleLog.write("[bold #555555]# Unknown :{0}".format(self.req.counter.unknownCount))
            self.consoleLog.write("[bold #AA0000]# None :{0}".format(self.req.counter.noneCount))
            

    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.timeStart = time.time()
        if event.button.id == "startButton":
            method = self.query_one(Select).value
            reqMethods = Requester.__subclasses__()
            chosen = reqMethods[method]
            threadCount = int(self.query_one("#threadCount").value)
            self.startRange = self.query_one("#startRange").value
            self.endRange = self.query_one("#endRange").value
            self.timeOut = int(self.query_one("#timeOut").value)
            testStatement = False
            try:
                a = int(ipaddress.ip_address(self.startRange))
                b = int(ipaddress.ip_address(self.endRange))
                testStatement = True
            except ValueError:
                self.consoleLog.write("[bold #FF0022]ERROR: Invalid IP addresses, Please check your values.")
            if(testStatement):
                if(a >= b):
                    self.consoleLog.write("[bold #FF0022]ERROR: Start Address is >= End Address.")
                    testStatement = False
                #elif(threadCount > os.cpu_count()):
                #    self.consoleLog.write("[bold #FF0022]ERROR: More threads than logistic CPU count, max is {1}".format(os.cpu_count()))
                #    testStatement = False
                elif(b-a < threadCount):
                    self.consoleLog.write("[bold #FF0022]ERROR: More Threads than IPs, please lower thread count.")
                    testStatement = False
                
                
            if(testStatement):
                #self.consoleLog.clear()

                self.consoleLog.write("> [bold blue]{0}[/bold blue] was selected".format(str(chosen.__name__)))
                event.button.display = False
                self.query_one("#stopButton").display = True
                self.consoleLog.write("> ipRange Set : [ {0} , {1} ] - {2} Ips Being Scanned".format(self.startRange,self.endRange,b-a))
                self.req = chosen(self.startRange,self.endRange,threadCount,self.consoleLog,self.timeOut)
                self.consoleLog.write("> given threads : [ {0} ]".format(self.req.givenThreads))
                self.consoleLog.write("> max threads : [ {0} ]".format(str(os.cpu_count())))
                for i in range(len(self.req.rangeList)):
                    time.sleep(0.1)
                    p = self.req.rangeList[i]
                    self.consoleLog.write("[bold #ff00ff]IPTHREAD-{0}[/bold #ff00ff] : {1} -> {2}".format(i,
                                                                                str(ipaddress.ip_address(p.start)),
                                                                                str(ipaddress.ip_address(p.stop-1))))
                self.consoleLog.write("[bold #00FF00]Starting Threads...[/bold #00FF00]".format(str(chosen.__name__)))
                self.req.start()
                timeLeft = self.query_one("#timeLeft")
                timeLeft.update(total=self.req.timeFunction())
                self.progress_timer.resume()
        elif(event.button.id == "clearButton"):
            self.consoleLog.clear()

        else:
            self.progress_timer.reset()
            self.progress_timer.pause()
            progress = self.query_one("#progressBar")
            progress.update(progress=0)
            timeLeft = self.query_one("#timeLeft")
            timeLeft.update(progress=0)
            self.consoleLog.write("[bold #ffc800]INFO: STOPPING SCAN, This may take a minute.")
            self.req.stop()
            

            event.button.display = False
            self.query_one("#startButton").display = True
        
class Dataview(Static):
    
    def compose(self) -> ComposeResult:
        with Horizontal():
            with RadioSet(id="count"):
                yield RadioButton("64",True)
                yield RadioButton("128")
                yield RadioButton("256")
            yield Select.from_values([1],prompt="",allow_blank=False,id="pageSelector")
            yield Input("",id="filter",placeholder="Filter Title")
            yield Button("Refresh",id="refresh")
        yield Vertical(DataTable(),id="verticaldata")
        yield Footer()
    
        
    def update_content(self) -> None:
            table = self.query_one(DataTable)
            table.clear()
            rows = self.fileManager.loadData(self.rowsPer,self.currentPage)
            table.add_rows(rows)

    def update_menu(self) -> None:
            self.pageCount = self.fileManager.queryPageCount(self.rowsPer)
            if self.fileManager.filterText != "":
                #TextArea.action_cursor_line_end()
                pass

            if(self.pageCount > self.currentPage):
                self.currentPage = 0
            selector = self.query_one(Select)
            selections = []
            for i in range(self.pageCount):
                selections.append([str(i+1),i])
            selector.set_options(tuple(selections))
    
    @on(Select.Changed)
    def select_changed(self, event: Select.Changed) -> None:
        self.currentPage = event.value
        self.update_content()

    @on(Input.Submitted)
    def getFilterPrompt(self, event: Input.Submitted) -> None:
            self.fileManager.filterText = event.value.lower().rstrip()
            self.update_menu()
            self.update_content()

        
    def _on_mount(self, event: Mount) -> None:
        global theFilemanager
        self.fileManager = theFilemanager
        self.rowsPer = 64
        self.currentPage = 0
    
        selector = self.query_one(Select)

        self.pageCount = self.fileManager.queryPageCount(self.rowsPer)
        selections = []
        for i in range(self.pageCount):
            selections.append([str(i+1),i])
        selector.set_options(tuple(selections))
        

        table = self.query_one(DataTable)
        table.clear()
        table.add_columns("IP","Title")
        rows = self.fileManager.loadData(self.rowsPer,0)
        table.add_rows(rows)

        table.cursor_type = "row"

        
        self.query_one(Footer).styles.link_color = "#FF00FF"


    def on_button_pressed(self, event: Button.Pressed) -> None:
        if(event.button.id == "refresh"):
            self.update_content()
            self.update_menu()
    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        self.rowsPer = int(event.pressed.label.plain)
        self.update_content()
        self.update_menu()

class SwooperApp(App):
    BINDINGS = [
        Binding("c", "copy", "Copy to Clipboard",show=True)
    ]
    CSS = """
        Screen {
            height: 99%;
            align: center middle;
        }
        #inputPanel{
            height: 4;
        }
        Tab{
            scrollbar-color: #59114e;
        }
        #threadCount{
            width:15;
            offset: 0 0;
            border-top: heavy #888888
        }
        #timeOut{
            dock: right;
            width: 14;
            offset: -19 0;
            border-top: heavy #888888
        }
        #clearButton{
            margin: 0 1 0 1;
            dock: right;
            offset: 0 0
        }
        #startRange {
            width: 22;
            border-top: heavy #888888;
        }
        #progressBar{
            offset: 5% 51%;
        }
        Footer{
            background: rgb(25,0,25);
            color: #888888;
        }

        #timeLeft{
            offset: 5% 51%;
        }
        #consoleLog{
            background: rgb(25,0,25);
            margin: 0 1 0 1;
            border-top: heavy white;
            overflow: hidden auto;
            offset: 0 -1;
        }
        #endRange{
            width: 22;
            border-top: heavy #888888;
        }
        #refresh {
            dock: right;
            margin: 1 0 1 0 
        }
        #startButton{
            margin: 1;
            offset: 0 -1;
        }
        #stopButton{
            margin: 1;
            offset: 0 -1;
            display: none;
        }
        #filter{
            width: 40;
        }
        #pageSelector {
            width: 10;
        }
        #methodSelector {
            dock: right;
            width:24;
            border-top: heavy #888888;
        }
        Horizontal{
            align: left top;
            height: auto;
        }
        ContentSwitcher{
            height: 90%;
        }
        DataTable {
            height: 100%;
            margin: 1
        }
    """

    def compose(self) -> ComposeResult:
        yield Tabs(
            Tab("Controls", id="control"),
            Tab("Dataviewing", id="data")
        )
        with ContentSwitcher(initial="control"):  
            yield ControlPanel(id="control")
            yield Dataview(id="data")

    def action_copy(self) -> None:
        if self.query_one(ContentSwitcher).current == "data":
            table = self.query_one(Dataview).query_one(DataTable)
            e = table.get_row_at(table.cursor_coordinate[0])[0]
            pyperclip.copy(e)
        


    def on_mount(self) -> None:
        """Focus the tabs when the app starts."""
        self.query_one(Tabs).focus()

    def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
        """Handle TabActivated message sent by Tabs."""
        self.query_one(ContentSwitcher).current = event.tab.id


async def deBug():
    req = smbRequester("10.254.255.255","10.254.255.255",givenThreads=2,timeout=3)
    req.start()
    while req.running:
        print([req.threadList,req.counter.taskCounter])
        await asyncio.sleep(0.1)
    print(req.counter.knownCount)
    await asyncio.sleep(10)

if __name__ == "__main__":
    theFilemanager = FileManager("ipLog.csv")
    app = SwooperApp()
    app.run()
    #asyncio.run(deBug())
    
from textual import on
from textual.app import App, ComposeResult
from textual.events import Mount
from textual.widgets import *
from textual.binding import Binding
from textual.validation import Validator, ValidationResult
from textual.box_model import *
from textual.containers import Horizontal, Vertical
import os, time, ipaddress, pyperclip

from FileManager import FileManagerNEW
from CleanRequesterClass import Scanner, SMBScanner

intToIp = lambda x : str(ipaddress.ip_address(x))
ipToInt = lambda x : int(ipaddress.ip_address(x))

# WHAT THE FUCK WAS I ON WHEN I WROTE THIS :C
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

# possibly not keterrifying???
def ipSortFunc(listIn:list[list[str]]):
    ipToInt = lambda x : int(ipaddress.ip_address(x))
    out = {ipAddr:stuff for ipAddr, stuff in listIn}
    out = [[ipAddr,out[ipAddr]] for ipAddr in sorted(out.keys(),key=ipToInt)]
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

####

class isFloat(Validator):  
    def validate(self, value: str) -> ValidationResult:
        """Check a string is equal to its reverse."""
        if self.checkFloat(value):
            return self.success()
        else:
            return self.failure()
    def checkFloat(self,textfloatVal:str):
        try:
            e = float(textfloatVal)
            assert e >= 0
            return True
        except ValueError:
            return False
        except AssertionError:
            return False

class ControlPanel(Static):

    def compose(self) -> ComposeResult:
        #veryifyReg = "^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"
        ipReg = "[\d.]{0,15}"

        yield Horizontal(
            Input("127.0.0.1","127.0.0.0",id="startRange",restrict=ipReg,validate_on=["submitted"]),
            Input("127.0.0.255","127.0.0.255",id="endRange",restrict=ipReg,validate_on=["submitted"]),
            Select.from_values([1,2,],allow_blank=False,id="methodSelector"),
            id="inputPanel"
        )
        yield Horizontal(
            Button("Start",id="startButton"),
            Button("Stop",id="stopButton",variant="error"),
            Input("8","8",id="threadCount",type="number",restrict=ipReg),

            ProgressBar(total=1.0,show_bar=True,id="timeLeft",show_eta=True),

            Input("3.5","3.5",id="timeOut",type="number",validators=[isFloat()]),
            Button("Clear Console",id="clearButton"),
            )
        yield RichLog(id="consoleLog",highlight=True, markup=True)

    def on_mount(self,event:Mount) -> None:
        global theFilemanager
        self.fileManager = theFilemanager
        self.req = None
        self.consoleLog = self.query_one(RichLog)
        self.startRange, self.endRange = ("127.0.0.0","127.0.0.255")
        selector = self.query_one(Select)
        
        scannerTypes = Scanner.__subclasses__()
        selections = tuple((sub.__name__, i)for i, sub in enumerate(scannerTypes))
        selector.set_options(selections)

        self.fileManager.switchReqContext(scannerTypes[0].__name__+"LOG.csv")
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
        self.progress_timer = self.set_interval(1 / 8, self.make_progress, pause=True)
        ##

    def make_progress(self) -> None:
        timeLeft = self.query_one("#timeLeft")
        timeLeft.update(progress=self.req.counter.getProgressNormalized())

        #self.consoleLog.write(f"{self.req.threadsActive()}")

        if self.req.threadsActive() > 0:
            return

        self.query_one("#startButton").display = True
        self.query_one("#stopButton").display = False
        self.progress_timer.reset()
        self.progress_timer.pause()
        timeLeft.update(progress=0)
        self.consoleLog.write(f"[bold #00FF00]SCAN COMPLETE, dumping IPs to: [{self.fileManager.filePath}]")
        self.consoleLog.write(f"[bold #00FF00]Process took {time.time() - self.timeStart} seconds")
        
        
        self.fileManager.dump({intToIp(ip): responce for ip,responce in self.req.ipBank.getIPDict().items()})
        self.consoleLog.write("")
        self.consoleLog.write("[bold #00FF00]# Known :{0}".format(self.req.counter.known))
        self.consoleLog.write("[bold #555555]# Unknown :{0}".format(self.req.counter.unknown))
        self.consoleLog.write("[bold #AA0000]# None :{0}".format(self.req.counter.none))
            

    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        #self.fileManager = FileManagerNEW()
        self.timeStart = time.time()
        if event.button.id == "startButton":
            methodIndex = int(self.query_one(Select).value)
            reqMethods = Scanner.__subclasses__()

            chosen = reqMethods[methodIndex]

            self.fileManager.switchReqContext(chosen.__name__+"LOG.csv")

            threadCount = int(self.query_one("#threadCount").value)
            self.startRange = self.query_one("#startRange").value
            self.endRange = self.query_one("#endRange").value
            self.timeOut = float(self.query_one("#timeOut").value)
            testStatement = False

            try:
                a = ipToInt(self.startRange)
                b = ipToInt(self.endRange)
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
            
                self.consoleLog.write(f"> [bold blue]{chosen.__name__}[/bold blue] was selected")
                event.button.display = False
                self.query_one("#stopButton").display = True
                self.consoleLog.write(f"> ipRange Set : [ {self.startRange} , {self.endRange} ] - {b-a} Ips Being Scanned")
                self.req = chosen(
                                    startIp=self.startRange,
                                    endIp=self.endRange,
                                    threads=threadCount,
                                    timeout=self.timeOut
                                )
                
                self.consoleLog.write(f"> given threads : [ {self.req.threadsAlotted} ]")
                self.consoleLog.write(f"> max threads : [ {os.cpu_count()} ]")
                rangeList = floodfill(self.req.ipRange,self.req.threadsAlotted)
                for i in range(len(rangeList)):
                    time.sleep(0.1)
                    p = rangeList[i]
                    self.consoleLog.write(f"[bold #ff00ff]IPTHREAD-{i}[/bold #ff00ff] : {intToIp(p.start)} -> {intToIp(p.stop-1)}")
                self.consoleLog.write("[bold #00FF00]Starting Threads...[/bold #00FF00]")
                self.req.startAll()
                self.progress_timer.resume()
        elif(event.button.id == "clearButton"):
            self.consoleLog.clear()
        else:
            self.progress_timer.reset()
            self.progress_timer.pause()
            #progress = self.query_one("#progressBar")
            #progress.update(progress=0)
            timeLeft = self.query_one("#timeLeft")
            timeLeft.update(progress=0)
            self.consoleLog.write("[bold #ffc800]INFO: STOPPING SCAN, This may take a minute.")
            self.req.stopAll()

            event.button.display = False
            self.query_one("#startButton").display = True
        
class Dataview(Static):
    
    def compose(self) -> ComposeResult:
        with Horizontal():
            with RadioSet(id="count"):
                yield RadioButton("64")
                yield RadioButton("128")
                yield RadioButton("256")
                yield RadioButton("512",True)
            yield Select((("1",0),),prompt="",allow_blank=False,id="pageSelector")
            yield Input("",id="filter",placeholder="Filter Title")
            yield Button("Refresh",id="refresh")
        yield Vertical(DataTable(),id="verticaldata")
        yield Footer()
    
        
    def update_content(self) -> None:
            #self.fileManager = FileManagerNEW()
            table = self.query_one(DataTable)
            table.clear()
            rows = self.fileManager.getPagesWithFilterRows(pageSize=self.rowsPer)
            #assert 0 == 1
            if len(rows):
                table.add_rows(rows[self.currentPage])

    def update_menu(self) -> None:
            self.pageCount = self.fileManager.getPageCount(self.rowsPer)
            if(self.pageCount > self.currentPage):
                self.currentPage = 0
            selector = self.query_one(Select)
            selections = [(str(i+1),i) for i in range(self.pageCount)]
            selector.set_options(tuple(selections))
    
    @on(Select.Changed)
    def select_changed(self, event: Select.Changed) -> None:
        self.currentPage = int(event.value)
        self.update_content()

    @on(Input.Submitted)
    def getFilterPrompt(self, event: Input.Submitted) -> None:
            self.fileManager.filterText = event.value.lower().rstrip()
            self.update_menu()
            self.update_content()

        
    def _on_mount(self, event: Mount) -> None:
        global theFilemanager
        self.fileManager = theFilemanager
        self.rowsPer = 256
        self.currentPage = 0
    
        selector = self.query_one(Select)
    
        table = self.query_one(DataTable)
        table.clear()
        table.add_columns("IP","Title")
        rows = self.fileManager.getPagesWithFilterRows(pageSize=self.rowsPer)

        if(len(rows)):
            table.add_rows(rows[self.currentPage])

        self.pageCount = self.fileManager.getPageCount(pageSize=self.rowsPer)
        selections = tuple((str(i+1),i) for i in range(self.pageCount))
        selector.set_options(selections)

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


# async def deBug():
#     scan = SMBScanner(   
#                             threads=1,
#                             startIp="10.30.0.0",
#                             endIp="10.30.2.255",
#                             timeout=4.5
#                             )
#     scan.startAll()
#     await scan.waitForCompletion()
#     tmp = scan.ipBank.getIPDict()
#     print(f"Found {len(tmp)} items")

if __name__ == "__main__":
    theFilemanager = FileManagerNEW()
    app = SwooperApp()
    app.run()
    #asyncio.run(deBug())
    pass
    
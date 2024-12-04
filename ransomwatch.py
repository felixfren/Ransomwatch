#Library untuk Logika program
from scapy.all import IP, TCP, UDP
from scapy.all import *
import platform
import joblib
import queue
import ifaddr
import datetime
import pefile

#Library untuk GUI program
import customtkinter
from CTkMessagebox import CTkMessagebox
from CTkTable import *
from plyer import notification
from PIL import Image
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

#dependency model untuk input
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from tensorflow import keras
import pandas as pd
import numpy as np

####   TO DO:
#### 1. AUTO UPDATE TOP TALKERS EVERY 10S <<<
#### 2. TABLE CLICK EVENT TO BLOCK & UNBLOCK SRC IP WITH NETSH OR IPTABLES (LINUX COMPATIBILITY) 50%, sisa handle blocknya

gray = "#EBEBEB"
dark1 = "#A3A3A3"
dark2 = "#3C3C3C"
dark3 = "#323232"
darkborder = "#313131"

blackblue = "#22292E"
highlightblue = "#539AD7"
mainblue = "#337AB7"
lime = "#2cbe79"
tangerine = "#ffd480"
danger = "#e20613"
crimson = "#88040b"
white = "#FFFFFF"
salem = "#0c955a"

customtkinter.set_appearance_mode("Light")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("green")  # Themes: "blue" (standard), "green", "dark-blue"

rf_pe = joblib.load('rf_lstm.pkl')
scaler = joblib.load('scaler.pkl') 
pca = joblib.load('pca.pkl')
lstm_model = keras.models.load_model('lstm_model.keras')



sniffing_state = False
t = None
talkers_data = {}
talkers_interfaces = []


def get_system_info():
    # Function untuk mengambil informasi sistem perangkat dengan library: 
    system_information = []
    ip_address = socket.gethostbyname(socket.gethostname())
    device_name = platform.node()
    device_os = platform.system()
    device_ver = platform.release()

    #system_information akan digunakan oleh main untuk ditampilkan pada widget 1. System Information.
    system_information.append(device_name)
    system_information.append(ip_address)
    system_information.append(device_os)
    system_information.append(device_ver)

    return system_information

def get_interfaces():
    interface_data = []
    adapters = ifaddr.get_adapters()

    for adapter in adapters:
        temp_data = []
        temp_data.append(adapter.nice_name)
        for ip in adapter.ips:
            if ip.is_IPv4 == True:
                #print("   %s/%s" % (ip.ip, ip.network_prefix))
                temp_data.append("%s" % (ip.ip))
        interface_data.append(temp_data)

    return interface_data

# Function to check for PE header
def is_pe_header(data):
    if data[:2] != b'MZ':
        return False
    # Check for 'PE\0\0' signature at the offset specified in the DOS header
    e_lfanew = int.from_bytes(data[0x3C:0x40], byteorder='little')
    return data[e_lfanew:e_lfanew+4] == b'PE\0\0'

payload_no = 0
seen_executables = {}
def process_packet(packet,q, app):
    global payload_no
    #print(packet)
    if IP in packet:
        protocol = packet[IP].proto
        in_bytes = len(packet)
        out_bytes = 0  # Placeholder, as we don't have outgoing bytes in a single packet
        in_pkts = 1
        out_pkts = 0  # Placeholder, as we don't have outgoing packets in a single packet
        tcp_flags = packet[TCP].flags if TCP in packet else 0
        flow_duration = 0  # Placeholder, as we don't have flow duration in a single packet
        timestamp = time.time()

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            l7_proto = 6  # TCP
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            l7_proto = 17  # UDP
        else:
            src_port = 0
            dst_port = 0
            l7_proto = 0


        # Extract payload
        payload = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload) if UDP in packet else b''
        # Check for PE header in payload
        
        if is_pe_header(payload):
            try:
                
                #print(f"PE Header ditemukan dalam paket dari {packet[IP].src} ke {packet[IP].dst}")
                pe_features = []
                for byte in payload:
                    pe_features.append(byte)
                #pe_features = extract_pe_features(pe)
                #print(pe_features)

                pe_key = payload[:1024]

                pe_features = pe_features[:1024]  # Model expects a 2D array
                #print(pe_features)
                # Create a pandas DataFrame with feature names
                feature_names = [str(i) for i in range(1024)]
                X_new = np.array(pe_features).reshape(1,-1)
                # df = pd.DataFrame(decimal_values.reshape(1, -1), columns=feature_names)
                print(X_new)
                X_scaled = scaler.transform(X_new)
                print(X_scaled)
                X_pca_new = pca.transform(X_scaled)
                print(X_pca_new)
                X_lstm_new = X_pca_new.reshape((X_pca_new.shape[0], 1, X_pca_new.shape[1]))
                lstm_features_new = lstm_model.predict(X_lstm_new)
                print(lstm_features_new)
               
                pe_prediction = rf_pe.predict(lstm_features_new)
                print(pe_prediction)
                # Send notification with the ransomware family
                if pe_prediction[0] == 0:
                    ransomware_family = "Goodware"
                elif pe_prediction[0] == 1:
                    ransomware_family = "Ransomware"
                #ransomware_family = pe_prediction[0]

                #print(payload_no,timestamp,packet[IP].src, packet[IP].dst, ransomware_family, "Allow")
                
                #q.put(f"Ransomware family {ransomware_family} notification sent.\n")
                #print(f"Ransomware family {ransomware_family} notification sent.")
                #print(q)    
                if pe_key not in seen_executables or (timestamp - seen_executables[pe_key]) > 1:
                    #currtime = datetime.datetime.now()
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    currtime = time.time()
                    payload_no = payload_no + 1
                    seen_executables[pe_key] = currtime  # Update timestamp for this executable
                    q.put([payload_no,timestamp,packet[IP].src, packet[IP].dst, ransomware_family, "Allow"])

                    app.after(0,lambda:notification.notify(
                    title='PE Header ditemukan',
                    message=f"{ransomware_family} ditemukan dalam paket jaringan dari {packet[IP].src} ke {packet[IP].dst}",
                    app_icon=None,
                    timeout=5
                    ))

                    talkers_data[packet[IP].dst] = payload_no
                    App.update_toptalkers(app)


            except pefile.PEFormatError as e:
                print(e)

def sniff_trigger(q,app):
    global sniffing_state
    global t
    print("post declare: ",sniffing_state)

    if sniffing_state:
        print("start func: ", sniffing_state)
        print("[!] Listening for incoming Executable Packets")
        if t is None or not t.isAlive():
            t = AsyncSniffer(prn=lambda packet: process_packet(packet, q, app), store=False)#Software Loopback Interface 1
            t.start()
        print("start func 2: ", sniffing_state, "t state:", t)

    elif not sniffing_state and t is not None:
        print("stop func: ", sniffing_state)
        print("[!] Stopping...")
        t.stop()

        time.sleep(3)

        t.join()
        t = None

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        global sniffing_state
        global t
        global talkers_data
        global talkers_interfaces
        sysipadd = get_system_info()
        sysinterface = get_interfaces()
        

        self.queue = queue.Queue()
        # configure window
        self.title("Ransomware Detector")
        self.geometry(f"{1280}x{720}")

        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure((1,2,3), weight=1)
        self.grid_rowconfigure(0, weight=0)  # Header row, no weight
        self.grid_rowconfigure(1, weight=1)  # Main content row, with weight
        self.grid_rowconfigure(2, weight=1)  # Output box row, with weight
        self.grid_rowconfigure(3, weight=0)  # Footer row, no weight

        # --- Header Frame ---
        self.header_frame = customtkinter.CTkFrame(self, height=50, corner_radius=0, fg_color=danger)
        self.header_frame.grid(row=0, column=1, columnspan=4, sticky="new")
        self.header_label = customtkinter.CTkLabel(self.header_frame, text="Click on Start to begin detection", font=customtkinter.CTkFont(size=16,weight="bold"), text_color=white)
        self.header_label.pack(pady=5)

        # --- Footer Frame ---
        # self.footer_frame = customtkinter.CTkFrame(self, height=30, corner_radius=0, fg_color=dark3)
        # self.footer_frame.grid(row=3, column=1, columnspan=4, sticky="ews")
        # self.footer_label = customtkinter.CTkLabel(self.footer_frame, text="2024-10-15 08.50.59 WIB", font=customtkinter.CTkFont(size=12), text_color=dark1)
        # self.footer_label.grid(pady=5)
        
        # create sidebar frame with widgets
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0, fg_color=dark2)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(3, weight=1)

        #Sidebar stuff

        self.sidenav_frame = customtkinter.CTkFrame(self.sidebar_frame, height=50, corner_radius=0, fg_color=dark3)
        self.sidenav_frame.grid(row=0, column=0, sticky="ew") 

        self.logo_label = customtkinter.CTkLabel(self.sidenav_frame, text="RansomWatch", font=customtkinter.CTkFont(size=16, weight="bold"), text_color=white)
        self.logo_label.pack(pady=5)

        logo_image = customtkinter.CTkImage(Image.open("mainicon.png"), size=(156,120))
        self.image_label = customtkinter.CTkLabel(self.sidebar_frame, image=logo_image, text="")
        self.image_label.grid(row=1, column=0,pady=(10,10))

        self.start_button = customtkinter.CTkButton(self.sidebar_frame, command=lambda: [self.start_button_event(), self.update_toptalkers()], text="Start", fg_color=lime, hover_color=salem)
        self.start_button.grid(row=2, column=0, padx=20, pady=10, sticky="sw")

        self.stop_button = customtkinter.CTkButton(self.sidebar_frame, command=self.stop_button_event, text="Stop", fg_color=danger, hover_color=crimson)
        self.stop_button.grid(row=3, column=0, padx=20, pady=10, sticky="nw")


        # self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["Options", "Minimize to Tray"],
        #                                                                command=self.change_appearance_mode_event)
        # self.appearance_mode_optionemenu.grid(row=4, column=0, padx=20, pady=(10, 10))

        self.scaling_label = customtkinter.CTkLabel(self.sidebar_frame, text="UI Scaling:", text_color=white, anchor="w")
        self.scaling_label.grid(row=4, column=0, padx=20)

        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["75%", "100%", "125%"],
                                                               command=self.change_scaling_event)
        self.scaling_optionemenu.grid(row=5, column=0, padx=20, pady=(10, 25))

        # # create main entry and button
        # self.entry = customtkinter.CTkEntry(self, placeholder_text="CTkEntry")
        # self.entry.grid(row=3, column=1, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")

        # self.main_button_1 = customtkinter.CTkButton(master=self, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        # self.main_button_1.grid(row=3, column=3, padx=(20, 20), pady=(20, 20), sticky="nsew")

        # Widget System Information
        self.sysinfo = customtkinter.CTkFrame(self, width=400, corner_radius=5, fg_color=white)
        self.sysinfo.grid(row=1, column=1, padx=(20, 0), pady=(20, 0), sticky="nwes")
        
        self.syslabel = customtkinter.CTkLabel(self.sysinfo, anchor="w", text="System Information", text_color=dark3, font=customtkinter.CTkFont(size=16,weight="bold"))
        self.syslabel.grid(row=0,column=0, sticky="w", padx=(10,0),pady=(5, 0))

        self.syshost = customtkinter.CTkLabel(self.sysinfo, anchor="w", text="Hostname", text_color=dark1)
        self.syshost.grid(row=1,column=0, sticky="w", padx=(10,0))
        self.syshostinfo = customtkinter.CTkLabel(self.sysinfo, anchor="w", text=sysipadd[0])
        self.syshostinfo.grid(row=1,column=1, sticky="w", padx=(10,0))

        self.sysip = customtkinter.CTkLabel(self.sysinfo, anchor="w", text="IP Address", text_color=dark1)
        self.sysip.grid(row=2,column=0, sticky="w", padx=(10,0))
        self.syshostinfo = customtkinter.CTkLabel(self.sysinfo, anchor="w", text=sysipadd[1])
        self.syshostinfo.grid(row=2,column=1, sticky="w", padx=(10,0))

        self.sysos = customtkinter.CTkLabel(self.sysinfo, anchor="w", text="Operating System", text_color=dark1)
        self.sysos.grid(row=3,column=0, sticky="w", padx=(10,0))
        self.syshostinfo = customtkinter.CTkLabel(self.sysinfo, anchor="w", text=sysipadd[2])
        self.syshostinfo.grid(row=3,column=1, sticky="w", padx=(10,0))

        self.sysver = customtkinter.CTkLabel(self.sysinfo, anchor="w", text="OS Version", text_color=dark1)
        self.sysver.grid(row=4,column=0, sticky="w", padx=(10,0))
        self.sysverinfo = customtkinter.CTkLabel(self.sysinfo, anchor="w", text=sysipadd[3])
        self.sysverinfo.grid(row=4,column=1, sticky="w", padx=(10,0))

        # Widget Avail Interfcaces
        self.interfaceinfo = customtkinter.CTkScrollableFrame(self, width=400, corner_radius=5, fg_color=white, scrollbar_button_color=gray, scrollbar_button_hover_color=dark1)
        self.interfaceinfo.grid(row=1, column=2, padx=(20, 0), pady=(20, 0), sticky="nwes")
        self.interfacelabel = customtkinter.CTkLabel(self.interfaceinfo, anchor="w", text="Available Interfaces", text_color=dark3, font=customtkinter.CTkFont(size=16,weight="bold"))
        self.interfacelabel.grid(row=0,column=0, sticky="w", padx=(10,0),pady=(0, 0))
    
        i = 0
        for interface in sysinterface:      
            self.sysint = customtkinter.CTkLabel(self.interfaceinfo, anchor="w", text=interface[0], text_color=dark1)
            self.sysint.grid(row=i+1,column=0, sticky="w",padx=(10,10))
            self.sysintinfo = customtkinter.CTkLabel(self.interfaceinfo, anchor="w", text=interface[1])
            self.sysintinfo.grid(row=i+1,column=1, sticky="w",padx=(10,10))
            i +=1

        # Widget : Table Detection History
        self.outputbox = customtkinter.CTkScrollableFrame(self, corner_radius=5, fg_color=white, 
                                                          label_text="Real Time Detection",orientation="vertical", label_anchor="w", label_fg_color=white,
                                                          label_text_color=dark3, label_font=customtkinter.CTkFont(size=16,weight="bold"),
                                                          scrollbar_button_color=gray, scrollbar_button_hover_color=dark1)
        self.outputbox.grid(row=2, column=1, padx=(20, 0), pady=(20, 20), sticky="nwes", columnspan=2)
        self.outputbox.columnconfigure(0,weight=1)
        value = [["No","Timestamp","Source IP","Destination IP","Prediction Result"],]#Action
        
        self.outputtable = CTkTable(self.outputbox, row=1, column=5, values=value, corner_radius=0
                                    ,anchor="w", colors=[white,white], header_color=gray, hover_color=tangerine,
                                    command=self.tabledetails)
        self.outputtable.grid(row=1, column=0, sticky= "ew", padx=(5,0))


        # Widget : Top Talkers (Matplotlib)
        self.toptalkers = customtkinter.CTkFrame(self, corner_radius=5, fg_color=white)
        self.toptalkers.grid(row=1, column=3, padx=(20, 20), pady=(20,0), sticky="nwes")
        self.toptalkerslabel = customtkinter.CTkLabel(self.toptalkers, anchor="w", text="Top Talkers", text_color=dark3, font=customtkinter.CTkFont(size=16,weight="bold"))
        self.toptalkerslabel.grid(row=0,column=0, sticky="w", padx=(10,0),pady=(0, 0))
        self.toptalkers.rowconfigure(1,weight=1)
        self.toptalkers.columnconfigure(0,weight=1)
        
        # talkers_ip = talkers_data.keys()
        # talkers_freq = talkers_data.values()
        x = 0
        for interface in sysinterface:      
            talkers_interfaces.append(interface[1])
            talkers_data[interface[1]] = 0
            x +=1
        self.update_toptalkers()
        # self.talkersFigure = Figure(figsize=(6, 4), dpi=50)
        # self.figure_canvas = FigureCanvasTkAgg(self.talkersFigure, self.toptalkers)
        # self.axes = self.talkersFigure.add_subplot()
        # self.axes.bar(talkers_ip, talkers_freq, color="#ffd480")
        # self.axes.tick_params(axis='x', labelrotation=30)
        # self.axes.spines['right'].set_visible(False)
        # self.axes.spines['top'].set_visible(False)

        # self.figure_canvas.get_tk_widget().grid(row=1,column=0, sticky="nsew", padx=(0,0),pady=(0, 5))
    



        # Widget : Notification Log (Text)
        self.textboxframe = customtkinter.CTkFrame(self, corner_radius=5, fg_color=white, width=400)
        self.textboxframe.grid(row=2, column=3, padx=(20, 20), pady=(20, 20), sticky="nwes")

        self.textboxlabel = customtkinter.CTkLabel(self.textboxframe, anchor="w", text="Notification Log", text_color=dark3, font=customtkinter.CTkFont(size=16,weight="bold"))
        self.textboxlabel.grid(row=0,column=0, sticky="w", padx=(10,0),pady=(5, 0))

        self.outputboxtext = customtkinter.CTkTextbox(self.textboxframe)
        self.outputboxtext.grid(row=1, column=0, sticky="nsew", padx=(5,5), pady=(5, 5))
        self.textboxframe.rowconfigure(1,weight=1)
        self.textboxframe.columnconfigure(0,weight=1)
        
        # set default values
        self.stop_button.configure(state="disabled")
        self.outputboxtext.configure(state="normal")
        self.scaling_optionemenu.set("100%")

    def open_input_dialog_event(self):
        dialog = customtkinter.CTkInputDialog(text="Type in a number:", title="CTkInputDialog")
        print("CTkInputDialog:", dialog.get_input())

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)

    def start_button_event(self):
        global sniffing_state
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")

        
        self.outputboxtext.insert(customtkinter.END, "[ ! ] Listener Started.\n")


        sniffing_state = True
        
        sniff_trigger(self.queue, self)
        self.update_header()
        self.update_textbox()

    def stop_button_event(self):
        global sniffing_state
        sniffing_state = False
        self.stop_button.configure(state="disabled")
        self.start_button.configure(state="normal", text="Begin")
        
        self.outputboxtext.insert(customtkinter.END, "[ ! ] Listener Stopped.\n")
        self.update_header()
        sniff_trigger(self.queue,self)

    def update_textbox(self):
        try:
            output = self.queue.get(block=False)
            if output[4] == "Goodware":
                notificationlog = f"[ {output[1]} ] - PASS\n > No Ransomware Found.\n\n"
            elif output[4] == "Ransomware":
                notificationlog = f"[ {output[1]} ] - ALERT\n > Ransomware Found. Action Needed.\n\n"
            else:
                notificationlog = None

            self.outputboxtext.insert(customtkinter.END, notificationlog)
            self.outputboxtext.see(customtkinter.END)
            self.outputtable.add_row(output)
            notificationlog = None
        except queue.Empty:
            pass
        finally:
            self.after(100, self.update_textbox)

    #######HANDLE HEADER STATE
    def update_header(self):
        if sniffing_state:
            self.header_frame.configure(fg_color=lime)
            self.header_label.configure(text="Listening on All Interfaces")

        elif not sniffing_state and t is not None:
            self.header_frame.configure(fg_color=danger)
            self.header_label.configure(text="Click on Begin to Start Detection")
        # elif not sniffing_state and t is None:
        #     self.header_frame.configure(fg_color=tangerine)
        #     self.header_label.configure(text="Please Wait...")


    #### get table row value
    def tabledetails(self,block):
        #print(block)
        value = self.outputtable.get_row(block['row'])
        #print(value)
        #message_content = f"Detected On     : {value[1]}\nSource IP     : {value[2]}\nDestination IP     : {value[3]}\nCurrent Action     : {value[5]}\n"
        message_content = [["Detected On", "Source IP", "Destination IP"],[value[1],value[2],value[3]]]
        msg = CTkMessagebox(self,
                            title="Details",
                            title_color=white,
                            message="\n\n\n\n\n\n\n\n\n\n\n",
                            option_1="Block",
                            option_2="Unblock",
                            bg_color=dark2,
                            fg_color=white,
                            corner_radius=5,   
                            button_color=danger,   
                            button_hover_color=crimson,                
                            )
        valuetable = CTkTable(msg, row=4,column=2,values=message_content, corner_radius=0,
                              hover_color=tangerine, anchor="w", orientation="vertical",
                              colors=[white,white])
        valuetable.grid(row=0,column=0, sticky="we", padx=(30,30),pady=(50, 50))

        response = msg.get()

        if response == "Block":
            confirmation = CTkMessagebox(
                self,
                title= "Are You Sure?",
                title_color=white,
                message= f"Traffic from the IP ({value[2]}) will be BLOCKED on Your Network.",
                option_1="No",
                option_2="Yes",
                bg_color=dark2,
                fg_color=white,
                corner_radius=5,
                icon="question",
                button_color=danger,   
                button_hover_color=crimson,  
                )
            confirm = confirmation.get()
            if confirm == "Yes":
                print("IP Blocked")
                command = f"netsh advfirewall firewall add rule name=\"Block IP {value[2]}\" dir=out action=block remoteip={value[2]}"
                subprocess.run(command, shell=True, check=True)
                command = f"netsh advfirewall firewall add rule name=\"Block IP {value[2]}\" dir=in action=block remoteip={value[2]}"
                subprocess.run(command, shell=True, check=True)
                print(command)
            else:
                print("Operation Canceled.")
        elif response == "Unblock":
            confirmation = CTkMessagebox(
                self,
                title= "Are You Sure?",
                title_color=white,
                message= f"Traffic from the IP ({value[2]}) will be ALLOWED on Your Network.",
                option_1="No",
                option_2="Yes",
                bg_color=dark2,
                fg_color=white,
                corner_radius=5,
                icon="warning",
                button_color=danger,     
                button_hover_color=crimson,   
                )
            confirm = confirmation.get()
            if confirm == "Yes":
                print("IP Allowed")
                command = f"netsh advfirewall firewall delete rule name=\"Block IP {value[2]}\""
                subprocess.run(command, shell=True, check=True)
            else:
                print("Operation Canceled.")
        else:
            print("Operation Canceled.")

    def update_toptalkers(self):
        global talkers_ip
        global talkers_freq
        global talkers_data
        
        # try:
        talkers_ip = talkers_data.keys()
        talkers_freq = talkers_data.values()

        self.talkersFigure = Figure(figsize=(6, 4), dpi=50)
        self.axes = self.talkersFigure.add_subplot()
        self.axes.bar(talkers_ip, talkers_freq, color="#ffd480")
        self.axes.tick_params(axis='x', labelrotation=30)
        self.axes.spines['right'].set_visible(False)
        self.axes.spines['top'].set_visible(False)

        self.figure_canvas = FigureCanvasTkAgg(self.talkersFigure, self.toptalkers)
        self.figure_canvas.get_tk_widget().grid(row=1,column=0, sticky="nsew", padx=(0,0),pady=(0, 5))

        # except:
        #     pass
    
if __name__ == "__main__":
    app = App()
    app.mainloop()
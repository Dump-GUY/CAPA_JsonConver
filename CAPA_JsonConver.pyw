#This script works with exported results of CAPA tool in .json format and convert them to .tag file or x64dbg annotation and bookmarking script.
#Analyze sample with CAPA:
#Example: CAPA -j malware.exe > malware.exe.json
#Example: CAPA -j malware.bin > malware.bin.json
#Example: CAPA -j DD488AF61F792C89265FD783F3EC4A18 > DD488AF61F792C89265FD783F3EC4A18.json
#Parameter '-j' must be presented in cmdline argument to export results in .json format.
#The exported .json file MUST have the original filename of sample (shown in examples) to successful use of exported x64dbg script !!! 
#Do NOT change the filename of sample for x64dbg or the script would not find the Base address.

from tkinter import filedialog
from tkinter import messagebox
from tkinter import *
import re
import json
from pathlib import Path
			
root = Tk()
root.withdraw()
response = messagebox.askyesnocancel("Option 1 - export to .tag file", "Export to .tag file?")
if response == True:
    root.filename = filedialog.askopenfilename(initialdir = "/",title = "Select .json file",filetypes = (("Json Files","*.json"),))
    with open(root.filename) as f:
        data = json.load(f)

    base = data['meta']['analysis']['base_address']
    Capabilities = list(data['rules'].keys())
    Tag_file = ""

    for i in range (0,len(Capabilities)):    
        Current_capability = Capabilities[i]
        Current_scope = data['rules'][Capabilities[i]]['meta']['scope']
        Matches_list = list(data['rules'][Capabilities[i]]['matches'].keys())
        if 'lib' in data['rules'][Capabilities[i]]['meta'].keys() and data['rules'][Capabilities[i]]['meta']['lib'] == True:
            pass
        else:
                if Current_scope == 'file':
                    Matches_list[0] = (str(base))
                for j in range (0,len(Matches_list)):
                    Bool = False
                    for k in range (0,len(Tag_file.split("\n"))):
                        if (str(hex(int(Matches_list[j]) - base))).split('x')[1] =='0' and '0;FILE' in Tag_file.split("\n")[k]:
                            H_var = Tag_file.split("\n")
                            H_var[k] = Tag_file.split("\n")[k] + ", " + Current_scope.upper() + ': ' +  Current_capability
                            Tag_file = "\n".join(H_var)
                            Bool=True

                        elif (str(hex(int(Matches_list[j]) - base))).split('x')[1] in Tag_file.split("\n")[k] and (str(hex(int(Matches_list[j]) - base))).split('x')[1] !='0':
                            H_var = Tag_file.split("\n")
                            H_var[k] = Tag_file.split("\n")[k] + ", " + Current_scope.upper() + ': ' +  Current_capability
                            Tag_file = "\n".join(H_var)
                            Bool=True
                    if not Bool:
                        Bool = False
                        Tag_file += (str(hex(int(Matches_list[j]) - base))).split('x')[1] + ";" + Current_scope.upper() + ':' +  Current_capability + "\n"
    f = open((root.filename).replace('.json', '.tag'), "w").write(Tag_file)

if response == False or response == True:
    response = messagebox.askyesnocancel("Option 2 - export to x64dbg script file", "Export to x64dbg.txt file?")
    if response == True:
        root.filename = filedialog.askopenfilename(initialdir = "/",title = "Select .json file",filetypes = (("Json Files","*.json"),))
        with open(root.filename) as f:
            data = json.load(f)

        base = data['meta']['analysis']['base_address']
        Capabilities = list(data['rules'].keys())
        Tag_file = ""

        for i in range (0,len(Capabilities)):  
            Current_capability = Capabilities[i]
            Current_scope = data['rules'][Capabilities[i]]['meta']['scope']
            Matches_list = list(data['rules'][Capabilities[i]]['matches'].keys())
            if 'lib' in data['rules'][Capabilities[i]]['meta'].keys() and data['rules'][Capabilities[i]]['meta']['lib'] == True:
                pass
            else:
                    if Current_scope == 'file':
                        Matches_list[0] = (str(base))
                    for j in range (0,len(Matches_list)):
                        Bool = False
                        for k in range (0,len(Tag_file.split("\n"))):
                            if (str(hex(int(Matches_list[j]) - base))).split('x')[1] =='0' and '0;FILE' in Tag_file.split("\n")[k]:
                                H_var = Tag_file.split("\n")
                                H_var[k] = Tag_file.split("\n")[k] + ", " + Current_scope.upper() + ': ' +  Current_capability
                                Tag_file = "\n".join(H_var)
                                Bool=True

                            elif (str(hex(int(Matches_list[j]) - base))).split('x')[1] in Tag_file.split("\n")[k] and (str(hex(int(Matches_list[j]) - base))).split('x')[1] !='0':
                                H_var = Tag_file.split("\n")
                                H_var[k] = Tag_file.split("\n")[k] + ", " + Current_scope.upper() + ': ' +  Current_capability
                                Tag_file = "\n".join(H_var)
                                Bool=True
                        if not Bool:
                            Bool = False
                            Tag_file += (str(hex(int(Matches_list[j]) - base))).split('x')[1] + ";" + Current_scope.upper() + ':' +  Current_capability + "\n"
        
        xdbg_RVA = []
        xdbg_comment = []
        Basename = Path(root.filename).name.replace('.json','')
        Base_define = "$base=" + "\"" + Basename +":base" + "\""
        Xdbg_script = Base_define + "\n"
        for k in range (0,len(Tag_file.split("\n")) -1):
            xdbg_RVA.append(Tag_file.split("\n")[k].split(';')[0])
            xdbg_comment.append(Tag_file.split("\n")[k].split(';')[1])
            Xdbg_script += "cmt $base+" + xdbg_RVA[k] + "," +"\""+ xdbg_comment[k][:226] +"\"" + "\n"
            Xdbg_script += "bookmark $base+" + xdbg_RVA[k] + "\n"
        f = open((root.filename).replace('.json', '.x64dbg.txt'), "w").write(Xdbg_script)
    else:
        pass
else:
    pass

# CAPA_JsonConver
Converts exported results of Capa tool from .json format to another formats supporting by different tools.<br/>
It parses the .json output and converts it to .tag file, x64dbg annotation and bookmarking script or Cutter/r2gui annotation script so you will be able to profit from Capa results in other tools.<br/>
The format of .tag file can be used for intagration CAPA results to tools like PE-bear (Tested): https://github.com/hasherezade/pe-bear-releases or IDA PRO (not Tested) with use of IFL plugin made by: https://github.com/hasherezade/IDA_ifl
<br/>
## What is Capa:
Capa detects capabilities in executable files. You run it against a PE file or shellcode and it tells you what it thinks the program can do.
For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate.<br/>
Capa repo: https://github.com/fireeye/capa <br/>
Capa blog post: https://www.fireeye.com/blog/threat-research/2020/07/capa-automatically-identify-malware-capabilities.html
<br/>
## How to use:
Analyze sample with CAPA:<br/>
Example: CAPA -j malware.exe > malware.exe.json<br/>
Example: CAPA -j malware.bin > malware.bin.json<br/>
Example: CAPA -j malware > malware.json<br/>
Example: CAPA -j DD488AF61F792C89265FD783F3EC4A18 > DD488AF61F792C89265FD783F3EC4A18.json<br/>
Parameter '-j' must be presented in cmdline argument to export results in .json format.<br/>
<br/>
The exported .json file MUST have the original filename of sample (shown in examples) to successful use of exported x64dbg script !!!<br/> 
Do NOT change the filename of sample for x64dbg or the script would not find the Base address.<br/>
<br/>
Run CAPA_JsonConver.pyw or standalone binary CAPA_JsonConver.exe (https://github.com/Dump-GUY/CAPA_JsonConver/releases)<br/>
CheckboxBox option menu will pop up and you can choose if you want to convert .json to .tag file, x64dbg script or Cutter/r2gui script.<br/>
File open dialog will pop up - choose .json file which you want to convert.<br/>
<br/>
All converted files are saved to the same location where the .json file used for conversion.<br/>
<br/>
CheckBox option menu:<br/>

![checkbox_options](/Images/CAPA_JsonConver_CheckboxOptions.PNG)

Selecting .json file:

![Loading_json file](/Images/Loading_json_file.PNG)
<br/>
<br/>
## x64dbg:
Run x64dbg with relevant sample.<br/>
Go to script tab and load script exported by CAPA_JsonConver.py.<br/>
Run script.
<br/>
![Script run](/Images/x64dbg_run_script.PNG)
<br/>
Unload the script.<br/>
You can see that code was commented in disassembly view and bookmark view. <br/>
<br/>
Disassembly view:
<br/>
![x64dbg_disassemblyView](/Images/x64dbg_disassemblyView.PNG)
<br/>
<br/>
Bookmark view:
<br/>
![Bookmark view](/Images/x64dbg_bookmarkview.PNG)
<br/>
<br/>
Graph view with bookmarks:
<br/>
![Graph and bookmark view](/Images/x64dbg_Graph_view_and_bookmarks.PNG)
<br/>
<br/>
## PE-bear:
If you run Pe-bear and load sample from the same directory, where .tag file is - .tag file is automatically imported.<br/>
If not - run Pe-bear and load sample. Click on Tag button - click on file - load - select your .tag file.<br/>

Hint: You can enable option in PE-bear - Tag view - Follow on click --> so if you click on RVA you are immediately on that position in 
Disassembly view, which could be quite handy.

PE-bear view 1:

![PE-Bear view 1](/Images/Pe_Bear_1.PNG)


PE-bear view 2:

![PE-Bear view 2](/Images/Pe_Bear_2.PNG)
<br/>
<br/>
## Cutter/r2gui:
Run Cutter, load relevant sample and run the .r2 script produced by tool CAPA_JsonConver.
You can run the .r2 script via advanced options during sample loading.

Advanced options during sample loading:

![Cutter_import_script1](/Images/Cutter_import_script1.png)

Or you can run .r2 script from Cutter view. If you run script from Cutter view - you MUST refresh view with F5 or in View Tab/Refresh Contents to see modified contents.

Running Cutter script from Cutter view:

![Cutter_import_script2](/Images/Cutter_import_script2.png)

Cutter - Comment and Disassembly view annotated with Capa results:

![Cutter_import_script2](/Images/CAPA_JsonConver_disassemblyView.PNG)

Cutter - Comment and Graph view annotated with Capa results and CallGraph view:

![Cutter_import_script2](/Images/CAPA_JsonConver_Graphview_comments_callgraph.PNG)

Cutter - Comment and Disassembly view annotated with Capa results and CallGraph view:

![Cutter_import_script2](/Images/CAPA_JsonConver_disassemblyView_comments_callgraph.PNG)

Cutter - Comment, Disassembly view and Decompile view annotated with Capa results:

![Cutter_import_script2](/Images/CAPA_JsonConver_disassemblyView_comments_decompileview.PNG)
<br/>
<br/>
## Limitations:
In case of more Capabilities detected by Capa which are relevant to the same origin RVA (same function, block or whole file),all capabilities are chained and added (as a comment) to the same RVA.<br/>
The sizes of labels and comments in x64dbg are limited to ~256 characters so in case of more Capabilities relevant to same origin RVA - only first 256 character are added and some Capability could be cut off :(<br/>
In real Case the cutting off chained Capabilities which takes together more than 256 character is not such a problem because<br/>
you already know that the (Function, Block) on the specific RVA has for example more than 10 Capabilities so it must be your point of interrest.
<br/>
In case of .tag file, there is no limitation - cutting off capabilities size relevant to same RVA - programs supporting .tag file can handle larger comments. <br/>
Example: PE-bear: https://github.com/hasherezade/pe-bear-releases
<br/>
## Additional information:
Require Python 3+ or you can use standalone binary for Windows 64bit (https://github.com/Dump-GUY/CAPA_JsonConver/releases).<br/>
Tested with CAPA version 1.0.0-1.1.0, X64dbg, Cutter, PE-Bear version 0.4.0.3, on win7 - win10.<br/>

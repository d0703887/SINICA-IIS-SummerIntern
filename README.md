---
title: Information Extraction on Cyber Threat Intelligence (CTI) Reports

---

# Information Extraction on Cyber Threat Intelligence (CTI) Reports

## Intro
[MITRE ATT&CK](https://attack.mitre.org/) defines a knowledge base of adversary tactics and techniques. This project aims to **automatically extract the techniques mentioned in CTI reports by leveraging natural language understanding.** Specifically, it infers the adversary behaviors from unstructured text description in CTI reports and maps them to corresponding techniques. 

## Example

**CTI Report Example:**
>The threat actors **1) sent the trojanized Microsoft Word documents, probably via email**. Talos discovered a document named MinutesofMeeting-2May19.docx. Once **2) the victim opens the document, it fetches a remove template from the actor-controlled website, hxxp://droobox[.]online:8o/luncher.doc**. Once the luncher.doc was downloaded, **3) it used CVE-2017-11882, to execute code on the victim's machine**. After the exploit, the file would write a series of base64-encoded PowerShell commands that acted as a stager and **4) set up persistence by adding it to the HKCU\Software\Microsoft\Windows\CurrentVersion\Run Registry key**.

**Extracted techniques:**
1.  T1566: Phishing Email
2.  T1204: User Execution
3.  T1203: Exploitation
4.  T1547: Boot Autostart

## Method
### Pipeline
<small>*This work is based on **[AttacKG: Constructing Knowledge-enhanced Attack Graphs from Cyber Threat Intelligence Reports](https://arxiv.org/abs/2111.07093)**.*</small>
![image](https://hackmd.io/_uploads/S10j1v0Mlx.png)
### Entity Extraction (NER)
Since CTI reports often contain domain-specific term and publicly available cybersecurity NER datasets are limited, existing NER model struggle to generalize to unseen terms and frequently produce false positive.

To solve this, I leveraged Large Language Models (LLMs)—specifically ChatGPT4—to perform accurate NER. The massive pretraining corpus of LLMs provids them with inherent **cybersecurity domain knowledge** and enables them to to **generalize well to unseen terms** by understanding the context withint CTI reports.

### Semantic Role Labeling
Follow *[Extractor: Extracting Attack Behavior from Threat Reports](https://ieeexplore.ieee.org/document/9581182)*. Semantic Role Labeling provides more semantic relation between entities compared to Dependency Parsing.

For example:
> DarkTortilla has established persistence via the Software\Microsoft\WindowsNT\CurrentVersion\Run registry key and by creating a .lnk shortcut file in the Windows startup folder.

**Dependency Parsing output:**
```
      "DarkTortilla"
            ↓
"Software\Microsoft..."
            ↓
    ".lnk shortcut file"
```

**Semantic Role Labeling output:**
```
                "DarkTortilla"
                  ↙       ↘
"Software\Microsoft.."   ".lnk shortcur file"
```

### Technique Graph Templates
MITRE ATT&CK provides procedure examples for each techniques. Technique Graph Templates (TG Templates) provides a rough template of how each techniques work in a knowledge graph, which later can be used in the graph matching to determine techniques used in the unseen CTI report.

Each technique can have $n_T$ TG
Templates, because a single technique may be implemented in diverse way. 

For example: 
**Procedure 1:**
> APT28 has used CVE-2015-1701 to access the SYSTEM token and copy it into the current process as part of privilege escalation.

**Procedure 2:**
>BADHATCH can impersonate a lsass.exe or vmtoolsd.exe token.

Although both procedures correspond to *T1134.001 Access Token Manipulation: Token Impersonation/Theft*, they involve distinct implementation. Hence, they are best represented by separate TG Templates.


**To generate TG Templates:**

1. Collect $n_p$ procedure examples for a given technique.
2. Transform each of the $n_p$ procedures into $n_p$ individual knowledge graph using the pipeline above.
3. Merge similar graphs into $n_T$ representative TG Templates.

This many-to-many mapping (technique -> TG Templates) is necessary because mering all procedure graphs into one would introduce excessive detail and noise.

## Result
**Target Report**:
> The threat actors sent the trojanized Microsoft Word documents, probably via email. Talos discovered a document named MinutesofMeeting-2May19.docx. Once the victim opens the document, it fetches a remove template from the actor-controlled website, hxxp://droobox[.]online:80/luncher.doc. Once the luncher.doc was downloaded, it used CVE-2017-11882, to execute code on the victim's machine. After the exploit, the file would write a series of base64-encoded PowerShell commands that acted as a stager and set up persistence by adding it to the HKCU\Software\Microsoft\Windows\CurrentVersion\Run Registry key.
> 
> Once the evasion checks were complete, the threat actors used MSbuild to execute an actor-created file named "LOCALAPPDATA\Intel\instal.xml". Based on lexical analysis, we assess with high confidence that this component of the macro script was based on an open-source project called "MSBuild-inline-task". While this technique was previously documented last year, it has rarely been observed being used in operations. Talos suspects the adversary chose MSBuild because it is a signed Microsoft binary, meaning that it can bypass application whitelisting controls on the host when being used to execute arbitrary code.
>
>Once the "instal.xml" file began execution, it would deobfuscate the base64-encoded commands. This revealed a stager, or a small script designed to obtain an additional payload. While analyzing this stager, we noticed some similarities to the "Get-Data" function of the FruityC2 PowerShell agent. One notable difference is that this particular stager included functionality that allowed the stager to communicate with the command and control (C2) via an encrypted RC4 byte stream. In this sample, the threat actors' C2 server was the domain msdn[.]cloud.
>
>If successful, the C2 would return a string of characters. Once the string was RC4 decrypted, it launched a PowerShell Empire agent. The PowerShell script would attempt to enumerate the host to look for certain information. Once the aforementioned information was obtained, it was sent back to the threat actor's C2.

**Output Graph**:
![image](https://hackmd.io/_uploads/SkfwH_Czgl.png)







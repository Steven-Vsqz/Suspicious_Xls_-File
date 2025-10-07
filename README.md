# Detected Suspicious Xls File Investigation

## 1. Incident Overview
I received an alert flagged as **“Detected Suspicious Xls File”** with a **Medium** severity rating. The alert indicated that a macro-enabled Excel file was executed on a user endpoint. My objective was to investigate the event, identify potential indicators of compromise, and determine if the activity was malicious or benign. The goal was to document the findings and assess whether containment or further remediation was required.

## 2. Tools & Technologies Used
- [**VirusTotal**](https://www.virustotal.com/gui/home/upload)
- [**IBM X-Force**](https://exchange.xforce.ibmcloud.com)
- [**Hybrid Analysis**](https://hybrid-analysis.com)
- [**Any Run**](https://app.any.run)
- [**Whois Lookup**](https://whois.domaintools.com)

## 3. Reviewing the Alert
**Alert Details:**
- **Event Time:** Mar 13, 2021, 08:20 PM  
- **Source Address:** 172.16.17.56  
- **Source Hostname:** Sofia  
- **File Name:** ORDER SHEET & SPEC.xlsm  
- **File Hash (MD5):** 7ccf88c0bbe3b29bf19d877c4596a8d4  
- **Device Action:** Allowed  


## 4. The Investigation
I began the investigation by submitting the file hash to **VirusTotal**, **IBM X-Force Exchange**, and **Hybrid Analysis** for verification. All sources confirmed the file as **malicious**, identifying it as a macro-enabled Excel document capable of executing embedded scripts upon opening.

<img width="1326" height="649" alt="vivaldi_Q40E7PDYUf" src="https://github.com/user-attachments/assets/aa0ff0d4-0da5-4ec2-9bfe-17534771f8b4" width="85%"/>
<br>
<img width="1540" height="624" alt="vivaldi_JA5YII2wrT" src="https://github.com/user-attachments/assets/d5bc404e-a460-4602-b0e2-b50a3d6352cc" width="85%"/>
<br>
<img width="1395" height="545" alt="vivaldi_7rMfDY6UWX" src="https://github.com/user-attachments/assets/612b9b61-3149-4a2d-8ce2-ca5e177d7c27" width="85%"/>

**Initial Indicators of Compromise (IOCs):**
- File type: Microsoft Excel Open XML Format document with macros enabled.
- Sha256 hash - `7bcd31bd41686c32663c7cabf42b18c50399e3b3b4533fc2ff002d9f2e058813`
- Behavior tags: *macros, auto-open, run-dll, executes-dropped-file.*  
- Destination IP observed during analysis: **177.53.143.89**  
- Domain: **multiwaretecnologia.com.br**  
- Associated process: *EXCEL.EXE → cscript.exe → EQNEDT32.EXE*
  
The file, *ORDER SHEET & SPEC.xlsm*, exhibited behavior consistent with downloader or dropper activity. Tags such as *auto-open* and *run-dll* suggested that the file could execute code automatically once opened by the user.

Since the EDR reported the device action as *Allowed*, I performed an endpoint inspection on host **Sofia (172.16.17.56)** to identify any abnormal processes or network connections. No suspicious local processes were active at that time.

<img width="1534" height="493" alt="vivaldi_paHwXd61CW" src="https://github.com/user-attachments/assets/f8519012-f1cf-46b7-9bd6-7f087771e07c" width="85%"/>

Next, I filtered network traffic in the SIEM platform to isolate communication to and from **172.16.17.56**. A connection attempt was observed to external IP **177.53.143.89** over port 443. The timestamp of the traffic matched the time of the initial alert, indicating possible **Command and Control (C2)** communication.

To validate the behavior, I uploaded the file to **Any.Run** for dynamic analysis. The sandbox report confirmed the execution of *EXCEL.EXE* spawning *cscript.exe* and *EQNEDT32.EXE*, along with outbound HTTPS traffic to **177.53.143.89** associated with domain *multiwaretecnologia.com.br*. The domain was linked to ASN **Brasil Site Informatica LTDA**, further confirming the connection originated from the infected process.

<img width="1815" height="870" alt="vivaldi_ZlCCXsptSn" src="https://github.com/user-attachments/assets/b1797e6b-5e33-473a-aaf1-57066ad3c8f7" width="85%"/>

I also verified the external IP and domain using **VirusTotal** and **Whois.domaintools**, which flagged them as malicious and previously associated with similar C2 infrastructure.

<img width="772" height="664" alt="vivaldi_wvpNUWgjjG" src="https://github.com/user-attachments/assets/e697f8f9-219f-4fda-919d-794f9f84cdee" width="85%"/>

Following the playbook for potential malware infection and confirmed C2 activity, I initiated **containment procedures** to isolate the affected system from the network and prevent further spread.

<img width="1172" height="565" alt="vivaldi_dgigNWeGfZ" src="https://github.com/user-attachments/assets/f9a7b904-fb0e-4640-b675-252e6a650004" width="85%"/>

## 5. Findings Summary
**Key Findings:**
- Malicious macro-enabled Excel file confirmed by multiple threat intelligence sources.  
- File exhibited auto-execution behavior using *cscript.exe* and *EQNEDT32.EXE*.  
- Outbound traffic to known malicious IP **177.53.143.89** via HTTPS.  
- Indicators consistent with command-and-control communication.  
- Endpoint containment initiated as a precautionary measure.

**Final Assessment:**
The investigation confirmed that the Excel document *ORDER SHEET & SPEC.xlsm* was **malicious**. The file executed embedded macros that launched scripting engines and attempted outbound connections to a known malicious domain. The activity aligns with malware using Excel macros as an initial infection vector to establish persistence and external communication.  
The affected endpoint was isolated to contain the potential threat, and further forensic review was recommended to ensure no lateral movement or secondary payloads were deployed.

---

<br>
<!-- To insert an image -->
<!-- ![Description](image-path.png) -->

<!-- To create a table -->
<!-- | Column 1 | Column 2 | Column 3 |
|----------|----------|----------|
| Value 1 | Value 2 | Value 3 | -->

<!-- To create a code block -->
<!-- ```bash
command or script here
``` -->

<!-- To create a link -->
<!-- [Link Text](https://example.com) -->

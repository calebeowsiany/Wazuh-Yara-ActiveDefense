# Wazuh-Yara-ActiveDefense
Complete Wazuh and Yara integration with automated malware response—remove or quarantine threats in real time.

I present two options for active response using Yara against malware files.
You can choose to either delete malware files immediately or move them to a quarantine folder for later inspection.

The scripts used here are variations of the VirusTotal active response script, as documented in Wazuh’s official guide: https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html<br>
The Yara integration configuration follows Wazuh’s official documentation almost exactly: https://documentation.wazuh.com/current/proof-of-concept-guide/detect-malware-yara-integration.html<br>
The only difference is that I installed it in /opt/ on Linux. The configuration for Windows remains identical. (I won't be showing how to integrated Yara to Wazuh, please follow the documentation above)
<br>
<br>
<br>
🚀 HOW IT WORKS

With Yara integration already set up, when a malicious file is detected, rule 108001 (Yara scan default) triggers.
This, in turn, activates an active response script: either "remove-threat*" or "quarantine-threat*" (depending on your chosen approach).

Since these scripts are mapped to rule 108001 in ossec.conf, they will automatically execute upon detection.

    If using the removal approach, the malware file is deleted.
    If using the quarantine approach, the file is moved to a designated quarantine folder.

After the action is taken, an event appears in the Wazuh console, detailing the malware’s location and the response executed.

For both Linux and Windows, the same Yara rule IDs are used (except for File Integrity Monitoring (FIM) paths, which are platform-specific). Since Yara integration rules are setup only on the Wazuh manager, there's no need to create separate configurations for Windows and Linux.
<br>
<br>
<br>
🔧 SETUP

1️⃣ Choose your preferred approach (remove or quarantine).<br>
2️⃣ Copy the relevant files to your environment.<br>
3️⃣ Adjust the FIM paths and rule IDs to match your setup.<br>
4️⃣ If you modify the Yara integration rule ID, Yara scan rule ID, or active response script IDs, ensure you update the corresponding Wazuh rules.<br>
<br>
<br>
<br>
🎬 DEMONSTRATION

✅ Linux malware removal
![yara malware removal - linux](https://github.com/user-attachments/assets/57c64204-0b79-4c62-ba47-b55493d4994c)

✅ Windows malware removal
![yara malware removal - windows](https://github.com/user-attachments/assets/e28e0ed2-f29f-4e8b-94ee-39c2b92461f7)

✅ Linux malware quarantining
![yara quarantining linux files - detection](https://github.com/user-attachments/assets/11de13f2-09dd-4292-b4d1-ae878a874074)
![quarantined files -  linux](https://github.com/user-attachments/assets/ee1f1c95-7848-4e77-9ffd-b267c55f451c)

✅ Windows malware quarantining
![yara quarantining files - windows](https://github.com/user-attachments/assets/24079d1a-5cf1-4d0e-86fd-ad231d2ebab5)
![quarantined files - windows](https://github.com/user-attachments/assets/e636f858-0fb5-46ee-8acd-6e11425ce2a4)








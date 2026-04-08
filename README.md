# 🔐 Brute Force Detection using Splunk

## 📌 Objective
To detect brute-force login attempts by analyzing Windows Security Event Logs.

---

## 📊 Data Used
- **Event ID 4625** → Failed login attempts  
- **Event ID 4624** → Successful login  

---

## 🔍 Detection Logic
A brute-force attack is identified when:
- Multiple failed login attempts occur  
- Followed by a successful login  
- From the same user and source IP  

---

## 🛠 Tools Used
- Splunk Enterprise  
- Windows Event Logs  

---

## 📈 Query Used
```spl
source="WinEventLog:Security" EventCode IN (4624,4625)
| stats count(eval(EventCode=4625)) as failed_attempts 
        count(eval(EventCode=4624)) as success_attempts 
        by Account_Name, Source_Network_Address
| where failed_attempts > 5 AND success_attempts > 0
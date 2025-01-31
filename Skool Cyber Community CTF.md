# Cyber Range APT Investigation Report

![Screenshot 2025-01-30 195201](https://github.com/user-attachments/assets/098902db-c93d-488a-963d-52d82c55633d)


## 1st Task: Identify the Compromised Host

### **Task:**
Discover and submit the name of the host within the Cyber Range that was compromised by the APT.

### **Analysis:**
Based on the given information, we know that the APT "Jackal Spear" originates from South Africa and occasionally operates in Egypt. Their attack methods include **spear-phishing campaigns** and **credential stuffing**. When they compromise an account, they establish persistence by creating an account with a **similar username**.

To understand **credential stuffing**, I referenced the **Mitre ATT&CK Framework** to research different **TTPs (Tactics, Techniques, and Procedures)** used in such attacks. Since the information states that the APT creates accounts with similar usernames, I searched for **newly created accounts with names similar to existing accounts**.

### **Query Used:**
```kql
DeviceEvents
| where ActionType contains "UserAccountCreated" 
| project Timestamp, DeviceName, ActionType, AccountName, InitiatingProcessAccountName
```


![First Query](https://github.com/user-attachments/assets/aea59d3a-b51b-4bd7-8d0f-54d9ec26eaff)


### **Findings:**
As shown in the picture above, I found that the compromised host was **"corpnet-1-ny"**, where an account named **"chadwick.s"** was created by a user **"chadwicks"**, which appeared suspicious.

---

## 2nd Task: Identify the Attacker's Public IP Address

### **Task:**
Determine the **public IP address** of the attacker.

### **Query Used:**
```kql
DeviceLogonEvents
| where DeviceName contains "corpnet-1-ny"
| where AccountName contains "chadwick.s"
| project Timestamp, DeviceName, AccountName, RemoteIP
```

![Task2](https://github.com/user-attachments/assets/e0369087-716c-423e-ab4e-b978e5bcfc90)


### **Findings:**
The newly created user **"chadwick.s"** logged in using the public IP **102.37.140.95**, which is geolocated in **South Africa**, one of the known regions where "Jackal Spear" operates.


![Task2 1](https://github.com/user-attachments/assets/463dc4be-e927-42f5-953d-b9477970b245)


---

## 3rd Task: Identify Login Attempts Before Success

### **Task:**
Determine how many login attempts the attacker made before successfully logging in.

### **Query Used:**
```kql
DeviceLogonEvents
| where RemoteIP contains "102.37.140.95"
| where ActionType contains "LogonFailed"
| count
```

### **Findings:**
This query helped count the number of failed login attempts from the attacker's IP before a successful login which is 14.

---

## 4th Task: Identify the Created Account

### **Task:**
Find the **account created on the local machine**.

### **Findings:**
Using the first query, we already determined that the attacker created the **"chadwick.s"** account.

---

## 5th Task: Identify Stolen Files

### **Task:**
Name one of the **files likely stolen** by the attacker while logged into the new account.


To understand this I was looking if there are any sensitive data that could be valuable to the attacker on the suspected device and I found out that the newly created account viewed sensitive files regarding CRISPR Research.


### **Query Used:**
```kql
DeviceEvents
| where DeviceName contains "corpnet-1-ny"
| where InitiatingProcessAccountName contains "chadwick.s"
| where ActionType contains "SensitiveFileRead"
```

![Task 5](https://github.com/user-attachments/assets/596b5ba4-694c-47b9-8a63-f4826c899d35)


Upon further investigation:
```kql
DeviceFileEvents
| where DeviceName contains "corpnet-1-ny"
| where InitiatingProcessAccountName contains "chadwick.s"
| where FileName has_any (".zip", "pdf")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
```
![image](https://github.com/user-attachments/assets/b899c6e8-7bcf-46a6-8f95-c0082ddf3cf2)


### **Findings:**
The newly created account **"chadwick.s"** accessed sensitive files related to **CRISPR Research**. The user created a **zip file** named:

📂 `C:\Users\chadwicks\Documents\CRISPR Research\gene_editing_papers.zip`

Further queries showed that the user also downloaded and installed **7zip.exe** and **OneDrive.exe**, likely used to **compress and exfiltrate** the data.

The answer to this task was **any of the sensitive files** contained in the zip archive.

---

## 🏆 **Final Flag & CTF Placement**

The flag obtained:  
`f6952d6eef555ddd87aca66e56b91530222d6e318414816f3ba7cf5bf694bf0f`

Placed **2nd in the CTF Competition**. 🎉



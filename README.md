\# 🛡️ AI-Powered SOC Alert Analyzer



A local-first Security Operations Center (SOC) platform for collecting Windows Security Events, detecting suspicious authentication activity, managing security alerts, and assisting analysts with AI-powered investigation.



The project combines \*\*Windows Event Log monitoring, rule-based threat detection, FastAPI, SQLite, React, and local Ollama/Llama 3.2 AI\*\* into a single SOC dashboard.



> \*\*Project status:\*\* Educational / portfolio prototype  

> \*\*Environment:\*\* Windows 11 + local development environment



\---



\## 📌 Overview



Security Operations Centers receive large numbers of security events that need to be monitored, filtered, investigated, and prioritized.



This project demonstrates a simplified SOC workflow:



```text

Windows Security Events

&#x20;       ↓

Windows Event Collector

&#x20;       ↓

Durable SQLite Event Queue

&#x20;       ↓

Rule-Based Detection Engine

&#x20;       ↓

Security Alert

&#x20;       ↓

FastAPI Backend

&#x20;       ↓

React SOC Dashboard

&#x20;       ↓

AI-Assisted Investigation

&#x20;       ↓

SOC Analyst Review

```



The detection engine handles the security rules deterministically, while the local AI layer assists with alert investigation and explanation.



\---



\## 🎯 Project Objectives



\- Monitor Windows Security authentication events

\- Collect Windows Event IDs \*\*4624\*\* and \*\*4625\*\*

\- Detect repeated failed authentication attempts

\- Detect potential brute-force activity

\- Store events using a durable SQLite queue

\- Prevent duplicate Windows events from being processed

\- Generate and manage SOC alerts

\- Provide a real-time dashboard for analysts

\- Allow analysts to investigate alerts using local AI

\- Keep AI inference local through Ollama



\---



\## ✨ Key Features



\### 🪟 Windows Security Event Monitoring



The collector uses PowerShell `Get-WinEvent` to retrieve Windows Security events.



Currently monitored events include:



| Event ID | Meaning |

|---|---|

| \*\*4624\*\* | Successful logon |

| \*\*4625\*\* | Failed logon |



The collector extracts useful fields such as:



\- Event ID

\- Record ID

\- Timestamp

\- Event type

\- Username

\- Source IP

\- Logon type

\- Status

\- Process

\- Computer name



\---



\### 🔎 Rule-Based Threat Detection



The Windows detection engine analyzes failed authentication events using a time-based detection window.



Current detection logic:



| Condition | Detection | Severity |

|---|---|---|

| 3+ failed logons within 5 minutes | Repeated Failed Login Attempts | MEDIUM |

| 5+ failed logons within 5 minutes | Possible Brute-Force Attack | HIGH |



The detector groups failed logons by source IP and evaluates their timestamps within the configured detection window.



Loopback and invalid source addresses are excluded from the detection logic.



\---



\### 🗄️ Durable Event Queue



Windows events are placed into a SQLite-backed queue before processing.



The queue provides:



\- Persistent event storage

\- Duplicate prevention

\- Pending/processed states

\- Record ID tracking

\- Recovery if the worker stops

\- Separation between collection and detection



This allows the collector and detection worker to operate as separate stages.



\---



\### ⚙️ SOC Worker



The Windows SOC worker periodically:



1\. Collects recent Windows Security events

2\. Adds new events to the SQLite queue

3\. Reads recent event history

4\. Runs the Windows detection engine

5\. Generates security alerts

6\. Saves alerts to SQLite

7\. Marks processed queue events



The worker can run continuously or execute a single processing cycle.



\---



\### 📊 SOC Dashboard



The React dashboard provides visibility into:



\- Total alerts

\- Critical alerts

\- High severity alerts

\- Medium severity alerts

\- Low severity alerts

\- Resolved alerts

\- Alert status

\- Source IP

\- Failed attempts

\- Alert timestamps

\- Recent activity

\- Threat distribution

\- Top alert types

\- Severity breakdown

\- Alert trend over the last 24 hours



The dashboard automatically refreshes alert data from the backend.



\---



\### 🤖 Local AI Investigation



The project uses:



\- \*\*Ollama\*\*

\- \*\*Llama 3.2\*\*



for local AI-assisted security alert analysis.



The AI layer is intended to help the analyst understand an alert, summarize suspicious activity, and provide investigation context.



The AI does \*\*not\*\* replace deterministic detection or the human analyst.



\---



\## 🏗️ Architecture



```text

┌──────────────────────────────┐

│      Windows 11 Endpoint     │

│                              │

│    Windows Security Log      │

│      4624 / 4625 Events      │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              │ Get-WinEvent

&#x20;              ▼

┌──────────────────────────────┐

│   Windows Live Collector     │

│                              │

│ windows\_live\_collector.py    │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              ▼

┌──────────────────────────────┐

│       SQLite Event Queue     │

│                              │

│  PENDING → PROCESSED         │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              ▼

┌──────────────────────────────┐

│      SOC Detection Worker    │

│                              │

│ windows\_soc\_worker.py        │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              ▼

┌──────────────────────────────┐

│   Windows Detection Engine   │

│                              │

│ windows\_time\_detection.py    │

│                              │

│  4625 → time-window rules    │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              ▼

┌──────────────────────────────┐

│       Alert Database         │

│           SQLite             │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              ▼

┌──────────────────────────────┐

│       FastAPI Backend        │

│                              │

│ REST API + Authentication    │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              ▼

┌──────────────────────────────┐

│      React / Vite UI         │

│                              │

│       SOC Dashboard          │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              ▼

┌──────────────────────────────┐

│     Ollama + Llama 3.2       │

│                              │

│   AI-Assisted Investigation  │

└──────────────────────────────┘

```



\---



\## 📂 Project Structure



```text

AI-SOC-Alert-Analyzer/

│

├── backend/

│   ├── ai\_analyzer.py

│   ├── database.py

│   ├── detection.py

│   ├── main.py

│   ├── severity.py

│   ├── windows\_detection\_adapter.py

│   ├── windows\_event\_parser.py

│   ├── windows\_live\_collector.py

│   ├── windows\_soc\_worker.py

│   ├── windows\_time\_detection.py

│   │

│   ├── check\_windows\_queue.py

│   ├── test\_powershell.py

│   ├── test\_queued\_bruteforce.py

│   ├── test\_windows\_queue.py

│   └── test\_worker\_bruteforce.py

│

├── frontend/

│   ├── src/

│   │   ├── App.jsx

│   │   ├── App.css

│   │   ├── index.css

│   │   └── main.jsx

│   │

│   ├── public/

│   ├── package.json

│   ├── package-lock.json

│   └── vite.config.js

│

├── data/

│   └── Local runtime data

│

├── database/

│   └── Local SQLite database

│

├── .gitignore

└── README.md

```



> Local databases and generated security-event data are intentionally excluded from version control.



\---



\## 🧰 Technology Stack



| Technology | Purpose |

|---|---|

| Python | Backend and security detection |

| FastAPI | REST API |

| SQLite | Alert and event storage |

| PowerShell | Windows Security Event collection |

| React | SOC dashboard |

| Vite | Frontend development/build tooling |

| Ollama | Local AI runtime |

| Llama 3.2 | Local AI model |

| HTML/CSS | Dashboard interface |

| Git/GitHub | Version control |



\---



\## 🔐 Authentication



The FastAPI backend includes authentication for the SOC dashboard and protected API operations.



Authentication uses:



\- Session-based authentication

\- API token validation

\- Environment variables for secrets

\- CORS configuration for the local frontend



Secrets should never be committed to GitHub.



Create a local environment configuration containing values such as:



```env

SESSION\_SECRET=your-random-session-secret

SOC\_API\_TOKEN=your-local-api-token

FRONTEND\_ORIGIN=http://localhost:5173

```



Never commit the actual `.env` file.



\---



\## 🚀 Local Setup



\### 1. Clone the repository



```bash

git clone https://github.com/sachinpujari05/AI-SOC-Alert-Analyzer.git

cd AI-SOC-Alert-Analyzer

```



\---



\### 2. Create a Python virtual environment



From the project root:



```powershell

cd backend

python -m venv .venv

```



Activate it:



```powershell

.venv\\Scripts\\Activate.ps1

```



\---



\### 3. Install backend dependencies



Install the Python packages required by the backend.



For example:



```powershell

pip install fastapi uvicorn requests python-multipart

```



If additional packages are required by the current backend environment, install those as well.



\---



\### 4. Configure environment variables



Set the local authentication values:



```powershell

$env:SESSION\_SECRET="replace-with-a-random-secret"

$env:SOC\_API\_TOKEN="replace-with-your-local-token"

```



For example, during local development:



```powershell

$env:SESSION\_SECRET="dev-session-secret"

$env:SOC\_API\_TOKEN="your-local-token"

```



Do not use development credentials in a publicly exposed deployment.



\---



\## ▶️ Start the Backend



From the `backend` directory:



```powershell

python -m uvicorn main:app --reload

```



The API will be available at:



```text

http://127.0.0.1:8000

```



FastAPI interactive documentation:



```text

http://127.0.0.1:8000/docs

```



\---



\## ▶️ Start the Frontend



Open a second terminal:



```powershell

cd frontend

npm install

npm run dev

```



The Vite development server will normally be available at:



```text

http://localhost:5173

```



\---



\## 🪟 Windows Event Collection



The collector reads Windows Security events using PowerShell.



Run the collector from the backend directory:



```powershell

python windows\_live\_collector.py

```



For access to the Windows Security event log, the terminal may need to be running with Administrator privileges.



The collector retrieves recent Event IDs:



```text

4624

4625

```



and places new events into the SQLite event queue.



\---



\## ⚙️ Start the SOC Worker



Run one processing cycle:



```powershell

python windows\_soc\_worker.py --once

```



Run continuous monitoring:



```powershell

python windows\_soc\_worker.py

```



The worker continuously polls Windows Security Events and processes new events.



\---



\## 🧪 Detection Testing



The project includes tests for the Windows event queue and brute-force detection workflow.



Examples:



```powershell

python test\_queued\_bruteforce.py

```



and:



```powershell

python test\_worker\_bruteforce.py

```



The brute-force integration test creates synthetic failed-login events and verifies that the system can:



```text

Insert events

&#x20;    ↓

Queue events

&#x20;    ↓

Detect brute-force activity

&#x20;    ↓

Generate HIGH severity alert

&#x20;    ↓

Save alert

&#x20;    ↓

Process queue events

```



\---



\## 🔍 Example Detection



Five failed Windows authentication events from the same source within the configured time window can produce:



```text

Alert Type:     Possible Brute-Force Attack

Severity:       HIGH

Source IP:      192.0.2.99

Failed Attempts: 5

```



The detection is based on event timestamps rather than the time at which the event happened to be inserted into the queue.



\---



\## 📈 Alert Lifecycle



```text

Windows Event

&#x20;    ↓

Collected

&#x20;    ↓

Queued

&#x20;    ↓

Detection

&#x20;    ↓

Alert Generated

&#x20;    ↓

Alert Stored

&#x20;    ↓

Dashboard

&#x20;    ↓

Analyst Investigation

&#x20;    ↓

Resolved / Updated

```



\---



\## 🧠 Detection vs AI



The project separates security detection from AI-assisted analysis.



\### Detection Engine



The detection engine uses explicit security rules:



```text

Known event

&#x20;   ↓

Detection rule

&#x20;   ↓

Threshold

&#x20;   ↓

Severity

&#x20;   ↓

Alert

```



\### AI Layer



The AI layer assists with:



```text

Alert

&#x20;  ↓

Context

&#x20;  ↓

Local LLM

&#x20;  ↓

Investigation assistance

```



This separation helps prevent an LLM from being the only component responsible for deciding whether a security event should generate an alert.



\---



\## 🛡️ Security Considerations



This project is designed for authorized lab and educational environments.



Do not commit:



\- API keys

\- Passwords

\- Authentication tokens

\- `.env` files

\- SQLite databases

\- Private logs

\- Real security event data

\- Private keys

\- Personal information



The repository's `.gitignore` excludes local databases and generated event data.



\---



\## ⚠️ Current Limitations



This project is currently a portfolio/educational prototype rather than a production SOC platform.



Current limitations include:



\- Windows-focused event collection

\- Limited detection rules

\- Local SQLite storage

\- Local development authentication

\- Limited event sources

\- No enterprise-scale event ingestion

\- No distributed worker architecture

\- No production-grade secrets management

\- No automated containment

\- AI analysis requires analyst validation

\- Detection coverage is much smaller than a commercial SIEM



\---



\## 🔮 Future Improvements



Planned improvements include:



\- Additional Windows Event ID detections

\- Sysmon integration

\- MITRE ATT\&CK mapping

\- IOC extraction

\- Threat-intelligence enrichment

\- Alert correlation

\- False-positive reduction

\- Advanced authentication anomaly detection

\- Email/notification integration

\- SOAR capabilities

\- Role-based access control

\- PostgreSQL support

\- Docker deployment

\- Production logging and monitoring

\- Automated incident reports

\- Expanded AI investigation workflows



\---



\## 🎓 Skills Demonstrated



This project demonstrates practical experience with:



\- SOC monitoring

\- Security alert triage

\- Windows Security Events

\- Authentication-event analysis

\- Brute-force detection

\- Detection engineering

\- Python

\- FastAPI

\- REST APIs

\- SQLite

\- React

\- Vite

\- PowerShell

\- Local LLMs

\- Ollama

\- AI-assisted security analysis

\- Git

\- GitHub

\- Software architecture

\- Security automation



\---



\## 📌 Project Goal



The goal of this project is to build practical experience in the technologies and workflows used by modern SOC teams.



The project focuses on the complete lifecycle:



```text

COLLECT

&#x20;  ↓

QUEUE

&#x20;  ↓

DETECT

&#x20;  ↓

ALERT

&#x20;  ↓

INVESTIGATE

&#x20;  ↓

ANALYZE

&#x20;  ↓

RESPOND

```



The final security decision remains with the human analyst.



\---



\## ⚖️ Disclaimer



This project is intended for:



\- Educational purposes

\- Cybersecurity learning

\- SOC analyst practice

\- Authorized security testing

\- Local security monitoring laboratories



Only monitor systems and security logs that you are authorized to access.



\---



\## 👤 Author



\*\*Sachin Pujari\*\*



Computer Engineering Student  

Interested in Cybersecurity, SOC Operations, Detection Engineering, and AI-assisted Security.



\### GitHub



https://github.com/sachinpujari05



\---



\## ⭐ If you find this project useful



Feel free to explore the repository, review the detection logic, and experiment with the project in an authorized lab environment.


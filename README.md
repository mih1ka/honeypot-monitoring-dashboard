# Honeypot Monitoring System

## Overview
The **Honeypot Monitoring System** is a lightweight Python and Flask-based project designed to simulate a vulnerable service that logs connection attempts. It captures details such as **source IP address, destination port, payload, and location**, storing them in an **SQLite database**. The system also provides a **real-time monitoring dashboard** that visualizes attacks, displays statistics, and helps analyze suspicious activity.

---

## Problem Statement
In modern networks, **cyber attacks often go undetected** until serious damage occurs. Network administrators need a **simple and effective way** to monitor, detect, and analyze unauthorized access attempts. Traditional intrusion detection systems can be **complex or expensive**, particularly for small organizations or students.

---

## Proposed Solution
This project implements a **low-interaction honeypot** that:

- Listens for incoming network requests.
- Records attack data in a database.
- Displays the collected data on a **Flask-based web dashboard** with:
  - Statistics
  - Attack graphs
  - Event logs  

This approach allows for **easy visualization and analysis** of suspicious activity.

---

## Features

- **Connection Capture:** Logs every incoming connection attempt with:
  - Source IP
  - Destination port
  - Payload
- **Database Storage:** Uses **SQLite** for lightweight and reliable event storage.
- **Dashboard Visualization:** Interactive dashboard showing:
  - Total events recorded
  - Unique IPs detected
  - Attack frequency by port
  - Recent attack events table
- **Attack Analytics:**  
  - Bar chart of attack counts by port  
  - Optional pie chart by country
- **System Health Status:** Displays connection and activity indicators.
- **Lightweight & Portable:** Works on any system with Python installed.

---

## Project Structure

honeypot-project/
│
├── src/
│ ├── honeypot.py # Main honeypot script (captures events)
│ ├── dashboard.py # Flask dashboard for visualization
│ ├── utils.py # Helper functions (optional)
│ ├── logs/
│ │ └── honeypot.db # SQLite database storing event logs
│ └── templates/
│ └── dashboard.html # Dashboard frontend (HTML template)
│
├── requirements.txt # Python dependencies
├── README.md # Project documentation
└── .gitignore # Ignored files and directories


---

## Technologies Used

- **Python 3**
- **Flask** (Web Framework)
- **SQLite** (Database)
- **Matplotlib** (Data Visualization)
- **Bootstrap / HTML** (Frontend Design)

---

## Installation and Setup

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/honeypot-monitoring-system.git
cd honeypot-monitoring-system
2. Create and Activate a Virtual Environment

Windows:

python -m venv venv
venv\Scripts\activate


Linux/Mac:

python -m venv venv
source venv/bin/activate

3. Install Dependencies
pip install -r requirements.txt

4. Run the Honeypot
cd src
python honeypot.py


This will start listening for incoming connections and recording them in the database.

5. Run the Dashboard

Open a new terminal in the same folder:

python dashboard.py


Then visit: http://127.0.0.1:5000
 to view the monitoring dashboard.

Output Preview

Dashboard Metrics: Total events, unique IPs, recent attacks

Attack Graph: Bar chart showing frequency of attacks per port

Event Table: Displays timestamp, source IP, port, and payload

Health Indicators: Shows database connection status and last update

Future Enhancements

Integration with an external threat intelligence API for IP geolocation

Real-time alert system via email or Telegram for new attacks

Advanced analytics dashboard with filtering and search options

Cloud deployment for continuous monitoring

Author

Mihika Manish
This project was developed as part of my Computer Networks course.

# Honeypot Monitoring System
A real-time cybersecurity monitoring system that simulates vulnerable services to detect, log, and visualize unauthorized access attempts. Designed for network security monitoring, threat intelligence, and educational purposes.

## Overview

The Honeypot Monitoring System is a comprehensive security tool that:
- Simulates vulnerable services to attract potential attackers
- Captures detailed attack data including IPs, ports, and payloads
- Visualizes threats through an interactive real-time dashboard
- Stores intelligence in a structured database for analysis

Ideal for security researchers, network administrators, students, and anyone interested in understanding attack patterns.

## Key Features

### Threat Detection
- Real-time connection monitoring on multiple ports
- Payload capture and analysis
- IP geolocation mapping with country detection
- Comprehensive logging of all connection attempts

### Analytics & Visualization
- Interactive dashboard with real-time updates
- Attack trend analysis over time
- Top attacker IPs identification
- Geographic attack distribution maps
- Port-based attack statistics

### System Capabilities
- Lightweight and portable - runs anywhere Python is installed
- SQLite database for reliable data storage
- RESTful API ready for extensions
- Health monitoring with status indicators
- Responsive design works on desktop and mobile

## Project Structure
honeypot-monitoring-dashboard/
│
├── src/
│ ├── honeypot.py # Main honeypot service
│ ├── app.py # Flask dashboard application
│ ├── static/
│ │ └── css/
│ │ └── dashboard.css # Custom styling
│ └── templates/
│ └── dashboard.html # Dashboard template
│
├── logs/
│ └── honeypot.db # SQLite database
│
├── requirements.txt # Dependencies
├── README.md # Documentation
└── .gitignore # Git exclusions


## Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/mih1ka/honeypot-monitoring-dashboard.git
   cd honeypot-monitoring-dashboard

2. Set up virtual environment
   # Create virtual environment
    python -m venv venv
    # Activate environment
    # On Windows:
    venv\Scripts\activate
    # On Linux/Mac:
    source venv/bin/activate
    
3. Install dependencies
    pip install -r requirements.txt
4. Start the honeypot :The honeypot will start listening for connections
    cd src
    python honeypot.py
5. Launch the dashboard (in a new terminal)
    cd src
    python app.py
6. Access the dashboard
    Open your browser and navigate to: http://127.0.0.1:5000

## Usage Examples
### Production Monitoring
- Detect unauthorized access attempts
- Monitor network perimeter security
- Gather threat intelligence data

### Research & Development
- Test security monitoring tools
- Develop new detection algorithms
- Academic cybersecurity research

## Future Enhancements

### Planned Features
- Email/Telegram alerts for critical attacks
- Advanced threat intelligence integration
- Multi-honeypot deployment support
- REST API for external integrations
- Cloud deployment options (AWS, Azure, GCP)

### Advanced Analytics
- Machine learning anomaly detection
- Attack correlation engine
- Threat scoring system
- Custom report generation

## Author

**Mihika Manish**
- GitHub: [@mih1ka](https://github.com/mih1ka)
- Project: [Honeypot Monitoring Dashboard](https://github.com/mih1ka/honeypot-monitoring-dashboard)

Developed as part of Computer Networks coursework to demonstrate practical cybersecurity monitoring techniques.








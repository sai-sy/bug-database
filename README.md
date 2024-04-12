# Bug Database

Authors: Saihaan, Arya, Rohith, Sarthak, Khang

## How to Run

### Activate Virtual Environment

#### Linux/WSL/MacOS

```bash
python3 -m venv virt
source virt/bin/activate
```

#### Windows

```bash
python -m venv virt
source virt/Scripts/activate
```

#### How to turn off virtual environment when you're done:

```bash
deactivate
```

### Install Python Dependencies and Initalize Environment Variables, then run project

```bash
pip install -r requirements.txt
export FLASK_APP=wsgi.py
export FLASK_ENV=development
flask run --debug
```

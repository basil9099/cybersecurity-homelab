# Python Anomaly Detector for Splunk Log Exports

A lightweight machine learning-based anomaly detection tool for identifying suspicious login behavior from Splunk-exported CSV logs.

---

## Project Structure

```
splunk-anomaly-detector/
├── main.py
├── preprocess.py
├── detect.py
├── data/
│   └── logins.csv
├── screenshots/
│   └── *.png
```

---

## How It Works

1. **Preprocessing**
   - Converts timestamps into hourly features
   - Encodes usernames and source IPs numerically
   - Prepares features for model input
   _(see `01_preprocess-script.png`)_

2. **Detection**
   - Uses `IsolationForest` to detect outliers in login behavior
   - Flags logins by rare users, IPs, or times
   _(see `02_detect-script.png`)_

3. **Execution**
   - Combines both steps in `main.py`
   - Prints anomalies in a clear table format
   _(see `03_main-script.png` and `04_script-output.png`)_

4. **Input Format**
   - CSV with columns: `timestamp`, `Account Name`, `Source IP`, `EventCode`
   _(see `05_sample-logs.png`)_

---

## Example Run

```bash
python3 main.py
```

Sample output:

```
[!] Anomalous Logins Detected:
Timestamp           Account Name  Source IP      ...
2025-08-04 02:40:00 guest         172.16.0.5     ...
2025-08-04 03:06:00 user1         192.168.1.13   ...
```

---

## Dependencies

```bash
pip install pandas scikit-learn
```

---

## Future Ideas

- CLI argument for file path input
- Output to JSON or CSV
- REST API wrapper
- Dockerize and schedule via cron

---

See `/screenshots` for step-by-step visuals of this tool in use.

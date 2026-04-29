# Intelligent Cyber Threat Detection System (ICTDS)

An end-to-end machine learning-based web application designed to detect and classify cyber threats in network traffic. The system uses a dual-model ensemble approach (Random Forest and Gradient Boosting) to analyze network flows and categorize them into benign or various attack types (DoS, Probe, R2L, U2R).

## 🌟 Features

- **Machine Learning Engine**: Ensemble model combining Random Forest and Gradient Boosting for high accuracy.
- **Support for Real Datasets**: Natively supports the CIC-IDS 2017 dataset.
- **Synthetic Data Fallback**: Automatically generates synthetic network traffic data for training and testing if real datasets are not provided.
- **Web Dashboard**: Interactive Flask-based dashboard to visualize threat statistics, recent logs, and system health.
- **CSV Analysis**: Upload network traffic data (CSV) to analyze and predict threats in real-time.
- **User Authentication**: Secure login and registration system using SQLite.

## 💻 Tech Stack

- **Backend**: Python, Flask
- **Database**: SQLite
- **Machine Learning**: scikit-learn, pandas, numpy
- **Frontend**: HTML, CSS, JavaScript (Jinja2 Templates)

## 🛠️ Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## 🚀 Installation & Setup

1. **Navigate to the project directory**:
   ```bash
   cd d:\ictds
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   # On Windows
   venv\Scripts\activate
   ```

3. **Install the dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:
   ```bash
   python app.py
   ```
   Alternatively, on Windows, you can simply run the provided batch script:
   ```cmd
   Run.bat
   ```

5. **Access the application**:
   Open your web browser and navigate to `http://localhost:5001`.

## 📊 Dataset Configuration (CIC-IDS 2017)

By default, the system will generate synthetic data for training if no dataset is provided. To achieve high accuracy (~97%), it is recommended to use the real CIC-IDS 2017 dataset.

1. Download the dataset from [UNB CIC-IDS 2017](https://www.unb.ca/cic/datasets/ids-2017.html).
2. Click on "MachineLearningCVE" and download the CSV files.
3. Create a folder named `cicids` inside the `data` directory (`d:\ictds\data\cicids\`).
4. Copy the downloaded CSV files into this folder.
5. Delete the existing trained model to force a retrain:
   ```bash
   del model\model.pkl
   ```
6. Restart the application (`python app.py`). The system will automatically detect the dataset, train the models, and save the new `.pkl` file.

## 📂 Project Structure

```text
ictds/
│
├── app.py                  # Main Flask application and routes
├── requirements.txt        # Python dependencies
├── Run.bat                 # Windows batch script to start the app
├── ictds.db                # SQLite database (auto-generated)
│
├── data/                   # Directory for storing datasets
│   └── cicids/             # Place CIC-IDS 2017 CSV files here
│
├── model/                  # Machine learning models and logic
│   ├── threat_model.py     # Core ML logic, training, and prediction
│   └── model.pkl           # Serialized trained model (auto-generated)
│
├── templates/              # HTML templates for the web interface
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── analyse.html
│   └── logs.html
│
└── venv/                   # Python virtual environment
```

## 👥 Team Members

- Saranya A.
- Uma M.
- Thanzim P.

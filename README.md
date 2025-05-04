# Data Security Project
## Project Folder Structure

Below is the **required folder and file layout**.  
The `data/` and `real_data/` folders are **required** but will be **provided separately** due to file size.  
They must be placed **exactly as shown** before running any notebooks.
> Note: The `cleaned_cic.csv` file is **generated automatically** and does not need to be placed manually.
```bash
dataset_project/
│
├── data/ # REQUIRED (NOT ON GITHUB)
│ ├── cleaned_cic.csv # GENERATED automatically
│ ├── Friday-WorkingHours-Afternoon-DDoS.pcap_ISCX.csv
│ ├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
│ ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
│ ├── Monday-WorkingHours.pcap_ISCX.csv
│ ├── Thursday-WorkingHours-Afternoon-Infiltration.pcap_ISCX.csv
│ ├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
│ ├── Tuesday-WorkingHours.pcap_ISCX.csv
│ └── Wednesday-WorkingHours.pcap_ISCX.csv
│
├── real_data/ # REQUIRED (NOT ON GITHUB)
│ ├── attack/
│ │ ├── nmap_attack_traffic_20250412_200758.pcap
│ │ ├── nmap_attack_traffic.csv
│ │ ├── synthetic_attack_1.pcap
│ │ ├── synthetic_attack_1.csv
│ │ └── extract_attack_features.py
│ │
│ ├── benign/
│ │ ├── real_benign_1GB.pcap
│ │ ├── real_benign_1GB.csv
│ │ ├── real_benign_70MB.pcap
│ │ ├── real_benign_70MB.csv
│ │ ├── real_benign_400BG.pcap
│ │ ├── real_benign_400BG.csv
│ │ ├── synthetic_benign_1.pcap
│ │ ├── synthetic_benign_1.csv
│ │ ├── synthetic_benign_2.pcap
│ │ ├── synthetic_benign_2.csv
│ │ └── extract_benign_features.py
│ │
│ └── test_1/
│ ├── synthetic_attack_1.csv
│ └── synthetic_benign_1.csv
│
├── models/ # GENERATED automatically
│ ├── 1_first_model/
│ │ ├── forest_model.joblib
│ │ └── scaler.joblib
│ ├── 2_first_tuning/
│ │ ├── iforest_tuned.joblib
│ │ └── tuning_summary.csv
│ ├── 3_aggressive_tuned/
│ │ ├── iforest_aggressive.joblib
│ │ ├── threshold_info.joblib
│ │ └── aggressive_summary.csv
│ ├── 4_supervised_rf/
│ │ └── model.joblib
│ └── 5_supervised_real_traffic_test/
│ └── model.joblib
│
├── notebooks/
│ ├── 1_Model_Start/
│ │ ├── 1_model.ipynb
│ │ ├── 2_forest_tuning.ipynb
│ │ └── 3_advanced_tuning.ipynb
│ ├── 2_Real_Data/
│ │ └── 4_real_data_checking.ipynb
│ ├── 3_Supervised/
│ │ ├── 1_supervised_initial.ipynb
│ │ └── 2_supervised_real_data.ipynb
│ ├── 4_Supervised_Deployed/
│ │ └── full_traffic_supervised.ipynb
│ ├── 5_Evasion_Attacks/
│ │ ├── 1_whitebox_attacks.ipynb
│ │ ├── 2_greybox_attacks.ipynb
│ │ └── 3_blackbox_attacks.ipynb
│ └── 6_Final_Model_Tuning/
│   └── final_attack_tuning.ipynb
│
├── real_traffic_scripts/ # OPTIONAL (NOT NEEDED TO RUN)
│ └── *.py # Scripts for traffic generation and PCAP capture
│
└── README.md

```

## Setup Instructions

### Step 1: Install Dependencies

Install all required Python packages using:

bash
pip install pandas numpy matplotlib seaborn scikit-learn imbalanced-learn pyshark


These libraries are used for:

Data processing (pandas, numpy)

Model training and evaluation (scikit-learn, imbalanced-learn)

Visualizations (matplotlib, seaborn)

Packet-level feature extraction (pyshark)

### Step 2: Add Required Input Folders

Before running any notebooks, ensure the following folders are present in the project root:
data/ (required, provided separately)

    Must include all raw .csv files listed in the folder structure.

    Do not include cleaned_cic.csv — it will be generated automatically by the first notebook.

real_data/ (required, provided separately)

    Must include all .pcap and .csv files inside attack/, benign/, and test_1/.

    These files are required for real traffic evaluation and adversarial attack testing.

    Both folders must exactly match the structure and filenames shown above.
# Running the Project

Run the notebooks in the following order:

    notebooks/1_Model_Start/1_model.ipynb

    notebooks/1_Model_Start/2_forest_tuning.ipynb

    notebooks/1_Model_Start/3_advanced_tuning.ipynb

    notebooks/2_Real_Data/4_real_data_checking.ipynb

    notebooks/3_Supervised/1_supervised_initial.ipynb

    notebooks/3_Supervised/2_supervised_real_data.ipynb

    notebooks/4_Supervised_Deployed/full_traffic_supervised.ipynb

    notebooks/5_Evasion_Attacks/1_whitebox_attacks.ipynb

    notebooks/5_Evasion_Attacks/2_greybox_attacks.ipynb

    notebooks/5_Evasion_Attacks/3_blackbox_attacks.ipynb

    notebooks/6_Final_Model_Tuning/final_attack_tuning.ipynb

Each notebook builds on the previous one and will generate outputs such as:

    cleaned_cic.csv

    Trained .joblib model files

    Evaluation reports and visualizations

Notes

    Do not rename or restructure any folders or files.

    The real_traffic_scripts/ folder is optional and contains traffic generation tools. It is not needed to run the main pipeline.

    All generated files (models, summaries) are saved in the models/ folder automatically.

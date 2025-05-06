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
│ ├── attack/
│ │   ├── extraction/
│ │   │   └── extract_attack_features.py
│ │   ├── real_generation/
│ │   │   └── capture_attack_traffic.sh
│ │   └── synthetic_generation/
│ │       └── attack_traffic_generation.py
│ └── benign/
│     ├── extraction/
│     │   └── extract_benign_features.py
│     ├── real_generation/
│     │   ├── capture_benign_traffic.sh
│     │   ├── capture_heavy_benign.sh
│     │   ├── generate_benign_traffic.sh
│     │   └── generate_diverse_benign.sh
│     └── synthetic_generation/
│         └── benign_advanced_generation.py
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

References

    Key research was considered throughout the project to guide design and methodology:
        
        Model Selection: Isolation Forest and Random Forest were chosen with awareness of foundational works by Liu et al. (2012) and Breiman (2001), along with applied uses in intrusion detection (e.g., Chua et al., 2024; Wu et al., 2022).
        
        Traffic and Attack Generation: Evasion techniques were aligned with known scan behavior described by Ring et al. (2018) and Dabbagh et al. (2011), focusing on slow, stealthy probes.
        
        Adversarial Testing: The structure of whitebox, greybox, and blackbox evaluations was informed by Yazdanpour et al. (2023) and Huang et al. (2019), which outline threat models based on attacker knowledge.
       
        Robustness and Evasion Defense: Final tuning strategies drew on ideas from Peng et al. (2020) and Alshahrani et al. (2022), who explored retraining and synthetic evasion traffic.


## Team Contributions

This project was developed in three phases, with each team member responsible for one phase. Miguel Pinto served as the overall team lead, ensuring coordination and consistency across all stages.

---

### Phase 1: Initial Modeling — *Ahmed Lotfy*

Ahmed was responsible for establishing the project's initial detection framework:

- Selected the **CICIDS2017 dataset** for training and evaluation.
- Implemented an **Isolation Forest** for unsupervised anomaly detection, aiming for high recall and class balance.
- Transitioned to a **Random Forest** classifier due to improved supervised performance.
- Tuned model hyperparameters and evaluated baseline performance metrics.
- Included a small subset of **early real traffic** to assess generalization.

His work produced a supervised baseline model that was critical for subsequent adversarial testing.

---

### Phase 2: Real Traffic Generation — *Mátyás Szikra*

Mátyás managed the generation of realistic network traffic for training and evaluation:

- Set up a controlled environment using **virtual machines** to simulate attacker and victim systems.
- Generated **low-and-slow port scans** using nmap to mimic stealthy reconnaissance behavior.
- Collected **benign traffic** from typical network activities such as browsing and file transfers.
- Supplemented the dataset with **synthetic attack flows** for greater diversity.
- Created custom scripts to extract **CIC-style flow features** and exported labeled CSV datasets.

This phase provided a hybrid dataset combining both realistic and synthetic data for robust model evaluation.

DISCLAIMER: My contribution only consists of one commit as for my step everything was done locally and committed as a whole.

---

### Phase 3: Adversarial Evaluation and Tuning — *Miguel Pinto*

Miguel led the adversarial robustness and refinement phase:

- Developed and executed a range of **evasion attacks** based on three threat models:
  - **Whitebox**: Full access to model internals, enabling precise feature manipulation.
  - **Greybox**: Partial knowledge of features and benign traffic, using statistical mimicry and surrogate models.
  - **Blackbox**: Only observed model outputs, using trial-and-error blending and basic transformation techniques.
- Evaluated the model's performance under these conditions and identified key weaknesses.
- **Retrained the model** with successful evasive samples to improve robustness.
- Confirmed that **final blackbox attacks were able to evade detection**, highlighting practical risks.

As team lead, Miguel also:

- Coordinated technical planning and task distribution across all phases.
- Ensured consistency in data formats, feature extraction methods, and evaluation metrics.
- Oversaw integration of team efforts into a cohesive project workflow.

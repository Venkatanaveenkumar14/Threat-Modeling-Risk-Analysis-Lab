import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
import matplotlib.pyplot as plt
from mitreattack.stix20 import MitreAttackData
from collections import defaultdict

def build_cwe_mapping():
    """Dynamically build CWE to MITRE ATT&CK technique mapping"""
    mitre = MitreAttackData("data/enterprise-attack.json")
    cwe_map = defaultdict(list)
    
    techniques = mitre.get_techniques()
    for tech in techniques:
        if 'external_references' in tech:
            # Get MITRE technique ID
            tech_id = tech['external_references'][0]['external_id']
            
            # Find all CWE references
            for ref in tech['external_references']:
                if ref['source_name'] == 'cwe':
                    cwe_id = f"CWE-{ref['external_id']}"
                    cwe_map[cwe_id].append(tech_id)
    
    return dict(cwe_map)

def analyze_risk():
    # Load and preprocess data
    df = pd.read_csv("data/processed_cves.csv")
    df['dateAdded'] = pd.to_datetime(df['dateAdded'])
    
    # ====== Feature Engineering ======
    # 1. Basic features
    df['desc_length'] = df['shortDescription'].str.len()
    df['has_exploit'] = df['notes'].str.contains('exploit', case=False).fillna(False)
    df['is_known_ransomware'] = df['knownRansomwareCampaignUse'].str.lower().isin(['true', 'yes', 'known'])
    
    # 2. MITRE ATT&CK Mapping (Dynamic)
    print("\nBuilding MITRE ATT&CK mapping...")
    cwe_to_mitre = build_cwe_mapping()
    
    def map_cwe_to_mitre(cwe_str):
        techniques = []
        for cwe in str(cwe_str).split(','):
            cwe = cwe.strip()
            if cwe in cwe_to_mitre:
                techniques.extend(cwe_to_mitre[cwe])
        return list(set(techniques)) if techniques else ['T1199']  # Default to unknown
    
    df['mitre_techniques'] = df['cwes'].apply(map_cwe_to_mitre)
    
    # 3. Temporal features
    df['days_since_added'] = (pd.Timestamp.now() - df['dateAdded']).dt.days
    df['quarter_added'] = df['dateAdded'].dt.quarter
    
    # ====== Target Variable ======
    y = np.where(
        df['is_known_ransomware'], 1,
        np.where(
            (df['cvss_score'] >= 9.0) | (df['has_exploit']),
            1, 0
        )
    )
    
    # ====== Modeling ======
    # Create technique dummy variables
    mitre_dummies = pd.get_dummies(df['mitre_techniques'].explode()).groupby(level=0).sum()
    
    X = pd.concat([
        df[['cvss_score', 'desc_length', 'has_exploit', 'days_since_added']],
        pd.get_dummies(df['quarter_added'], prefix='qtr'),
        mitre_dummies
    ], axis=1).fillna(0)
    
    model = LogisticRegression(max_iter=2000, class_weight='balanced')
    model.fit(X, y)
    print(f"\nModel Accuracy: {model.score(X, y):.2f}")
    
    # ====== Visualization ======
    plt.figure(figsize=(15, 10))
    
    # 1. Vendor Risk
    plt.subplot(2, 2, 1)
    vendor_risk = df.groupby('vendorProject')['cvss_score'].mean().sort_values()
    vendor_risk.plot(kind='barh', title='Average CVSS by Vendor')
    
    # 2. MITRE Technique Distribution
    plt.subplot(2, 2, 2)
    mitre_counts = pd.Series(np.concatenate(df['mitre_techniques'].values)).value_counts()
    mitre_counts.plot(kind='pie', title='MITRE Technique Distribution')
    
    # 3. Temporal Trends
    plt.subplot(2, 2, 3)
    df.groupby(df['dateAdded'].dt.to_period('M'))['cvss_score'].mean().plot(
        title='Monthly Average CVSS Score'
    )
    
    plt.tight_layout()
    plt.savefig('reports/risk_analysis.png')
    print("\nSaved visualizations to reports/risk_analysis.png")
    
    # ====== Advanced Output ======
    print("\nTop Risk Indicators:")
    print(pd.DataFrame({
        'Feature': X.columns,
        'Coefficient': model.coef_[0]
    }).sort_values('Coefficient', ascending=False).head(10))
    
    return model

if __name__ == "__main__":
    analyze_risk()
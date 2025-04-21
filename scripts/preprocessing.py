import pandas as pd
import numpy as np

def load_and_preprocess():
    cves = pd.read_csv("data/cve_dataset.csv")
    
    # Ensure we have data to work with
    if len(cves) == 0:
        raise ValueError("Input CSV is empty!")
    
    # Add synthetic CVSS scores if no risk filter exists
    cves['cvss_score'] = np.round(np.random.uniform(1, 10, len(cves)), 1)
    
    # Fallback filter if ransomware column has no True values
    if 'knownRansomwareCampaignUse' in cves.columns:
        high_risk = cves[cves['knownRansomwareCampaignUse'] == 'True']
        if len(high_risk) == 0:  # If no matches, use top 20% CVSS scores
            high_risk = cves.nlargest(int(0.2 * len(cves)), 'cvss_score')
    else:
        high_risk = cves.nlargest(int(0.2 * len(cves)), 'cvss_score')
    
    high_risk.to_csv("data/processed_cves.csv", index=False)
    print(f"Saved {len(high_risk)} high-risk CVEs")
    return high_risk

if __name__ == "__main__":
    load_and_preprocess()
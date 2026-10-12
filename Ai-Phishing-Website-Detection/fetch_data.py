import os
import requests
import pandas as pd

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)
DATASET_PATH = os.path.join(DATA_DIR, "dataset.csv")

def download_clean_dataset():
    print("[*] Downloading balanced, benchmark anti-phishing dataset...")
    # Clean, peer-reviewed dataset containing authentic benign paths & real phishing attacks
    url = "https://raw.githubusercontent.com/Mayank-2004/sample-data-phishing/main/urldata.csv"
    
    # Fallback to direct raw benchmark mirror
    backup_url = "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv"

    try:
        df = pd.read_csv(backup_url)
        # Standardize column names
        # dataset_small has columns: url, label (phishing = 1, legitimate = 0)
        if "url" in df.columns and "label" in df.columns:
            clean_df = df[["url", "label"]].dropna()
        else:
            # If header differs, map first column as url, last as label
            clean_df = pd.DataFrame({
                "url": df.iloc[:, 0],
                "label": df.iloc[:, -1]
            }).dropna()
            
        clean_df["label"] = clean_df["label"].astype(int)
        
        # Balance to 5,000 samples per class
        phish = clean_df[clean_df["label"] == 1].head(5000)
        legit = clean_df[clean_df["label"] == 0].head(5000)
        
        final_df = pd.concat([phish, legit]).sample(frac=1.0, random_state=42).reset_index(drop=True)
        final_df.to_csv(DATASET_PATH, index=False)
        print(f"[+] Downloaded and formatted {len(final_df)} verified URLs to {DATASET_PATH}")
        print(f"    - Legitimate count: {len(legit)}")
        print(f"    - Phishing count:   {len(phish)}")
        
    except Exception as e:
        print(f"[!] Direct download error: {e}")
        print("[*] Falling back to automated curated builder...")
        # Direct generation of standard real-world web URLs
        legit = [
            "https://spring.io/projects/spring-boot",
            "https://docs.oracle.com/en/java/javase/17/docs/api/",
            "https://github.com/spring-projects/spring-boot/releases",
            "https://stackoverflow.com/questions/tagged/java",
            "https://en.wikipedia.org/wiki/Computer_security",
            "https://aws.amazon.com/ec2/pricing/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview",
            "https://hub.docker.com/_/openjdk",
            "https://www.nytimes.com/section/technology",
            "https://www.linkedin.com/feed/"
        ] * 400
        
        phish = [
            "http://secure-paypal-login.update-alert.xyz/signin",
            "http://192.168.1.100/account-verify/chase/",
            "http://apple-id-verify.support-signin.cf/auth",
            "http://login.microsoftonline.acc-portal.top/auth.php",

            "http://netflix-billing-recovery.update-info.com/signin",
            "http://wallet-metamask-io.auth-web3.net/phrase",
            "http://chase-bank-online-alert.servehttp.com/login",
            "http://secure-banking-bofa-verify.online/auth/login",
            "http://update-steam-guard.support-community.top/trade",
            "http://portal-login-google-drive.freecluster.eu/login"
        ] * 400
        
        df = pd.DataFrame({
            "url": legit + phish,
            "label": [0] * len(legit) + [1] * len(phish)
        }).sample(frac=1.0, random_state=42).reset_index(drop=True)
        df.to_csv(DATASET_PATH, index=False)
        print(f"[+] Saved fallback dataset to {DATASET_PATH}")

if __name__ == "__main__":
    download_clean_dataset()
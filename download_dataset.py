import kagglehub
import shutil
import os

print("Downloading dataset...")
path = kagglehub.dataset_download("smmmmmmmmmmmm/cybersecurity-intrusion-simulated-network")

print("Path to dataset files:", path)

# Target directory
target_dir = os.path.join(os.getcwd(), 'data', 'kaggle_dataset')
os.makedirs(target_dir, exist_ok=True)

print(f"Copying files to {target_dir}...")
# Copy files
for item in os.listdir(path):
    s = os.path.join(path, item)
    d = os.path.join(target_dir, item)
    if os.path.isdir(s):
        shutil.copytree(s, d, dirs_exist_ok=True)
    else:
        shutil.copy2(s, d)

print("Dataset setup complete.")

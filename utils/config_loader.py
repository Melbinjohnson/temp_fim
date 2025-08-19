import json
import os

def load_config(path='config/settings.json'):
    with open(path, 'r') as f:
        return json.load(f)

def save_config(config, path='config/settings.json'):
    with open(path, 'w') as f:
        json.dump(config, f, indent=4)

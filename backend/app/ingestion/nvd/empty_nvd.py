# those that were fetched but are empty
import json
from pathlib import Path
 
empty = []
for f in Path('storage/raw/nvd').glob('*.json'):
      data = json.load(open(f))
      if not data.get('vulnerabilities'):
          empty.append(f.stem)

deleted = 0
for f in Path('storage/raw/nvd').glob('*.json'):
    data = json.load(open(f))
    if not data.get('vulnerabilities'):
        f.unlink()
        deleted += 1

print(f'Deleted {deleted} empty files')
  
print(f'Empty: {len(empty)}')
for cve in empty[:]:
      print(cve)
  
with open('output/nvd_empty.txt', 'w') as out:
     out.write('\n'.join(empty))

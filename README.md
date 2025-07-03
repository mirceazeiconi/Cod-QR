# Materiale Relevante

📄 [Lucrare finală (PDF)](lucrare_finala.pdf)  
🖼️ [Descarcă posterul (PDF)](Poster_Zeiconi_Mircea.pdf)

---

![Poster](Poster_Zeiconi_Mircea-1.png)

## Exemple de cod

### clasificator\_malware.py

```python
import json
from sklearn.ensemble import RandomForestClassifier

def load_features(path):
    with open(path) as f:
        return json.load(f)

def train_model(X, y):
    clf = RandomForestClassifier()
    clf.fit(X, y)
    return clf


```markdown
### rezultate\_sandboxuri.json

```json
{
  "file": "sample.exe",
  "score": 95,
  "sandbox": "JoeSandbox",
  "signatures": [
    "Creates autorun key",
    "Injects into svchost.exe",
    "Contacts C2 server"
  ]
}


---



```markdown
# Materiale Relevante

- [Lucrare finală (PDF)](lucrare_finala.pdf)
- [Descarcă posterul (PDF)](Poster_Zeiconi_Mircea.pdf)

---

![Poster](Poster_Zeiconi_Mircea-1.png)

---

## Exemple de cod

### clasificator\_malware.py

```python
import json
from sklearn.ensemble import RandomForestClassifier

def load_features(path):
    with open(path) as f:
        return json.load(f)

def train_model(X, y):
    clf = RandomForestClassifier()
    clf.fit(X, y)
    return clf

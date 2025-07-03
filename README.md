# Materiale Relevante

📄 [Lucrare finală (PDF)](lucrare_finala.pdf)  
🖼️ [Descarcă posterul (PDF)](Poster_Zeiconi_Mircea.pdf)

---

![Poster](Poster_Zeiconi_Mircea-1.png)

## Exemple de cod

### clasificator\_malware.py

```python
# Definire reguli pentru incadrarea in categorii
categorii_taxonomie = {
    "Tehnici de evaziune": [
        "anti-VM", "anti-debug", "ofuscare cod", "injectare proces", "rootkit"
    ],
    "Persistenta": [
        "cheie Run", "programare task", "serviciu auto-start", "modificare registry la boot"
    ],
    "Interactiune de retea": [
        "conexiune C2", "HTTP suspect", "DNS malitios", "scanare porturi", "propagare retea"
    ],
    "Comportamente distructive": [
        "criptare fisiere", "stergere fisiere", "exfiltrare date", "atac DDoS", "ransomware"
    ]
    # (pot continua cu alte categorii/subcategorii definite in taxonomie)
}

# Functie de clasificare a unei mostre pe baza listei de observatii
def clasifica_malware(observatii):
    '''
    Functie de clasificare a unei mostre pe baza listei de observatii (comportamente)
    extrase din analiza dinamica. Returneaza lista de categorii identificate.
    '''
    categorii_identificate = set()  # folosim set pentru a evita duplicatele

    # Parcurgem fiecare categorie din taxonomie si verificam daca vreo regula apare in observatii
    for categorie, indicii in categorii_taxonomie.items():
        for indiciu in indicii:
            for obs in observatii:
                if indiciu.lower() in obs.lower():  # comparam case-insensitive
                    categorii_identificate.add(categorie)
                    break  # daca am gasit un indiciu, marcam categoria si trecem la urmatoarea
                    # aici putem numara si numarul de indicii gasite pt a calibra un scor daca e cazul

    return list(categorii_identificate)


# Exemplu de utilizare a functiei de clasificare cu date simulate:
observatii_exemplu = [
    "Modifică o cheie Run în registri pentru persistență.",
    "Realizează o conexiune la un server de comandă și control (C2).",
    "Criptează fișierele utilizatorului și afișează o notă de răscumpărare"
]

rezultat = clasifica_malware(observatii_exemplu)
print("Categorii identificate:", rezultat)

def train_model(X, y):
    clf = RandomForestClassifier()
    clf.fit(X, y)
    return clf


```markdown
### rezultate\_sandboxuri.json

```json
{
    "Cuckoo": {
        "score": 10,
        "signatures": [
            "Creează cheie de autorun în registru",
            "Își copiează fișierul în directorul de start",
            "Contactează server de comandă și control (C2)"
        ],
        "network": {
            "hosts": [
                "45.67.89.123"
            ],
            "domains": [
                "malicious.example.com"
            ],
            "http": [
                {
                    "host": "malicious.example.com",
                    "uri": "/payload",
                    "method": "GET"
                }
            ]
        },
        "files": [
            "C:\\Users\\victim\\AppData\\Roaming\\malware.exe",
            "C:\\Users\\victim\\AppData\\Local\\Temp\\tmp123.tmp"
        ],
        "registry": [
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MalwareStub"
        ],
        "processes": [
            {
                "process_name": "malware.exe",
                "pid": 1234,
                "children": [
                    {
                        "process_name": "cmd.exe",
                        "pid": 5678,
                        "command_line": "cmd.exe /c vssadmin Delete Shadows /all /quiet"
                    },
                    {
                        "process_name": "svchost.exe",
                        "pid": 910,
                        "injected": true
                    }
                ]
            }
        ]
    },
    "ANYRUN": {
        "score": 100,
        "network": {
            "domains": [
                "malicious.example.com"
            ],
            "connections": [
                "45.67.89.123:80 (HTTP)",
                "45.67.89.123:443 (HTTPS)"
            ]
        },
        "files": {
            "created": [
                "C:\\Users\\victim\\AppData\\Roaming\\malware.exe"
            ],
            "deleted": [
                "C:\\Users\\victim\\Downloads\\mostra_malware.exe"
            ]
        },
        "registry": {
            "modified": [
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MalwareStub"
            ]
        },
        "processes": {
            "main": "malware.exe (PID 1234)",
            "children": [
                "cmd.exe (PID 5678) -> vssadmin.exe",
                "svchost.exe (PID 910) (proces legitimat țintă injecție)"
            ]
        }
    },
    "JoeSandbox": {
        "score": 95,
        "network": {
            "contacts": [
                "malicious.example.com (45.67.89.123)",
                "DNS request for malicious.example.com"
            ]
        },
        "files": {
            "dropped": [
                "C:\\Users\\victim\\AppData\\Roaming\\malware.exe",
                "C:\\Users\\victim\\AppData\\Local\\Temp\\config.dat"
            ]
        },
        "registry": {
            "added": [
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MalwareStub"
            ]
        },
        "processes": {
            "tree": "malware.exe -> cmd.exe (vssadmin) -> svchost.exe (injectat)"
        },
        "signatures": [
            "Executes OS command via cmd.exe",
            "Modifies registry for persistence",
            "Network communication to malicious host"
        ],
        "family": "AgentTesla (suspectat)"
    },
    "HybridAnalysis": {
        "threat_score": 100,
        "verdict": "Malicious",
        "network": {
            "domains_contacted": [
                "malicious.example.com"
            ],
            "hosts": [
                "45.67.89.123"
            ]
        },
        "file_changes": {
            "created": [
                "C:\\Users\\victim\\AppData\\Roaming\\malware.exe"
            ],
            "deleted": [
                "mostra_malware.exe (original)"
            ]
        },
        "processes": {
            "process_tree": "malware.exe (PID 1234) -> cmd.exe (PID 5678) -> vssadmin.exe; malware.exe -> svchost.exe (injection)"
        },
        "classification": "Trojan/Stealer"
    },
    "Triage": {
        "score": 9,
        "analysis_summary": {
            "threat_level": "high",
            "duration": 60
        },
        "network": {
            "indicators": [
                "malicious.example.com (DNS and HTTP GET)",
                "45.67.89.123:80"
            ]
        },
        "files": {
            "created": [
                "C:\\Users\\victim\\AppData\\Roaming\\malware.exe",
                "C:\\Users\\victim\\AppData\\Local\\Temp\\config.dat"
            ],
            "deleted": [
                "C:\\Users\\victim\\Downloads\\mostra_malware.exe"
            ]
        },
        "processes": {
            "tree": [
                "malware.exe (1234)",
                "|__ cmd.exe (5678) [execută vssadmin]",
                "|__ svchost.exe (910) [cod malițios injectat]"
            ]
        },
        "signatures": [
            "network_c2_contact",
            "persistence_registry_run",
            "code_injection_remote_process"
        ],
        "family": "AgentTesla"
    },
    "Detux": {
        "error": "Format de fișier nesuportat - analiza Linux nu a putut rula fișier executabil Windows"
    }
}


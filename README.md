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

```
## rezultate_sandboxuri.json

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

```
## sandbox_analysis.py

```py
import requests
import time
import json


CUCKOO_API_URL = "http://localhost:8090"
ANYRUN_API_URL = "https://api.any.run/v1/analysis"
JOE_API_URL = "https://jbxcloud.joesecurity.org/api"
HYBRID_API_URL = "https://www.hybrid-analysis.com/api/v2"
TRIAGE_API_URL = "https://api.tria.ge/v0"
DETUX_API_URL = "http://localhost:8000"


ANYRUN_API_KEY = "CHEIA_DV_ANYRUN"
JOE_API_KEY = "CHEIA_DV_JOE"
HYBRID_API_KEY = "CHEIA_DV_HYBRID"
TRIAGE_API_KEY = "CHEIA_DV_TRIAGE"


# Cale fișier
malware_file_path = "mostra_malware.exe"

# Citirea fișierului malware în modul binar, pentru trimitere către sandbox-uri
with open(malware_file_path, "rb") as f:
    malware_data = f.read()

#Stocarea rezultatelor de la fiecare sandbox
results = {}

#  1. Trimitere către Cuckoo Sandbox (local)
try:
    # Endpoint-ul pentru a trimite fișierul spre analiză în Cuckoo (tasks/create/file)
    cuckoo_submit_url = f"{CUCKOO_API_URL}/tasks/create/file"
    files = {"file": ("mostra_malware.exe", malware_data)}
    resp = requests.post(cuckoo_submit_url, files=files)
    resp.raise_for_status()
    task_id = resp.json().get("task_id")
    print(f"[Cuckoo] Mostra trimisă, ID task = {task_id}")

    # Așteaptă finalizarea analizei în buclă interogând periodic starea task-ului
    cuckoo_report_url = f"{CUCKOO_API_URL}/tasks/report/{task_id}"
    status_url = f"{CUCKOO_API_URL}/tasks/view/{task_id}"
    while True:
        status_resp = requests.get(status_url)
        status_resp.raise_for_status()
        status_info = status_resp.json()
        task_status = status_info.get("task", {}).get("status")
        if task_status == "reported":  # status "reported" indică finalizarea analizei și generarea raportului
            break
        print("[Cuckoo] Analiza nu s-a finalizat încă, aștept 10 secunde...")
        time.sleep(10)
    # După finalizare preia raportul în format JSON
    report_resp = requests.get(cuckoo_report_url)
    report_resp.raise_for_status()
    cuckoo_report = report_resp.json()
    # Extrage informații relevante din raport (ex: scor, indicatori de rețea, modificări fișiere etc.)
    cuckoo_summary = {
        "score": cuckoo_report.get("info", {}).get("score"),
        "signatures": [sig.get("description") for sig in cuckoo_report.get("signatures", [])],
        "network": cuckoo_report.get("network", {}),  # domenii, IP-uri, URL accesate
        "files": cuckoo_report.get("behavior", {}).get("summary", {}).get("files", []),  # fișiere accesate/creat
        "registry": cuckoo_report.get("behavior", {}).get("summary", {}).get("keys", []),  # chei de registru modificate
        "processes": cuckoo_report.get("behavior", {}).get("processes", []),  # procese create
    }
    results["Cuckoo"] = cuckoo_summary
except Exception as e:
    print(f"Eroare la analiza cu Cuckoo: {e}")
    results["Cuckoo"] = {"error": str(e)}

#  2. Trimitere către Any.run
try:
    # Endpoint și antet pentru trimitere fișier la Any.run (folosind API-ul lor)
    headers = {"Authorization": f"API-Key {ANYRUN_API_KEY}"}
    # Conform documentației, Any.run acceptă analiza fișierelor printr-o cerere POST
    files = {"file": ("mostra_malware.exe", malware_data)}
    resp = requests.post(ANYRUN_API_URL, headers=headers, files=files)
    resp.raise_for_status()
    anyrun_data = resp.json()
    analysis_id = anyrun_data.get("taskId") or anyrun_data.get("id")  # Obține ID-ul analizei
    print(f"[Any.run] Mostra trimisă, ID analiză = {analysis_id}")
    # Așteaptă finalizarea analizei (Any.run permite monitorizarea în timp real: folosim polling simplu)
    # Presupunem un endpoint de verificare a stării (exemplu fictiv: /analysis/status/<ID>)
    status_url = f"{ANYRUN_API_URL}/{analysis_id}/status"
    report_url = f"{ANYRUN_API_URL}/{analysis_id}/report"
    while True:
        status_resp = requests.get(status_url, headers=headers)
        status_resp.raise_for_status()
        status = status_resp.json().get("status")
        if status == "finished" or status == "done":
            break
        print("[Any.run] Analiza în desfășurare, aștept 10 secunde...")
        time.sleep(10)
    # Preia raportul la finalizare (presupunând că Any.run oferă un raport în format JSON prin API)
    report_resp = requests.get(report_url, headers=headers)
    report_resp.raise_for_status()
    anyrun_report = report_resp.json()
    # Extrage informații relevante din raportul Any.run
    anyrun_summary = {
        "score": anyrun_report.get("score", None),  # dacă există un scor de risc
        "network": anyrun_report.get("network", {}),  # ex: conexiuni rețea observate
        "files": anyrun_report.get("filesystem", {}),  # fișiere create/șterse
        "registry": anyrun_report.get("registry", {}),  # chei de registru (dacă sunt raportate)
        "processes": anyrun_report.get("processes", {}),  # procese și graful acestora
        # Any.run fiind interactiv nu returnează de fiecare dată totul direct: ajustăm în funcție de API real
    }
    results["ANYRUN"] = anyrun_summary
except Exception as e:
    print(f"Eroare la analiza cu Any.run: {e}")
    results["ANYRUN"] = {"error": str(e)}

#   3. Trimitere către Joe Sandbox
try:
    # Endpoint pentru creare analiză Joe Sandbox
    joe_submit_url = f"{JOE_API_URL}/v2/analysis/submit/file"  # exemplu: versiunea 2 a API
    params = {
        "apikey": JOE_API_KEY,
        "accept_tac": "1"  # acceptare termeni și condiții dacă e necesar
    }
    files = {"file": ("mostra_malware.exe", malware_data)}
    resp = requests.post(joe_submit_url, files=files, data=params)
    resp.raise_for_status()
    joe_response = resp.json()
    analysis_id = joe_response.get("analysis") or joe_response.get(
        "webid")  # ID-ul analizei sau webid (Joe poate folosi un ID special)
    print(f"[Joe Sandbox] Mostra trimisă, ID analiză = {analysis_id}")
    # Așteaptă până când analiza este completă
    # Joe Sandbox poate necesita o așteptare mai lungă deoarece realizează analize extinse
    status_url = f"{JOE_API_URL}/v2/analysis/status/{analysis_id}"
    report_url = f"{JOE_API_URL}/v2/analysis/report/{analysis_id}/json"
    while True:
        status_resp = requests.get(status_url, params={"apikey": JOE_API_KEY})
        status_resp.raise_for_status()
        status_info = status_resp.json()
        if status_info.get("status") == "finished":
            break
        print("[Joe Sandbox] Analiza în curs, mai aștept 15 secunde...")
        time.sleep(15)
    # După finalizare obține raportul în format JSON
    report_resp = requests.get(report_url, params={"apikey": JOE_API_KEY})
    report_resp.raise_for_status()
    joe_report = report_resp.json()
    # Extrage informații relevante din raportul Joe Sandbox
    joe_summary = {
        "score": joe_report.get("risk_score", None),  # Joe poate oferi un scor de risc
        "network": joe_report.get("network", {}),
        "files": joe_report.get("dropped", {}),  # fișiere dropate sau create
        "registry": joe_report.get("registry", {}),
        "processes": joe_report.get("processtree", {}),
        "signatures": joe_report.get("signatures", []),
        "family": joe_report.get("malware_family", None)  # dacă Joe identifică familia malware
    }
    results["JoeSandbox"] = joe_summary
except Exception as e:
    print(f"Eroare la analiza cu Joe Sandbox: {e}")
    results["JoeSandbox"] = {"error": str(e)}

#   4. Trimitere către Hybrid Analysis (Falcon Sandbox)
try:
    # Endpoint pentru trimitere fișier la Hybrid Analysis
    hybrid_submit_url = f"{HYBRID_API_URL}/submit/file"
    headers = {
        "User-Agent": "FalconSandbox",  # necesar de API-ul Hybrid
        "api-key": HYBRID_API_KEY,
        "Content-Type": "application/json"
    }
    files = {"file": ("mostra_malware.exe", malware_data)}
    data = {
        "environment_id": 100  # ID-ul mediului
    }
    resp = requests.post(hybrid_submit_url, headers=headers, files=files, data=data)
    resp.raise_for_status()
    resp_data = resp.json()
    analysis_id = resp_data.get("id") or resp_data.get("analysisId")
    print(f"[Hybrid Analysis] Mostra trimisă, ID analiză = {analysis_id}")
    # Verifică starea analizei în buclă
    report_url = f"{HYBRID_API_URL}/report/{analysis_id}/summary"
    while True:
        report_resp = requests.get(report_url, headers=headers)
        if report_resp.status_code == 200:
            break  # raportul este disponibil
        print("[Hybrid Analysis] Raportul nu este gata încă, aștept 10 secunde...")
        time.sleep(10)
    # Obține raportul sumar (sau complet)
    report_data = report_resp.json()
    # Extrage informații relevante
    hybrid_summary = {
        "threat_score": report_data.get("threat_score", None),
        "verdict": report_data.get("verdict", None),  # malicious/suspicious/clean
        "network": report_data.get("network_analysis", {}),
        "file_changes": report_data.get("file_system", {}),
        "processes": report_data.get("process_tree", {}),
        "classification": report_data.get("classification", None)  # ex: Trojan/Backdoor etc.
    }
    results["HybridAnalysis"] = hybrid_summary
except Exception as e:
    print(f"Eroare la analiza cu Hybrid Analysis: {e}")
    results["HybridAnalysis"] = {"error": str(e)}

#  5. Trimitere către Hatching Triage
try:
    # Endpoint pentru trimitere fișier la Triage
    triage_submit_url = f"{TRIAGE_API_URL}/samples"
    headers = {"Authorization": f"Bearer {TRIAGE_API_KEY}"}
    files = {"file": ("mostra_malware.exe", malware_data)}
    resp = requests.post(triage_submit_url, headers=headers, files=files)
    resp.raise_for_status()
    triage_resp = resp.json()
    sha256 = triage_resp.get("id")  # Triage folosește hash-ul (SHA256) ca identificator al eșantionului
    print(f"[Triage] Mostra trimisă, SHA256 = {sha256}")
    # Așteaptă până când analiza este gata (polling pe baza hash-ului)
    report_url = f"{TRIAGE_API_URL}/samples/{sha256}/report/json"
    while True:
        report_resp = requests.get(report_url, headers=headers)
        if report_resp.status_code == 200:
            break
        print("[Triage] Analiza în curs, aștept 10 secunde...")
        time.sleep(10)
    triage_report = report_resp.json()
    # Extrage informații cheie din raportul Triage
    triage_summary = {
        "score": triage_report.get("score", None),
        "analysis_summary": triage_report.get("analysis", {}),
        "network": triage_report.get("network", {}),
        "files": triage_report.get("files", {}),
        "processes": triage_report.get("process_tree", {}),
        "signatures": triage_report.get("signatures", []),
        "family": triage_report.get("malware_family", None)
    }
    results["Triage"] = triage_summary
except Exception as e:
    print(f"Eroare la analiza cu Hatching Triage: {e}")
    results["Triage"] = {"error": str(e)}

#  6. Trimitere către Detux (analiză Linux)
try:
    # Detux este un sandbox pentru malware Linux. Dacă trimitem un .exe Windows e posibil să nu producă rezultate
    detux_submit_url = f"{DETUX_API_URL}/analysis/submit"
    files = {"file": ("mostra_malware.exe", malware_data)}
    resp = requests.post(detux_submit_url, files=files)
    resp.raise_for_status()
    detux_resp = resp.json()
    analysis_id = detux_resp.get("analysis_id") or detux_resp.get("id")
    print(f"[Detux] Mostra trimisă, ID = {analysis_id}")
    # Așteptare scurtă pentru Detux (dacă e execuție rapidă)
    time.sleep(10)
    # Obținere raport (dacă Detux are un endpoint de raport, altfel poate produce direct un fișier local)
    detux_report_url = f"{DETUX_API_URL}/analysis/{analysis_id}/report"
    report_resp = requests.get(detux_report_url)
    report_resp.raise_for_status()
    detux_report = report_resp.json()
    results["Detux"] = detux_report  # posibil conține doar date statice dacă fișierul nu a rulat (fiind non-Linux)
except Exception as e:
    print(f"Eroare la analiza cu Detux: {e}")
    results["Detux"] = {"error": str(e)}

#  7. Salvarea rezultatelor în fișier JSON
with open("sandbox_results.json", "w") as outfile:
    json.dump(results, outfile, indent=4)
    print("Rezultatele au fost salvate în sandbox_results.json")

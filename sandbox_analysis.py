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



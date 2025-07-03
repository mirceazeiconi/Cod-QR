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





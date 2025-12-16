

```markdown
# 🛡️ Analyseur Trivy + NVD (cloud_vul_management)

Script Python pour analyser des cibles, générer des rapports Trivy, et les enrichir avec les données NVD pour une analyse avancée et une repriorisation des vulnérabilités (RBVM).

## Table des matières
- [Installation](#installation)
- [Configuration de la clé API](#configuration-de-la-clé-api)
- [Extraction des cibles](#extraction-des-cibles)
- [Utilisation](#utilisation)
  - [Analyse d'une cible unique](#analyse-dune-cible-unique)
  - [Analyse en lot (Scan All)](#analyse-en-lot-scan-all)
  - [Génération des rapports finaux](#génération-des-rapports-finaux)
- [Bonnes pratiques](#bonnes-pratiques)
- [Structure du Projet](#structure-du-projet)

---

## Installation

Ce projet requiert Python 3.x et les dépendances listées dans `requirements.txt`.

```bash
# Cloner le dépôt
git clone [URL_DU_REPO]
cd Script_trivy

# Installer les dépendances (pandas, requests, fpdf2, etc.)
pip install -r requirements.txt

```

##Configuration de la clé APILa clé API est nécessaire pour interroger la base de données NVD et récupérer les scores CVSS, EPSS, et l'état KEV.

1. Obtenez une clé API gratuite sur [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Créez un fichier `api_config.py` à la racine du projet :
```python
NVD_API_KEY = "votre_clé_api_ici"

```


3. **Sécurité** : Ajoutez `api_config.py` à votre `.gitignore` pour éviter de versionner votre clé API.

##Extraction des ciblesCes commandes aident à générer le fichier `targets.txt` ou `targets.csv` à partir de l'environnement.

###Pour les images Docker```bash
# Lister toutes les images avec leurs tags
docker images --format "{{.Repository}}:{{.Tag}}" > targets.txt

# Filtrer les images (ex: exclure <none>)
docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>" > targets.txt

```

###Pour les dépôts Git```bash
# Trouver tous les dépôts Git dans un répertoire
find /chemin/vers/depots -type d -name ".git" | sed 's/\/.git$//' > targets.txt

```

###Pour les applications web (URLs)```bash
# Liste d'URLs à analyser
echo "[https://example1.com](https://example1.com)" > targets.txt
echo "[https://example2.com](https://example2.com)" >> targets.txt

```

###Format du fichier des cibles (targets.csv)Le fichier `targets.csv` est utilisé par le script `scan_all.py` pour automatiser les analyses. Il doit contenir les colonnes suivantes :

```csv
type,nom,cible,priorite,environnement
image,docker,ubuntu:20.04,high,production
repository,git,[https://github.com/user/repo.git,medium,development](https://github.com/user/repo.git,medium,development)
web,url,[https://example.com](https://example.com),high,staging
fs,chemin,/chemin/vers/dossier,low,test

```

**Description des Colonnes :**

* `type` : Type de cible (`image`, `repository`, `web`, `fs`)
* `nom` : Nom convivial pour identifier la cible
* `cible` : URL, chemin ou identifiant de la cible
* `priorite` : Niveau de priorité de l'actif (`low`, `medium`, `high`) pour l'ajustement FIPS 199
* `environnement` : Contexte de déploiement (`production`, `staging`, `development`, `test`)

##Utilisation###Analyse d'une cible uniqueCe workflow est utilisé lorsque vous avez déjà généré un rapport Trivy (JSON) manuellement ou que vous traitez un seul fichier.

1. Générez un rapport Trivy (JSON) :
```bash
trivy image --format json -o scan.json ubuntu:20.04

```


2. Convertissez en CSV si nécessaire :
```bash
python trivy_parser.py -i scan.json -o scan.csv

```


3. Enrichissez avec NVD :
```bash
python nvd_client.py -i scan.csv -o scan_enriched.csv

```


4. Générez les rapports finaux :
```bash
python repriorise.py -i scan_enriched.csv -o rapports/ -f all

```



###Analyse en lot (Scan All)Ce workflow utilise `targets.csv` pour automatiser le scan de plusieurs environnements et consolider les résultats.

1. Exécutez le script d'analyse en lot (`scan_all.py` doit être présent dans le projet) :
```bash
python scan_all.py

```


*Note : Le script créera les dossiers `scans/` et `repos/` au besoin.*

###Génération des rapports finauxAprès le scan, utilisez les commandes suivantes pour traiter et générer les rapports.

####Option 1 : Rapport consolidé de toutes les cibles (recommandé pour une vue d'ensemble)```bash
# 1. Convertir et fusionner tous les rapports JSON du dossier 'scans/' en un seul CSV
python trivy_parser.py -i scans/ -o processed/ --merge all_scans.csv

# 2. Enrichir avec NVD
python nvd_client.py -i processed/all_scans.csv -o processed/all_enriched.csv

# 3. Reprioriser et générer les rapports (CSV, XLSX, PDF)
python repriorise.py -i processed/all_enriched.csv -o rapports/consolidated/ -f all

```

####Option 2 : Générer des rapports individuels (par cible)```bash
for file in scans/*.json; do
    base=$(basename "$file" .json)
    
    # Processus : Parse, Enrich, Prioritize pour chaque fichier
    python trivy_parser.py -i "$file" -o "processed/${base}.csv"
    python nvd_client.py -i "processed/${base}.csv" -o "processed/${base}_enriched.csv"
    python repriorise.py -i "processed/${base}_enriched.csv" -o "rapports/${base}/" -f all
done

```

---

##Bonnes pratiques* **Consultation :** Consultez les rapports finaux dans le dossier `rapports/`.
* `vulnerabilities_prioritized.csv` : Données complètes.
* `vulnerabilities_prioritized.xlsx` : Version Excel avec mise en forme et onglet légende.
* `vulnerabilities_prioritized.pdf` : Rapport PDF avec graphiques de répartition.


* **Mettez à jour régulièrement** la base de données Trivy :
```bash
trivy image --download-db-only

```


* **Planifiez des analyses régulières** avec cron ou un outil d'orchestration.

##Extraction des targetsPour extraire les informations de cible (images, fichiers, etc.) directement à partir des rapports enrichis :

```bash
python extract_targets.py

```

Voir le fichier [EXTRACT_TARGETS_README.md](https://www.google.com/search?q=EXTRACT_TARGETS_README.md) pour plus de détails sur le format de sortie.

##Structure du Projet```
Script_trivy/
├── api_config.py             # ⚠️ CLÉ API (NON versionné)
├── targets.csv               # Liste des cibles pour scan_all.py
├── trivy_parser.py           # Logic: Parser Trivy
├── nvd_client.py             # Logic: Client API NVD
├── repriorise.py             # Logic: Script de repriorisation
├── requirements.txt
├── scans/                    # 📂 Sorties JSON brutes de Trivy
├── processed/                # 📂 CSV intermédiaires (après Parse/Enrich)
└── rapports/                 # 📂 Rapports finaux (CSV, XLSX, PDF)

```

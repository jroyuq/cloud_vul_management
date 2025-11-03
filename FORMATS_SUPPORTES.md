# 📊 Formats de Rapports Trivy Supportés

## ✅ Formats Acceptés

Le script supporte **2 formats** de rapports Trivy :

### 1. Format JSON (Recommandé)

**Génération avec Trivy :**
```bash
trivy image -f json -o rapport_vulnerabilites.json nginx:latest
trivy fs -f json -o rapport_vulnerabilites.json /chemin/projet
trivy k8s -f json -o rapport_vulnerabilites.json cluster
```

**Avantages :**
- ✅ Format complet avec toutes les métadonnées
- ✅ Structure hiérarchique claire
- ✅ Informations détaillées sur chaque CVE

### 2. Format CSV (Tabulaire)

**Génération avec Trivy :**
```bash
trivy image -f table -o rapport_vulnerabilites.csv nginx:latest
# Ou avec l'option --format
trivy image --format table --output rapport_vulnerabilites.csv nginx:latest
```

**Avantages :**
- ✅ Lisible dans Excel/LibreOffice
- ✅ Format simple et compact
- ✅ Facile à filtrer manuellement

## 🔄 Détection Automatique

Le script détecte automatiquement le format selon l'extension :

| Extension | Format Détecté |
|-----------|----------------|
| `.json`   | JSON           |
| `.csv`    | CSV            |

## 📝 Structure des Colonnes CSV Attendues

Le parser CSV cherche ces colonnes (noms flexibles) :

| Colonne Attendue | Variantes Acceptées |
|------------------|---------------------|
| CVE ID | `Vulnerability ID`, `CVE`, `VulnerabilityID` |
| Package | `Package`, `PkgName` |
| Version Installée | `Installed Version`, `InstalledVersion` |
| Version Corrigée | `Fixed Version`, `FixedVersion` |
| Sévérité | `Severity` |
| Titre | `Title` |
| Description | `Description` |
| Target | `Target` |

## 💡 Exemples de Nommage

### Rapports Uniques
```
rapport_vulnerabilites.json  ← Détecté automatiquement
rapport_vulnerabilites.csv   ← Détecté automatiquement
```

### Rapports Multiples
```
rapport_app1.json
rapport_app2.csv
rapport_prod_20241103.json
rapport_dev_20241103.csv
trivy_scan_nginx.json
trivy_scan_postgres.csv
```

Utilisez `analyser_multiple.py` pour traiter tous ces rapports en une fois !

## 🚀 Utilisation Pratique

### Scénario 1 : Un seul rapport JSON
```bash
trivy image -f json -o rapport_vulnerabilites.json nginx:latest
python main.py
```

### Scénario 2 : Un seul rapport CSV
```bash
trivy image -f table -o rapport_vulnerabilites.csv nginx:latest
python main.py
```

### Scénario 3 : Plusieurs rapports (mix JSON/CSV)
```bash
# Scanner plusieurs images
trivy image -f json -o rapport_nginx.json nginx:latest
trivy image -f table -o rapport_postgres.csv postgres:latest
trivy image -f json -o rapport_redis.json redis:latest

# Analyser tous les rapports
python analyser_multiple.py
```

## ⚠️ Notes Importantes

1. **Priorité JSON** : Si vous avez `rapport_vulnerabilites.json` ET `rapport_vulnerabilites.csv`, le JSON sera utilisé par défaut

2. **Encodage** : Les fichiers CSV doivent être en UTF-8

3. **Séparateur CSV** : Le script supporte les virgules (`,`) comme séparateur

4. **Colonnes manquantes** : Si une colonne est absente dans le CSV, la valeur sera "N/A"

## 🔍 Vérification du Format

Le script affiche le format détecté au démarrage :

```
Chargement du rapport Trivy (JSON): rapport_vulnerabilites.json
✓ Rapport JSON chargé avec succès
```

Ou :

```
Chargement du rapport Trivy (CSV): rapport_vulnerabilites.csv
✓ Rapport CSV chargé avec succès (142 lignes)
```

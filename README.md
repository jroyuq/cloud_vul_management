# Analyseur Trivy + NVD

Script Python pour enrichir les rapports Trivy avec les données NVD.

## Installation

```bash
pip install -r requirements.txt
```

## Configuration de la clé API

1. Ouvrez `api_config.py`
2. Remplacez `VOTRE_CLE_API_ICI` par votre clé API NVD
3. **Ne versionnez jamais ce fichier sur Git** (déjà dans .gitignore)

## Utilisation

### Analyse d'un seul rapport

Le script détecte automatiquement **n'importe quel fichier CSV** !

1. Placez votre rapport Trivy CSV dans le dossier (n'importe quel nom)
   - Exemples : `rapport_docker.csv`, `scan.csv`, `vulnerabilites.csv`
2. Exécutez : `python main.py`
3. Consultez les résultats dans le dossier `output/`

### Analyse de plusieurs rapports

```bash
python analyser_multiple.py rapport1.json rapport2.csv rapport3.json
```

Ou placez tous vos rapports dans le dossier et exécutez :
```bash
python analyser_multiple.py
```
Le script détectera automatiquement tous les rapports Trivy.

## Structure

```
Script_trivy/
├── main.py                    # Point d'entrée
├── config.py                  # Configuration
├── trivy_parser.py            # Parser Trivy
├── nvd_client.py              # Client API NVD
├── report_generator.py        # Génération de rapports
├── api_config.py              # ⚠️ CLÉ API (ne pas versionner)
├── analyser_multiple.py       # Analyse de plusieurs rapports
├── rapport_vulnerabilites.json # Votre rapport Trivy (JSON)
└── rapport_vulnerabilites.csv  # Ou votre rapport Trivy (CSV)
```

## Format Supporté

- ✅ **CSV** : Format tabulaire de Trivy

Le script détecte automatiquement **n'importe quel fichier .csv** dans le dossier (sauf ceux dans `output/`).

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

Le script accepte les formats **JSON** et **CSV** !

1. Placez votre rapport Trivy dans le dossier :
   - Format JSON : `rapport_vulnerabilites.json`
   - Format CSV : `rapport_vulnerabilites.csv`
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

## Formats Supportés

- ✅ **JSON** : Format par défaut de Trivy
- ✅ **CSV** : Format tabulaire de Trivy

Le script détecte automatiquement le format selon l'extension du fichier.

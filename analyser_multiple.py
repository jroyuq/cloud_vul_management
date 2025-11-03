#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script pour analyser plusieurs rapports Trivy en une seule fois
"""

import sys
import logging
from pathlib import Path
from main import main as analyze_single
from config import Config

def analyze_multiple_reports(report_paths: list):
    """
    Analyse plusieurs rapports Trivy
    
    Args:
        report_paths: Liste des chemins vers les rapports
    """
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║   Analyse Multiple de Rapports Trivy + NVD                   ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()
    
    results = []
    
    for idx, report_path in enumerate(report_paths, 1):
        print(f"\n{'='*60}")
        print(f"📊 Analyse {idx}/{len(report_paths)}: {report_path}")
        print(f"{'='*60}\n")
        
        # Vérifier que le fichier existe
        if not Path(report_path).exists():
            print(f"⚠️ Fichier ignoré (introuvable): {report_path}\n")
            results.append((report_path, "ÉCHEC - Fichier introuvable"))
            continue
        
        # Configurer temporairement le chemin du rapport
        import os
        os.environ["TRIVY_REPORT"] = report_path
        
        # Exécuter l'analyse
        try:
            exit_code = analyze_single()
            if exit_code == 0:
                results.append((report_path, "✓ SUCCÈS"))
            else:
                results.append((report_path, "✗ ÉCHEC"))
        except Exception as e:
            print(f"✗ Erreur lors de l'analyse: {e}")
            results.append((report_path, f"✗ ERREUR: {e}"))
    
    # Résumé final
    print("\n" + "="*60)
    print("📊 RÉSUMÉ DES ANALYSES")
    print("="*60)
    
    for report, status in results:
        print(f"{status:20} | {report}")
    
    print("="*60)
    
    success_count = sum(1 for _, status in results if "SUCCÈS" in status)
    print(f"\n✓ Réussis: {success_count}/{len(report_paths)}")
    print(f"✗ Échecs: {len(report_paths) - success_count}/{len(report_paths)}")


if __name__ == "__main__":
    # Exemple d'utilisation
    if len(sys.argv) > 1:
        # Utiliser les arguments de ligne de commande
        reports = sys.argv[1:]
    else:
        # Chercher tous les rapports dans le dossier courant
        current_dir = Path(".")
        reports = []
        
        # Chercher les fichiers JSON et CSV
        for pattern in ["rapport_*.json", "rapport_*.csv", "*trivy*.json", "*trivy*.csv"]:
            reports.extend([str(f) for f in current_dir.glob(pattern)])
        
        if not reports:
            print("❌ Aucun rapport Trivy trouvé dans le dossier courant")
            print("\nUtilisation:")
            print("  python analyser_multiple.py rapport1.json rapport2.csv ...")
            print("\nOu placez vos rapports avec un nom contenant 'rapport_' ou 'trivy'")
            sys.exit(1)
        
        print(f"📁 {len(reports)} rapport(s) trouvé(s):")
        for r in reports:
            print(f"  • {r}")
        print()
    
    analyze_multiple_reports(reports)

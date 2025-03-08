# 🚀 CyberBeast Optimization & Security Pack - Mode Extrême

## 📋 Description
CyberBeast est un script PowerShell avancé conçu pour optimiser et sécuriser votre système Windows. Il offre plusieurs modes d'optimisation spécialisés pour différents cas d'utilisation.

## ⚠️ Prérequis
- Windows 10 ou Windows 11
- PowerShell 5.1 ou supérieur
- Au moins 10 Go d'espace disque libre
- Droits administrateur
- Connexion Internet active

## 🎮 Modes disponibles

1. **Mode Gaming**
   - Optimisation des performances GPU/CPU
   - Configuration réseau optimale pour le gaming
   - Réduction de la latence

2. **Mode Développement**
   - Configuration WSL2 et Docker
   - Optimisation des IDE
   - Configuration Git optimisée

3. **Mode Cybersécurité**
   - Renforcement du pare-feu
   - Configuration sécurisée avancée
   - Monitoring des menaces

4. **Mode Streaming**
   - Optimisation pour OBS/Streamlabs
   - Configuration de la bande passante
   - Priorités des processus

5. **Mode Cloud**
   - Configuration pour Azure/AWS/GCP
   - Optimisation des connexions distantes
   - Support des conteneurs

6. **Mode Créatif**
   - Optimisation pour les logiciels Adobe
   - Configuration de la mémoire cache
   - Gestion des ressources graphiques

7. **Mode Serveur**
   - Configuration IIS/Web
   - Optimisation base de données
   - Sécurité renforcée

8. **Mode Extrême**
   - Combine tous les modes
   - Optimisation maximale
   - Performance ultime

## 🚀 Installation et Utilisation

### Lancement du script
```powershell
# Ouvrir PowerShell en tant qu'administrateur et exécuter :
Set-ExecutionPolicy Bypass -Scope Process -Force
cd "chemin/vers/le/dossier"
./cyberbeat_ops.ps1
```

### 🎯 Commandes de lancement avancées

```powershell
# Lancement standard
./cyberbeat_ops.ps1

# Lancement avec mode spécifique
./cyberbeat_ops.ps1 -mode gaming        # Mode Gaming
./cyberbeat_ops.ps1 -mode dev           # Mode Développement
./cyberbeat_ops.ps1 -mode cybersec      # Mode Cybersécurité
./cyberbeat_ops.ps1 -mode streaming     # Mode Streaming
./cyberbeat_ops.ps1 -mode cloud         # Mode Cloud
./cyberbeat_ops.ps1 -mode creative      # Mode Créatif
./cyberbeat_ops.ps1 -mode server        # Mode Serveur
./cyberbeat_ops.ps1 -mode extreme       # Mode Extrême

# Lancement avec options supplémentaires
./cyberbeat_ops.ps1 -silent             # Exécution silencieuse
./cyberbeat_ops.ps1 -norestart          # Sans redémarrage
./cyberbeat_ops.ps1 -backup             # Créer uniquement une sauvegarde
./cyberbeat_ops.ps1 -restore            # Restaurer la dernière sauvegarde
./cyberbeat_ops.ps1 -update             # Mettre à jour le script
./cyberbeat_ops.ps1 -log debug          # Mode debug détaillé

# Combinaisons possibles
./cyberbeat_ops.ps1 -mode gaming -silent -norestart    # Mode gaming silencieux sans redémarrage
./cyberbeat_ops.ps1 -mode dev -log debug               # Mode développement avec logs détaillés
./cyberbeat_ops.ps1 -mode extreme -backup              # Mode extrême avec sauvegarde supplémentaire

# Exemples d'utilisation avec chemins spécifiques
cd C:\Users\Username\Desktop\CyberBeat
.\cyberbeat_ops.ps1 -mode gaming

# Lancement depuis un autre répertoire
& "C:\Users\Username\Desktop\CyberBeat\cyberbeat_ops.ps1" -mode gaming
```

### Commandes utiles pendant l'exécution
- Appuyer sur 'P' : Mettre en pause/reprendre l'exécution
- Dans le menu de pause :
  - 1 : Reprendre
  - 2 : Voir la progression
  - 3 : Voir les statistiques
  - 4 : Annuler

## 📊 Fonctionnalités principales

- Création automatique de points de restauration
- Sauvegarde des paramètres système
- Génération de rapports détaillés
- Monitoring en temps réel
- Support de pause/reprise
- Restauration automatique en cas d'erreur

## 📝 Fichiers générés

- `Cyberbeast_Logs_[date].txt` : Journal détaillé des opérations
- `Cyberbeast_Backup_[date]` : Dossier de sauvegarde
- `Cyberbeast_Optimization_Comparison_[date].txt` : Rapport de comparaison avant/après

## ⚠️ Avertissements

1. **IMPORTANT** : Créez une sauvegarde système avant d'exécuter le script
2. Certaines optimisations nécessitent un redémarrage
3. Le mode Extrême peut affecter la stabilité du système
4. Certains antivirus peuvent bloquer l'exécution
5. Les paramètres sont optimisés pour la performance, pas pour l'économie d'énergie

## 🔄 Restauration

En cas de problème, vous pouvez :
1. Utiliser le point de restauration système créé automatiquement
2. Exécuter la commande de restauration :
```powershell
./cyberbeat_ops.ps1 -restore
```

## 🆘 Support

Pour tout problème ou question :
1. Vérifiez les logs dans le dossier de sauvegarde
2. Consultez le rapport de comparaison
3. Utilisez la fonction de restauration

## 🔄 Mise à jour

Pour mettre à jour le script :
```powershell
./cyberbeat_ops.ps1 -update
```

## 📜 Licence
Ce script est distribué sous licence MIT. Voir le fichier LICENSE pour plus de détails. 

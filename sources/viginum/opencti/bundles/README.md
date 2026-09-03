# Bundles STIX 2.1 — construits pour OpenCTI

Ces bundles ont été **construits à partir des rapports PDF VIGINUM** (groupe B —
aucune annexe STIX publiée par VIGINUM). Ils sont directement réimportables dans
OpenCTI.

| Fichier | Rapport(s) | Objets |
|---|---|---|
| `2025-05_storm-1516.json` | Analyse du MOI russe Storm-1516 (06/05/2025) | ~960 : Intrusion-Set + 17 identités + infra CopyCop + 300 domaines + 74 DISARM + relations |
| `2024-02-04_portal-kombat-2-3.json` | Portal Kombat rapports 2 (14/02/2024) et 3 (29/04/2024) | ~470 : Campaign + TigerWeb/CHEVTCHENKO/Krymtechnologii/Inforos + 224 domaines + IP |

**Ne sont PAS ici** les rapports du **groupe A** (RRN, Portal Kombat #1, Matriochka,
UN-notorious BIG) : leurs bundles STIX natifs sont publiés par VIGINUM sur
<https://github.com/VIGINUM-FR/Rapports-Techniques> et importés tels quels (à
l'enrichissement près : auteur = VIGINUM, description, référence externe vers le
PDF — voir les fiches `opencti/*.md`).

## Réimport

```sh
# pycti
python -c "
from pycti import OpenCTIApiClient
c = OpenCTIApiClient('http://opencti:8080', '<TOKEN>')
c.stix2.import_bundle_from_json(open('2025-05_storm-1516.json').read(), update=True)
"
```
ou : OpenCTI → Data → Import → déposer le fichier (connecteur `import-file-stix`).

## Provenance / reconstruction

Scripts de construction et extractions texte : `misp-cti:provisioning/viginum/`
(déplacés depuis le scratchpad). Chaque bundle est régénérable depuis le PDF via
`pdftotext -layout` (les PDF VIGINUM ont une couche texte fiable) + le script
correspondant.

Fidélité : seules les entités, TTP (annexes DISARM à T-codes) et IOC **explicitement
présents dans le rapport** sont modélisés. Aucune inférence. Anomalies signalées
dans `../../README.md` (journal des anomalies).

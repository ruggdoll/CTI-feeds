# reports/viginum — bundles STIX 2.1 réimportables

Rapports **VIGINUM** transformés en bundles STIX 2.1 prêts à importer dans OpenCTI
(ou tout outil compatible STIX). Un sous-dossier par source ; ici `viginum/`.

Documentation par rapport (synthèse fidèle, entités, anomalies) :
`../../sources/viginum/`. Suivi : `misp-cti:importers/report_sources/viginum.yaml`.

## Bundles présents (groupe B — construits depuis les PDF)

| Fichier | Rapport(s) VIGINUM | Objets |
|---|---|---|
| `2025-05_storm-1516.json` | Analyse du MOI russe Storm-1516 (06/05/2025) | ~960 |
| `2024-02-04_portal-kombat-2-3.json` | Portal Kombat, rapports 2 (14/02/2024) et 3 (29/04/2024) | ~470 |
| `2025-06_african-initiative.json` | African Initiative / AI-Freak (12/06/2025, conjoint VIGINUM/FCDO/SEAE) | ~290 |
| `2026-06_rokh-solis.json` | Rokh Solis (11/06/2026) | ~150 |
| `2026-06_municipales-2026.json` | Protection du débat public — municipales 2026 (11/06/2026) | ~37 |
| `2024-09_jo-paris-2024.json` | Synthèse menace informationnelle JOP Paris 2024 (13/09/2024) | ~14 |
| `2025-02_roumanie.json` | Roumanie / algorithmes & influenceurs (04/02/2025) | ~15 |
| `2025-02_ukraine-3ans.json` | Guerre en Ukraine — 3 ans d'opérations russes (24/02/2025) | ~15 |

## Groupe A — bundles STIX natifs de VIGINUM

Les rapports **RRN**, **Portal Kombat #1**, **Matriochka**, **UN-notorious BIG**
disposent d'un bundle STIX publié par VIGINUM :
<https://github.com/VIGINUM-FR/Rapports-Techniques>. Ils sont importés tels quels,
au seul enrichissement près appliqué à l'import (`created_by_ref` = VIGINUM,
description FR, référence externe vers le PDF — voir
`misp-cti:provisioning/viginum/push_bundle.py`).

## Réimport

```sh
python -c "
from pycti import OpenCTIApiClient
c = OpenCTIApiClient('http://opencti:8080', '<TOKEN>')
c.stix2.import_bundle_from_json(open('viginum/2025-05_storm-1516.json').read(), update=True)
"
```
ou : OpenCTI → Data → Import → déposer le fichier (connecteur `import-file-stix`).

## Reconstruction

`misp-cti:provisioning/viginum/build.py` (générique, piloté par une spec YAML) +
`pdftotext -layout` sur le PDF source. Fidélité : seuls les entités, TTP (annexes
DISARM à T-codes) et IOC **explicitement présents dans le rapport** sont modélisés.

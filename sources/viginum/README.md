# VIGINUM — fiches de suivi

**VIGINUM** — Service de vigilance et de protection contre les ingérences
numériques étrangères (SGDSN, Premier ministre). Publie des rapports publics et
techniques sur les *modes opératoires informationnels* (MOI) étrangers visant le
débat public français.

- Publications : <https://www.sgdsn.gouv.fr/viginum/publications>
- Annexes techniques (STIX / CSV) : <https://github.com/VIGINUM-FR/Rapports-Techniques>
- `viginum.gouv.fr` n'est pas résolu depuis l'infra d'ingestion — tout passe par
  `sgdsn.gouv.fr` (même contenu) et le dépôt GitHub.
- Table de suivi machine : `misp-cti:importers/report_sources/viginum.yaml`

## Méthode

- Une fiche `articles/<date>_<slug>.md` par publication : synthèse fidèle au
  rapport, URL(s), MOI/acteurs cités, TTP DISARM si le rapport en liste, verdict.
- Si la publication donne lieu à un objet dans OpenCTI : fiche succincte
  `opencti/<slug>.md` (id du Report, entités clés, source du bundle, écarts).
- **Groupe A** : annexe STIX prête sur GitHub → import quasi direct.
- **Groupe B** : MOI/campagne nommé, entités à extraire des annexes du PDF.
- **Groupe C** : hors périmètre OpenCTI (méthodologie, guides, rapports
  d'activité, synthèses sans annexe) → fiche `articles/` seule.

## Inventaire (revu le 2026-09-03)

**19 publications recensées — 13 importées dans OpenCTI, 6 fiches seules (groupe C).**

| Date | Publication | Grp | État |
|---|---|:--:|---|
| 2026-06-11 | Protection du débat public — élections municipales mars 2026 | B | ✅ importé |
| 2026-06-11 | **Rokh Solis** — MOI ayant ciblé les municipales de mars 2026 | B | ✅ importé |
| 2026-03-13 | Kits de sensibilisation aux IEN | C | ✅ fiche |
| 2026-01-22 | Définitions du concept de MOI | C | ✅ fiche |
| 2025-12-30 | Rapport d'activité 2024 — VIGINUM | C | ✅ fiche |
| 2025-12-16 | Guide menace informationnelle — acteurs économiques | C | ✅ fiche |
| 2025-12-08 | Guide — débat public en contexte électoral | C | ✅ fiche |
| 2025-06-12 | **African Initiative** / AI-Freak (conjoint VIGINUM/FCDO/SEAE) | B | ✅ importé |
| 2025-05-06 | **Storm-1516** | B | ✅ importé |
| 2025-02-24 | Guerre en Ukraine — 3 ans d'opérations russes (synthèse) | B | ✅ importé |
| 2025-02-07 | Défis et « opportunités » de l'IA | C | ✅ fiche |
| 2025-02-04 | Roumanie / algorithmes & influenceurs (relais d'analyses tierces) | B | ✅ importé |
| 2024-12-02 | **UN-notorious BIG** — DROM-COM et Corse | A | ✅ importé |
| 2024-09-13 | Synthèse menace informationnelle — JOP Paris 2024 | B | ✅ importé |
| 2024-06-10 | **Matriochka** | A | ✅ importé |
| 2024-04-29 | **Portal Kombat** — extension du réseau (rapport 3) | B | ✅ importé |
| 2024-02-14 | **Portal Kombat** — suite des investigations (rapport 2) | B | ✅ importé |
| 2024-02-12 | **Portal Kombat** — réseau structuré (rapport 1) | A | ✅ importé |
| 2023-06-13 | **RRN** / Doppelgänger | A | ✅ importé |

Détail : `../../importers/report_sources/viginum.yaml` (misp-cti). Fiches par
rapport : `articles/` · fiches OpenCTI : `opencti/` · bundles réimportables :
`opencti/bundles/` · scripts : `misp-cti:provisioning/viginum/`.

## Journal des anomalies / limites

1. **UN-notorious BIG** — le bundle STIX natif de VIGINUM porte `published: 2024-03-27`,
   incohérent avec des faits d'octobre 2024 et une publication du 02/12/2024.
   **Corrigé à 2024-12-02** dans OpenCTI.
2. **Matriochka** — le bundle natif nomme la campagne « Matrioshka » (≠ titre du
   rapport « Matriochka », ≠ « Matryoshka » ailleurs). Conservé tel quel ; les fiches
   groupe B utilisent cette graphie pour éviter les doublons.
3. **Doublons d'identités Portal Kombat** — le bundle natif de PK1 contenait déjà
   `Yevgeny SHEVCHENKO` / `Denis SHEVCHENKO` ; le build PK2 les avait recréés en
   graphie FR. Doublons supprimés, graphies FR ajoutées en alias.
   → règle : **toujours vérifier les entités existantes avant d'en créer**.
4. **RRN** existe à la fois comme `Campaign` (bundle natif) et `Intrusion-Set`
   (référencé par les rapports groupe B). Divergence de type non résorbée.
5. **Extraction PDF** — les PDF VIGINUM ont une **couche texte fiable** :
   `pdftotext -layout` suffit, pas d'OCR d'image. Toutes les annexes d'IOC (300
   domaines Storm-1516, 224 Portal Kombat, 105 avatars African Initiative, etc.)
   ont été extraites ainsi et vérifiées (`grep` de recoupement dans le texte source).
6. **Rokh Solis** — IP 198.177.120[.]194 / [.]196 issues du rapport public
   « municipales 2026 » (le rapport technique cite [.]188) ; les trois conservées.
7. **DISARM** — les URL des techniques référencent l'`external_id` (T0xxx) ;
   OpenCTI les rattache à son catalogue DISARM natif s'il est chargé.

## Chaîne d'outillage (vanilla)

- **Groupe A** : `import_bundle_from_json` (pycti) des bundles natifs VIGINUM (GitHub).
- **Groupe B** : `pdftotext -layout` → `provisioning/viginum/build.py` (générique,
  piloté par une spec YAML) → `import_bundle_from_json`. Bundles conservés dans
  `opencti/bundles/` pour réimport (OpenCTI → Data → Import, ou pycti).
- **OpenCTI → MISP** : connecteur officiel **`opencti/connector-misp-intel`**
  (`opencti/docker-compose.yml`), live stream « VIGINUM -> MISP » filtré sur
  `entity_type = Report` ET `createdBy = VIGINUM`. Crée un event MISP par Report
  (tag `source:opencti`). Protection anti-boucle : `MISP_DETECT_ROUND_TRIP=true`
  + `source:opencti` dans le `MISP_IMPORT_TAGS_NOT` du connecteur d'import.
  ⚠️ `MISP_OWNER_ORG=VIGINUM-CTI` non honoré par le connecteur (events créés sous
  DeeL-CTI) — protection assurée par le tag.
4. **Storm-1516 / DISARM** — les URL des techniques pointent vers
   `disarmframework.herokuapp.com` ; à remplacer si OpenCTI résout déjà le catalogue DISARM.
5. **Doublons d'identités Portal Kombat** — le bundle STIX natif de PK1 contenait déjà
   `Yevgeny SHEVCHENKO` / `Denis SHEVCHENKO` ; le build PK2 les avait recréés en
   graphie française (`Evgueni CHEVTCHENKO` / `Denis CHEVTCHENKO`). Doublons supprimés,
   graphies FR ajoutées en alias sur les objets canoniques. → à l'avenir : toujours
   vérifier les entités déjà présentes avant d'en créer.
6. **Extraction PDF** — les PDF VIGINUM ont une **couche texte fiable** : `pdftotext -layout`
   suffit, pas besoin de transcrire depuis l'image. Storm-1516 : 300 domaines + annexes
   extraits ainsi.

## Chaîne d'outillage (vanilla)

- **Groupe A** : `import_bundle_from_json` (pycti) des bundles natifs VIGINUM (GitHub).
- **Groupe B** : `pdftotext -layout` → script de construction STIX par rapport
  (`misp-cti:provisioning/viginum/`) → `import_bundle_from_json`. Bundles conservés
  dans `opencti/bundles/` pour réimport.
- **OpenCTI → MISP** : connecteur officiel **`opencti/connector-misp-intel`**
  (`opencti/docker-compose.yml`), live stream « VIGINUM -> MISP » filtré sur
  `createdBy = VIGINUM`. Remplace tout import MISP manuel.
  ⚠️ en cours de réglage : filtre à restreindre aux `Report` (le stream capte aussi
  les `grouping` des bundles natifs), org propriétaire MISP `VIGINUM-CTI` à créer.
  Connecteur **arrêté** en attendant réglage.

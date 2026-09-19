# Flux CTI structurés : MISP et OpenCTI

Extrait du [catalogue](README.md) des seules sources dont la production est **directement ingérable** par une plateforme MISP ou OpenCTI, sans écrire de convertisseur.

> Revue : 2026-09-19 — chaque point d'entrée listé ici a été interrogé à cette date. Les volumes et les dates de dernière donnée sont ceux constatés, pas ceux annoncés par l'éditeur.

## Critère de retenue

Le catalogue principal classe les sources par ce qu'elles **disent** ; ce fichier les classe par ce qu'elles **émettent**. Une source n'y figure que si son format est celui de la plateforme.

| Section | Format retenu | Format écarté |
|---|---|---|
| **MISP** | feed MISP (`manifest.json` + un JSON par événement) · export d'événement MISP · galaxie ou warninglist au format MISP | CSV, TXT, JSON maison — même référencés dans les *default feeds* de MISP, qui les importe en `freetext`/`csv` : c'est MISP qui structure, pas la source |
| **OpenCTI** | bundle STIX 2.x (`"type": "bundle"`, objets `spec_version 2.1`) · collection TAXII 2.1 | STIX 1.x XML (non ingérable tel quel) · IOC en texte, YARA, Sigma |

**OpenCTI n'a pas de format propre.** Sa langue native est STIX 2.1 ; « publier au format OpenCTI » signifie donc publier des bundles STIX 2.1 ou exposer une collection TAXII 2.1. Aucune source du catalogue n'exporte un format spécifique à la plateforme.

Repère utile : la liste des *default feeds* de MISP ([`MISP/app/files/feed-metadata/defaults.json`](https://github.com/MISP/MISP/blob/2.4/app/files/feed-metadata/defaults.json)) compte 88 entrées, dont **8 seulement** en `source_format: misp`. Les 80 autres sont des blocklists que MISP parse — elles restent au §2.2 du catalogue, pas ici.

---

## 1. MISP

### 1.1 Feeds MISP complets

Un `manifest.json` et un fichier par événement : abonnables tels quels dans *Sync Actions → Feeds*.

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [CIRCL](https://www.circl.lu/doc/misp/feed-osint/) | §2.1 · §3 (LU) | `https://www.circl.lu/doc/misp/feed-osint/` | 1 680 événements, 2011-09-22 → 2026-08-13 | le feed de référence, produit par l'éditeur de MISP ; agrège plusieurs organisations contributrices (CIRCL, CthulhuSPRL.be, CERT-RLP…) |
| [abuse.ch — URLhaus](https://urlhaus.abuse.ch/downloads/misp/) | §2.1 | `https://urlhaus.abuse.ch/downloads/misp/` | 1 949 événements, dernier 2026-09-18 | un événement par jour d'IOC ; le manifeste répond sans authentification |
| [abuse.ch — ThreatFox](https://threatfox.abuse.ch/downloads/misp/) | §2.1 | `https://threatfox.abuse.ch/downloads/misp/` | 1 993 événements, dernier 2026-09-18 | idem ; la page d'export pousse désormais vers une URL de feed personnelle (Auth-Key, compte gratuit) — le chemin anonyme fonctionne encore |
| [abuse.ch — MalwareBazaar](https://bazaar.abuse.ch/downloads/misp/) | §2.1 | `https://bazaar.abuse.ch/downloads/misp/` | 1 918 événements, dernier 2026-09-07 | échantillons du jour |
| [Botvrij.eu](https://www.botvrij.eu/data/feed-osint/) | §2.1 | `https://www.botvrij.eu/data/feed-osint/` | 435 événements, 2013-08-07 → 2026-02-03 | feed OSINT de Koen Van Impe ; relaie aussi des événements ESET |
| [Infoblox](https://github.com/infobloxopen/threat-intelligence/tree/main/indicators/misp) | §7.1 (Amérique du Nord) | `https://raw.githubusercontent.com/infobloxopen/threat-intelligence/main/indicators/misp` (URL de feed ; le `manifest.json` répond, pas la racine) | 46 événements, 2022-04-08 → 2026-08-13 | **seul éditeur privé du catalogue, à cette revue, à publier un feed MISP complet** ; un événement par campagne DNS (malvertising, *drop catch*, smishing) ; dépôt actif (2026-09-15) |
| [CERT-FR / ANSSI](https://misp.cert.ssi.gouv.fr/feed-misp/) | §3 (France) | `https://misp.cert.ssi.gouv.fr/feed-misp/` | 18 événements, dernier daté 2024-06-04 (fichiers régénérés 2026-04-09) | feed public, non listé dans les *defaults* MISP ; dormant depuis mi-2024 mais toujours servi, avec un `hashes.csv` agrégé |
| [DigitalSide](https://github.com/davidonzo/Threat-Intel/tree/master/digitalside-misp-feed) | §11 | `https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/` · miroir `raw.githubusercontent.com/davidonzo/Threat-Intel/master/digitalside-misp-feed/` | 1 062 événements, 2022-10-03 → **2024-10-18** | **arrêté.** Le site ne répond plus (le DNS résout, l'hôte non) et le dépôt GitHub n'a plus reçu de commit depuis le 2024-10-18. Reste dans les *defaults* MISP |
| ~~bin.re / Rösti~~ | §11 | `https://rosti.64617461.xyz/downloads/misp/` | — | **mort** : le domaine ne résout plus. Entrée encore présente dans les *defaults* MISP |

### 1.2 Événements MISP isolés

Pas de manifeste : des exports d'événement à importer un par un (*Import from MISP export*).

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [ESET](https://github.com/eset/malware-ioc) | §7.1 (Europe) | `eset/malware-ioc`, fichiers `*misp*.json` | 60 fichiers d'événement dans 26 des 148 dossiers ; dernière mise à jour d'un événement 2026-06-09 | **pratique non documentée dans le README du catalogue.** Le dépôt est très actif (2026-09-17) mais les campagnes récentes ne sont livrées qu'en `samples.sha256` : l'export MISP est intermittent. Couvre Turla, Winnti, Gelsemium, BackdoorDiplomacy, Winter Vivern… |
| [AssoEchap — stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | §7.2 (Mobile) | `generated/misp_event.json` | 1 événement, 1 692 objets MISP, régénéré 2026-06-21 | événement unique tenu à jour ; publie **aussi** un bundle STIX 2.1 (§2.1 ci-dessous) |
| [GovCERT.ch](https://github.com/govcert-ch/CTI) | §3 (Suisse) | `20241202_LummaStealer/misp.event.31002.json` | 1 événement, 112 attributs, 2024-12-02 | export `restSearch` complet (*Op Emmenhtal malspam spreading Lumma Stealer in Switzerland*) ; ponctuel, le reste du dépôt est en CSV/TXT |
| [TTC-CERT](https://github.com/ttc-cert/TTC-CERT-MISP-Shared-Events) | §3 (Thaïlande) | `ttc-cert/TTC-CERT-MISP-Shared-Events` | 9 événements, figé 2024-05-23 | Sharp Panda, Mustang Panda, infostealers visant la Thaïlande ; dates en calendrier bouddhique dans les noms de fichiers |

### 1.3 Contenu MISP natif hors événements

Ni IOC ni rapports : le référentiel et les garde-fous. À charger avant les feeds, sous peine d'ingérer des faux positifs et de dupliquer les acteurs.

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [MISP Galaxy](https://github.com/MISP/misp-galaxy) | §1 | `MISP/misp-galaxy`, `clusters/` | 135 clusters, 2026-09-18 | la table de correspondance des alias ; également consommée par OpenCTI |
| [MISP warninglists](https://github.com/MISP/misp-warninglists) | §16 | `MISP/misp-warninglists` | 2026-09-08 | listes de faux positifs |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/usage/api) | §1 | `https://malpedia.caad.fkie.fraunhofer.de/api/get/misp` | ~4 Mo, sans clé (*access limitation: none*) | vue courante de Malpedia **au format galaxy cluster MISP** ; le reste de l'API demande une clé |
| [Deutsche Telekom](https://github.com/telekom-security/misp-warning-lists) | §6 | `telekom-security/misp-warning-lists`, `lists/` | 229 warninglists, 2026-09-19 | plages IP de scanners et de fournisseurs cloud, au format warninglist MISP, mises à jour quotidiennement ; **production distincte de T-Pot, seule citée au catalogue** |

### 1.4 MISP sous condition

| Source | § README | Modalité |
|---|---|---|
| [CERT-UA](https://cert.gov.ua) | §3 (Ukraine) | instance MISP accessible sur demande, hors ligne publique |
| [CERT.LV](https://www.cert.lv/en/data-feed) | §3 (Lettonie) | *data feed* national sur demande, contenu réservé |
| [RST Cloud](https://github.com/rstcloud/rstcloud_misp) | §1 | importateur officiel créant événements, attributs et clusters dans MISP — mais depuis un flux commercial sous licence |

---

## 2. OpenCTI (STIX 2.1)

### 2.1 Bundles STIX 2.1 publiés

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) | §1 | `mitre-attack/attack-stix-data` (`enterprise-attack/`, `mobile-attack/`, `ics-attack/`, `index.json`) | 2026-08-05 | la base STIX 2.1 de référence ; versionnée, avec un index machine |
| [Elastic Security Labs](https://github.com/elastic/labs-releases) | §7.1 (Amérique du Nord) | `elastic/labs-releases`, `indicators/<campagne>/stix-bundle.json` | 23 bundles, dépôt actif 2026-09-11 | **seul éditeur privé du catalogue, à cette revue, à publier ses IOC en bundles STIX 2.1**, un par famille ou campagne (BLISTER, BITSLOTH, WARMCOOKIE, SHELLTER…) ; livre aussi un convertisseur STIX→ECS |
| [MVT — mvt-indicators](https://github.com/mvt-project/mvt-indicators) | §7.2 (Mobile) | `mvt-project/mvt-indicators`, `<campagne>/*.stix2` | 14 bundles, dépôt actif 2026-08-27 | spyware mobile (Predator, Triangulation, Candiru, Cellebrite, EagleMsgSpy, Spyrtacus…) ; corpus STIX 2.1 le plus vivant du catalogue |
| [Amnesty Tech](https://github.com/AmnestyTech/investigations) | §7.2 (Mobile) | `AmnestyTech/investigations`, `<enquête>/*.stix2` | 5 bundles, dernier 2024-12-16 (NoviSpy / Serbie) | chaque enquête embarque son `generate_stix.py` ; rythme dicté par les publications, pas par un pipeline |
| [AssoEchap — stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | §7.2 (Mobile) | `generated/stalkerware.stix2` | 12 320 objets STIX 2.1 (6 073 indicateurs, 174 malwares), 2026-06-21 | bundle unique régénéré ; seule source du catalogue à publier **en parallèle** un événement MISP et un bundle STIX 2.1 du même corpus |
| [CTID — Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/example_flows/) | §9 | `.../corpus/<nom>.json` (le dépôt ne versionne que les `.afb`) | 41 flux, dépôt actif 2026-09-09 | bundles STIX 2.1 portant l'extension *attack-flow* : les SDO/SCO standards s'ingèrent, les objets `attack-action` / `attack-flow` demandent la définition d'extension livrée dans le bundle |
| [DigitalSide](https://github.com/davidonzo/Threat-Intel/tree/master/stix2) | §11 | `davidonzo/Threat-Intel`, `stix2/` | 1 000+ bundles, **figé 2024-10-18** | un bundle par échantillon (`report`, `indicator`, `malware`, `observed-data`) ; même arrêt que le feed MISP |

### 2.2 TAXII 2.1

| Source | § README | Point d'entrée | État |
|---|---|---|---|
| [MITRE ATT&CK](https://attack-taxii.mitre.org/api/v21/) | §1 | `https://attack-taxii.mitre.org/api/v21/collections/` | **ouvert, sans authentification** ; collections Enterprise / Mobile / ICS. Exige l'en-tête `Accept: application/taxii+json;version=2.1` — sans lui le serveur renvoie 400 |
| [DigitalSide](https://osint.digitalside.it/taxiiserver.html) | §11 | `https://osint.digitalside.it/taxii2` (`guest` / `guest`) | **injoignable** à la revue ; rétention annoncée 24 h |
| [CISA — AIS](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/automated-indicator-sharing-ais) | §3 (États-Unis) | connexion TAXII 2.1 bidirectionnelle | **sous convention** : *Terms of Use* pour les organisations non fédérales, MISA pour les fédérales. Pas un flux ouvert |

### 2.3 Référence méthodologique

| Source | § README | Point d'entrée | Commentaire |
|---|---|---|---|
| [VIGINUM — Doctrine OpenCTI](https://github.com/VIGINUM-FR/Doctrine-OpenCTI) | §3 (France) · §13 | `SGDSN_VIGINUM_DoctrineOpenCTI.pdf` (FR/EN), 2025-04-24 | pas de données : le cadre de capitalisation de la menace informationnelle dans OpenCTI publié par le SGDSN. Fait suite au guide d'utilisation de janvier 2024 |

### 2.4 STIX 1.x — non ingérable tel quel

OpenCTI ne lit pas le STIX 1.x XML. Ces corpus demandent une conversion préalable et sont, de toute façon, historiques.

| Source | § README | Point d'entrée | Dernière donnée |
|---|---|---|---|
| [Citizen Lab](https://github.com/citizenlab/malware-indicators) | §7.2 (Mobile) · §9 | `<enquête>/stix.xml` | 21 fichiers, dernier dossier 2020-06 (DarkBasin) ; dépôt figé 2020-10 |
| [Meta](https://github.com/facebook/threat-research) | §7.1 (Amérique du Nord) | `indicators/stix1/*.xml` | 13 fichiers, dernier 2023-05 ; le dépôt reste actif sur d'autres formats |

---

## 3. Pièges

- **« Présent dans les *default feeds* de MISP » ne veut pas dire « feed MISP ».** ELLIO, Bambenek, DataPlane, IPsum, Phishing.Database, threatview.io, hole.cert.pl, eCrimeLabs, APNIC Honeynet, OpenPhish, PhishTank y figurent en `freetext` ou `csv` : ce sont des blocklists que MISP découpe lui-même. Elles restent au §2.2 du catalogue.
- **Un dépôt vivant ne garantit pas un flux vivant.** ESET pousse du code toutes les semaines mais n'a pas rafraîchi d'événement MISP depuis juin 2026 ; DigitalSide affiche une organisation soignée pour un pipeline arrêté depuis octobre 2024. Vérifier la date du contenu, pas celle du dépôt.
- **Les miroirs ne sont pas des sources.** `blackorbird/APT_REPORT` (§11) contient une dizaine de `.stix2` qui sont des copies de MVT et d'Amnesty Tech ; `CyberMonitor/APT_CyberCriminal_Campagin_Collections` (§11) archive des STIX et des événements MISP joints à d'anciens rapports. Utiles en archive, jamais en amont d'un pipeline.
- **Un index de feeds n'est pas un feed.** `rodanmaharjan/ThreatIntelligence` (§11) publie un `MISP_Feed_index.json` de 118 définitions, chargeable d'un bloc dans MISP — mais 117 en `freetext` et 1 en `csv`, aucune native.
- **Sekoia.io** (§7.1) publie un unique `IOCs/apt31/2021-11-10 APT31 - STIX2.jsonl` dans son dépôt *Community* : une exception de 2021, pas une pratique. Le reste est en texte, YARA et Sigma.

## 4. Écart relevé avec le catalogue

- **DigitalSide** est daté « 2026-09-06 » au §11 du README. Le dépôt `davidonzo/Threat-Intel` n'a reçu aucun commit depuis le **2024-10-18** et `osint.digitalside.it` ne répond plus. À corriger à la prochaine revue.
- **ESET** (§7.1) et **Deutsche Telekom** (§6) publient des formats MISP que leur ligne au catalogue ne mentionne pas.

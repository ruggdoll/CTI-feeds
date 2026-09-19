# Flux CTI structurés : MISP et OpenCTI

Extrait du [catalogue](README.md) des seules sources dont la production est **directement ingérable** par une plateforme MISP ou OpenCTI, sans écrire de convertisseur.

> Revue : 2026-09-19 — chaque point d'entrée listé ici a été interrogé à cette date. Les volumes et les dates de dernière donnée sont ceux constatés, pas ceux annoncés par l'éditeur. La méthode de recherche et ses angles morts sont en §4.

## Critère de retenue

Le catalogue principal classe les sources par ce qu'elles **disent** ; ce fichier les classe par ce qu'elles **émettent**. Une source n'y figure que si son format est celui de la plateforme.

| Section | Format retenu | Format écarté |
|---|---|---|
| **MISP** | feed MISP (`manifest.json` + un JSON par événement) · export d'événement MISP · galaxie ou warninglist au format MISP | CSV, TXT, JSON maison — même référencés dans les *default feeds* de MISP, qui les importe en `freetext`/`csv` : c'est MISP qui structure, pas la source |
| **OpenCTI** | bundle STIX 2.x (`"type": "bundle"`, objets `spec_version 2.1`) · collection TAXII 2.1 | STIX 1.x XML (non ingérable tel quel) · TAXII 1.x · IOC en texte, YARA, Sigma |

**OpenCTI n'a pas de format propre.** Sa langue native est STIX 2.1 ; « publier au format OpenCTI » signifie donc publier des bundles STIX 2.1 ou exposer une collection TAXII 2.1. Aucune source ne publie un format spécifique à la plateforme ; quelques-unes exportent depuis OpenCTI (propriétés `x_opencti_*`), ce qui est signalé.

Repère : la liste des *default feeds* de MISP dépend de la branche. Sur `2.4` ([`defaults.json`](https://github.com/MISP/MISP/blob/2.4/app/files/feed-metadata/defaults.json)) : 88 entrées, 8 en `source_format: misp`. Sur `2.5` / `develop` : **107 entrées, 18 natives** — TweetFeed y a été ajouté le 2026-09-15, NOCACTI en décembre 2025. Les autres entrées sont des blocklists que MISP découpe lui-même ; elles restent au §2.2 du catalogue.

---

## 1. MISP

### 1.1 Feeds MISP complets

Un `manifest.json` et un fichier par événement : abonnables tels quels dans *Sync Actions → Feeds* (pointer le répertoire, MISP ajoute `/manifest.json`).

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [CIRCL](https://www.circl.lu/doc/misp/feed-osint/) | §2.1 · §3 (LU) | `https://www.circl.lu/doc/misp/feed-osint/` | 1 680 événements, 2011-09-22 → 2026-08-13 | le feed de référence, produit par l'éditeur de MISP ; agrège plusieurs organisations contributrices. Le même feed est **converti en STIX 2.1** par CIRCL (§2.1) |
| [abuse.ch — URLhaus](https://urlhaus.abuse.ch/downloads/misp/) | §2.1 | `https://urlhaus.abuse.ch/downloads/misp/` | 1 949 événements, dernier 2026-09-18 | un événement par jour ; le manifeste répond sans authentification |
| [abuse.ch — ThreatFox](https://threatfox.abuse.ch/downloads/misp/) | §2.1 | `https://threatfox.abuse.ch/downloads/misp/` | 1 993 événements, dernier 2026-09-18 | idem ; la page d'export pousse vers une URL de feed personnelle (Auth-Key, compte gratuit) — le chemin anonyme fonctionne encore |
| [abuse.ch — MalwareBazaar](https://bazaar.abuse.ch/downloads/misp/) | §2.1 | `https://bazaar.abuse.ch/downloads/misp/` | 1 918 événements, dernier 2026-09-07 | échantillons du jour |
| [Botvrij.eu](https://www.botvrij.eu/data/feed-osint/) | §2.1 | `https://www.botvrij.eu/data/feed-osint/` | 435 événements, 2013-08-07 → 2026-02-03 | feed OSINT de Koen Van Impe ; relaie aussi des événements ESET |
| [CSIRT Italia / ACN](https://www.acn.gov.it/portale/en/csirt-italia/misp) | §3 (Italie) | `https://www.csirt.gov.it/feed-misp/` | 60 événements, 2026-09-16 → 2026-09-19 (fenêtre glissante) | **CSIRT national italien, absent du catalogue jusqu'à cette revue.** Tout IoC TLP:CLEAR de l'agence passe par ce feed ; renouvelé quotidiennement |
| [CERT-FR / ANSSI](https://misp.cert.ssi.gouv.fr/feed-misp/) | §3 (France) | `https://misp.cert.ssi.gouv.fr/feed-misp/` | 18 événements, dernier daté 2024-06-04 (fichiers régénérés 2026-04-09) | feed public annoncé par [CERTFR-2022-IOC-001](https://www.cert.ssi.gouv.fr/ioc/CERTFR-2022-IOC-001/) ; dormant depuis mi-2024 mais toujours servi, avec un `hashes.csv` agrégé |
| [Infoblox](https://github.com/infobloxopen/threat-intelligence/tree/main/indicators/misp) | §7.1 (Amérique du Nord) | `https://raw.githubusercontent.com/infobloxopen/threat-intelligence/main/indicators/misp` | 46 événements, 2022-04-08 → 2026-08-13 | un événement par campagne DNS (malvertising, *drop catch*, smishing) ; dépôt actif (2026-09-15) |
| [TweetFeed](https://tweetfeed.live/feeds/) | §11 | `https://tweetfeed.live/misp` (miroir `0xDanielLopez/TweetFeed`, `misp/`) | 365 événements (un par jour, fenêtre glissante d'un an), dernier 2026-09-19 | régénéré toutes les 15 minutes ; CC0. Publie **aussi** des bundles STIX 2.1 et un serveur TAXII 2.1 (§2) |
| [Rösti](https://rosti.dev/misp) | §11 | `https://misp.rosti.dev/` | 9 636 événements, 2026-06-16 → 2026-09-18 | *Repackaged Öpen Source Threat Intelligence* (Johannes Bader, auteur de bin.re) : un événement par rapport public, IOC extraits automatiquement de 292 sources. **Réemballage**, pas production : la provenance est celle du rapport cité. Remplace `rosti.64617461.xyz`, mort |
| [PrecisionSec — OSINT](https://precisionsec.com/free-misp-feed/) | §7.2 (C2) | `https://misp-osint.precisionsec.com/` | 864 événements, 2026-07-25 → 2026-08-22 | sous-ensemble du feed commercial (ClickFix), **retardé de 30 jours**, fenêtre glissante de 30 jours ; vitrine d'un produit payant |
| [Rectifyq](https://rectifyq.com/) | §7.1 (Asie du Sud-Est) | `https://feeds.rectifyq.com/MISP2026/` (aussi `MISP2024/`, `MISP2025/`, `MISP-ICS-OT/`, `MISP-MY/`) | 867 événements en 2026 (→ 2026-07-30) ; 1 283 en 2025 ; 551 en 2024 ; ICS-OT 101 ; Malaisie 214 | initiative malaisienne, un événement par entrée de renseignement ; cinq feeds par année et par thème |
| [SiberKapan](https://siberkapan.org/misp-feed/) | §2.1 | `https://siberkapan.org/misp-feed/` | 60 événements, 2026-07-22 → 2026-09-19 | plateforme communautaire turque (honeypots, capteurs FortiGate) ; publie **aussi** un bundle STIX 2.1 et un serveur TAXII 2.1 (§2), et **republie la liste USOM** que l'agence ne diffuse plus en clair (§3, Turquie) |
| [ThreatCluster](https://threatcluster.io/) | §11 | `https://threatcluster.io/misp` | 9 événements, 2026-09-13 → 2026-09-16 (fenêtre glissante) | agrégateur (20 000 sources, résumés IA) ; serveur lent (504 à la première tentative) |
| [chrome-mal-ids](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids) | §2.2 | `https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/formats/misp-feed` | 187 événements, régénérés 2026-09-18 | identifiants d'extensions Chrome malveillantes, agrégés depuis les publications des éditeurs ; publie **aussi** un bundle STIX 2.1 (§2.1) |
| [APTtrail](https://trilwu.github.io/apttrail/) | §11 | `https://trilwu.github.io/apttrail/misp-feed/` | 340 événements (un par groupe), générés 2026-08-15 | **réemballage des trails APT de Maltrail** (§2.2) avec correspondance ATT&CK ; annoncé « horaire », dernière génération un mois avant la revue |
| [xfeeds](https://github.com/neilweitzel/xfeeds) | §11 | `https://raw.githubusercontent.com/neilweitzel/xfeeds/main/feeds` (`misp-manifest.json`) | 1 événement, 2026-09-19 | agrégat de blocklists IP ne retenant que les IP corroborées par plusieurs sources indépendantes ; publie **aussi** un bundle STIX 2.1 |
| [NOCACTI](https://misp-feed.nocacti.com/Intrusion/) | — | `https://misp-feed.nocacti.com/Intrusion/` · `…/AdversaryInfrastructure/` | 3 + 1 événements, 2026-09-01 | ajouté aux *defaults* MISP 2.5.31 ; le site n'expose qu'une page de connexion MISP, aucune information sur le producteur. Non retenu au catalogue |
| [cyberdefense.blue](https://github.com/RedBlue232/threat-feed-publisher) | — | `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/misp-feed` | 3 événements (un par périmètre), 2026-04-27 | IP vues par **un seul** capteur CrowdSec/Suricata en France, fenêtre de 7 jours. Non retenu au catalogue |
| [DigitalSide](https://github.com/davidonzo/Threat-Intel/tree/master/digitalside-misp-feed) | §11 | `https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/` | 1 062 événements, 2022-10-03 → **2024-10-18** | **arrêté.** Le site ne répond plus (le DNS résout, l'hôte non) et le dépôt GitHub n'a plus reçu de commit depuis le 2024-10-18. Reste dans les *defaults* MISP |

### 1.2 Événements MISP isolés

Pas de manifeste : des exports d'événement à importer un par un (*Import from MISP export*).

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [ESET](https://github.com/eset/malware-ioc) | §7.1 (Europe) | `eset/malware-ioc`, fichiers `*misp*.json` | 60 fichiers d'événement dans 26 des 148 dossiers ; dernière mise à jour d'un événement 2026-06-09 | le dépôt est très actif (2026-09-17) mais les campagnes récentes ne sont livrées qu'en `samples.sha256` : l'export MISP est intermittent. Couvre Turla, Winnti, Gelsemium, BackdoorDiplomacy, Winter Vivern… |
| [HvS-Consulting](https://github.com/hvs-consulting/ioc_signatures) | §7.1 (Europe) | `hvs-consulting/ioc_signatures`, fichiers `*Misp-Event.json` | 4 événements : Black Basta (2024-04, 2024-11), feed T3 2024, BlueHammer (2026-04-08, 5 attributs) | société de réponse à incident allemande ; un export MISP par rapport, à côté des YARA et CSV. Un export XML plus ancien (APT27, 2021) |
| [AssoEchap — stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | §7.2 (Mobile) | `generated/misp_event.json` | 1 événement, 1 692 objets MISP, régénéré 2026-06-21 | événement unique tenu à jour ; publie **aussi** un bundle STIX 2.1 (§2.1) |
| [GovCERT.ch](https://github.com/govcert-ch/CTI) | §3 (Suisse) | `20241202_LummaStealer/misp.event.31002.json` | 1 événement, 112 attributs, 2024-12-02 | export `restSearch` complet ; ponctuel, le reste du dépôt est en CSV/TXT |
| [TTC-CERT](https://github.com/ttc-cert/TTC-CERT-MISP-Shared-Events) | §3 (Thaïlande) | `ttc-cert/TTC-CERT-MISP-Shared-Events` | 9 événements, figé 2024-05-23 | Sharp Panda, Mustang Panda, infostealers visant la Thaïlande |

### 1.3 Contenu MISP natif hors événements

Ni IOC ni rapports : le référentiel et les garde-fous. À charger avant les feeds, sous peine d'ingérer des faux positifs et de dupliquer les acteurs.

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [MISP Galaxy](https://github.com/MISP/misp-galaxy) | §1 | `MISP/misp-galaxy`, `clusters/` | 135 clusters, 2026-09-18 | la table de correspondance des alias ; également consommée par OpenCTI |
| [MISP warninglists](https://github.com/MISP/misp-warninglists) | §16 | `MISP/misp-warninglists` | 2026-09-08 | listes de faux positifs |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/usage/api) | §1 | `https://malpedia.caad.fkie.fraunhofer.de/api/get/misp` | ~4 Mo, sans clé | vue courante de Malpedia **au format galaxy cluster MISP** ; le reste de l'API demande une clé |
| [Deutsche Telekom](https://github.com/telekom-security/misp-warning-lists) | §6 | `telekom-security/misp-warning-lists`, `lists/` | 229 warninglists, 2026-09-19 | plages IP de scanners et de fournisseurs cloud, mises à jour quotidiennement ; production distincte de T-Pot |

### 1.4 MISP sous condition

Instances ou feeds qui existent mais ne s'obtiennent pas par une URL publique.

| Source | § README | Modalité |
|---|---|---|
| [ICS-CSIRT.io](https://www.ics-csirt.io/threats.html) | §5 | communauté ICS animée depuis la Belgique (cudeso.be) : adhésion **gratuite** sur demande, puis synchronisation MISP ou export CSV/JSON/TXT/STIX |
| [CERT-AGID](https://cert-agid.gov.it/tag/ioc/) | §3 (Italie) | flux IoC réservé aux administrations publiques accréditées : instance MISP ou client CNTI de l'agence |
| [AusCERT](https://auscert.org.au/services/threat-intelligence/) | — | instance MISP réservée aux membres, incluant le flux CTIS de l'ACSC |
| [CSIRT de Gobierno](https://csirt.gob.cl/servicios/intercambio-de-indicadores-de-compromiso/) | §3 (Chili) | serveur MISP partagé avec les services publics chiliens connectés |
| [PISAX](https://misp.pisax.org/) | — | ISAC paneuropéen des points d'échange Internet ; instance MISP sur compte |
| [CERT-UA](https://cert.gov.ua) | §3 (Ukraine) | instance MISP accessible sur demande |
| [CERT.LV](https://www.cert.lv/en/data-feed) | §3 (Lettonie) | *data feed* national sur demande, contenu réservé |
| [RST Cloud](https://github.com/rstcloud/rstcloud_misp) | §1 | importateur officiel créant événements, attributs et clusters dans MISP — depuis un flux commercial sous licence |

---

## 2. OpenCTI (STIX 2.1)

### 2.1 Bundles STIX 2.1 publiés — production propre

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) | §1 | `mitre-attack/attack-stix-data` (`enterprise-attack/`, `mobile-attack/`, `ics-attack/`, `index.json`) | 2026-08-05 | la base STIX 2.1 de référence ; versionnée, avec un index machine |
| [Elastic Security Labs](https://github.com/elastic/labs-releases) | §7.1 (Amérique du Nord) | `elastic/labs-releases`, `indicators/<campagne>/stix-bundle.json` | 23 bundles, dépôt actif 2026-09-11 | un bundle par famille ou campagne (BLISTER, BITSLOTH, WARMCOOKIE, SHELLTER…) ; le seul éditeur privé du catalogue à le faire |
| [PhishDestroy](https://github.com/phishdestroy/destroylist) | §2.2 | `destroylist`, `stix/bundle.json` · dossiers de preuves `*-evidence/data/ioc/stix-bundle.json` | 122 617 indicateurs (2026-08-17) ; ShortDot 5 006 ; NameSilo, NICENIC, Trustname | blocklist de phishing et d'arnaque (205 000 domaines) ; les dossiers *evidence* documentent l'abus par registrar ou par TLD avec un bundle par dossier |
| [MVT — mvt-indicators](https://github.com/mvt-project/mvt-indicators) | §7.2 (Mobile) | `mvt-project/mvt-indicators`, `<campagne>/*.stix2` | 14 bundles, dépôt actif 2026-08-27 | spyware mobile (Predator, Triangulation, Candiru, Cellebrite, EagleMsgSpy, Spyrtacus, Coruna, DarkSword…) |
| [Amnesty Tech](https://github.com/AmnestyTech/investigations) | §7.2 (Mobile) | `AmnestyTech/investigations`, `<enquête>/*.stix2` | 5 bundles, dernier 2024-12-16 (NoviSpy / Serbie) | rythme dicté par les publications |
| [AssoEchap — stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | §7.2 (Mobile) | `generated/stalkerware.stix2` | 12 320 objets (6 073 indicateurs, 174 malwares), 2026-06-21 | bundle unique régénéré ; publie en parallèle l'événement MISP du même corpus |
| [chrome-mal-ids](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids) | §2.2 | `formats/chrome-mal-ids-stix.json` | 7 398 indicateurs, 55 objets `malware`, 2026-09-18 | extensions Chrome malveillantes ; même corpus que le feed MISP |
| [Threat Actors' use of AI (cybershujin)](https://github.com/cybershujin/Threat-Actors-use-of-Artifical-Intelligence) | §11 | `stix/threat-actors-ai-stix2.1.json` | 1 659 objets dont 115 `intrusion-set`, 209 indicateurs ; 2026-09-14 | recension de l'usage de l'IA par les acteurs (rapports OpenAI, Anthropic, Google…) structurée en STIX ; bundle généré depuis le README |
| [DoGoodCybersecurity](https://github.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed) | §2.1 | `daily/<date>.json` | 382 bundles quotidiens ; 2 715 indicateurs le 2026-09-17 | IP vues par un réseau de honeypots distribué ; le site du projet ne répond pas, seul le dépôt fait foi |
| [SiberKapan](https://siberkapan.org/api-docs) | §2.1 | `https://siberkapan.org/api/v1/stix` | bundle courant (188 Ko), sans clé | même corpus que le feed MISP et la collection TAXII |
| [TweetFeed](https://tweetfeed.live/feeds/) | §11 | `https://tweetfeed.live/stix/today.json` · `week.json` · `month.json` (`manifest.json` les décrit) | 64 indicateurs le 2026-09-19 (jour) | même corpus que le feed MISP |
| [CIRCL — feed OSINT en STIX 2.1](https://codeberg.org/adulau/misp-circl-feed) | §2.1 | `feeds/circl/stix-2.1/<uuid>.json` (Codeberg ; miroir `helga.circl.lu` fermé aux robots) | un bundle par événement (ex. 991 objets) ; dernier commit 2026-02-02 | conversion officielle du feed MISP par `misp-stix` ; l'API Codeberg répond par intermittence (504), les fichiers bruts oui |
| [The Hunter's Ledger](https://github.com/PixelatedContinuum/Threat-Intel-Reports) | §11 | `stix/*.json` | 43 bundles, dépôt actif 2026-09-19 | recherche originale d'un analyste indépendant (RAT, open directories, sites de fuite) ; bundles exportés d'OpenCTI (`x_opencti_*`) |
| [CTID — Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/example_flows/) | §9 | `.../corpus/<nom>.json` (le dépôt ne versionne que les `.afb`) | 41 flux, dépôt actif 2026-09-09 | extension *attack-flow* : les SDO/SCO standards s'ingèrent, les objets `attack-action` / `attack-flow` demandent la définition d'extension livrée dans le bundle |
| [DigitalSide](https://github.com/davidonzo/Threat-Intel/tree/master/stix2) | §11 | `davidonzo/Threat-Intel`, `stix2/` | 1 000+ bundles, **figé 2024-10-18** | même arrêt que le feed MISP |

### 2.2 Bundles STIX 2.1 — agrégats et réemballages

Ingérables, mais la provenance est celle des sources amont : à charger avec un niveau de confiance propre, jamais comme production originale.

| Source | § README | Point d'entrée | Volume / dernière donnée | Amont |
|---|---|---|---|---|
| [APTtrail](https://trilwu.github.io/apttrail/) | §11 | release `apttrail_threat_feed_stix.json` (164 Mo) | 172 923 indicateurs, 340 `intrusion-set` ; généré 2026-08-15 | trails APT de Maltrail (§2.2), enrichis d'identifiants ATT&CK |
| [xfeeds](https://github.com/neilweitzel/xfeeds) | §11 | `feeds/stix-bundle.json` | 8 429 indicateurs, 2026-09-19 | blocklists IP publiques, corroboration multi-sources |
| [TI-Collector — CTAC MY](https://github.com/r4y79/ti-feed) | — | `taxii2/` (arbre TAXII 2.1 statique) · `feeds/*.txt` | 2 005 indicateurs sur 24 h, 2026-09-18 | feeds amont republiés (certificats SSLBL, domaines, hash) + CISA KEV 30 jours ; producteur non identifié. Non retenu au catalogue |
| [Rösti](https://rosti.dev/feeds) | §11 | API v2 (clé sur compte) — le format STIX est annoncé, non vérifié ici ; le feed MISP (§1.1) est public | — | rapports publics de 292 sources |

### 2.3 Référentiels STIX 2.1

Pas d'observables : les cadres à charger une fois, qui donnent aux rapports leurs `attack-pattern`, `identity` et `location`.

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [MITRE CAPEC](https://github.com/mitre/cti/tree/master/capec/2.1) | §1 | `mitre/cti`, `capec/2.1/stix-capec.json` | 2 666 objets (615 `attack-pattern`), 2023-01-30 | le dépôt `mitre/cti` porte aussi ATT&CK en STIX 2.0 ; pour ATT&CK, préférer `attack-stix-data` |
| [MITRE ATLAS](https://github.com/mitre-atlas/atlas-navigator-data) | §1 | `dist/stix-atlas.json` · `dist/stix-atlas-attack-enterprise.json` | 538 objets (170 `attack-pattern`, 35 `course-of-action`), 2026-04-30 | tactiques et techniques contre les systèmes d'IA ; `atlas-data` (source) actif 2026-09-15 |
| [DISARM Foundation](https://github.com/DISARMFoundation/DISARMframeworks) | §13 | `generated_files/DISARM_STIX/DISARM.json` | 698 objets (391 `attack-pattern`, 16 tactiques), 2024-11-22 | cadre de description des opérations de manipulation de l'information ; connecteur OpenCTI officiel |
| [CTID — Sensor Mappings to ATT&CK](https://github.com/center-for-threat-informed-defense/sensor-mappings-to-attack) | §9 | `mappings/stix/enterprise/*.json` | 7 bundles (Sysmon, Auditd, Zeek, CloudTrail, OSQuery, WinEvtx…), 2025-06-21 | objets `x-mitre-sensor-mapping` : quelle source de journal couvre quelle composante de donnée ATT&CK |
| [Filigran — OpenCTI datasets](https://github.com/OpenCTI-Platform/datasets) | §1 | `data/sectors.json` · `geography.json` · `companies.json` | secteurs : 121 objets (72 `identity`) ; 2026-06-07 | référentiels de secteurs, pays et régions que les connecteurs OpenCTI utilisent ; utile pour aligner ses propres `identity` |
| [VIGINUM — Doctrine OpenCTI](https://github.com/VIGINUM-FR/Doctrine-OpenCTI) | §3 (France) · §13 | `SGDSN_VIGINUM_DoctrineOpenCTI.pdf` (FR/EN) | 2025-04-24 | pas de données : le cadre de capitalisation de la menace informationnelle dans OpenCTI publié par le SGDSN |

### 2.4 TAXII

| Source | § README | Point d'entrée | État |
|---|---|---|---|
| [MITRE ATT&CK](https://attack-taxii.mitre.org/api/v21/) | §1 | `https://attack-taxii.mitre.org/api/v21/collections/` | **TAXII 2.1 ouvert**, sans authentification ; collections Enterprise / Mobile / ICS. Exige l'en-tête `Accept: application/taxii+json;version=2.1` — sans lui le serveur renvoie 400 |
| [TweetFeed](https://tweetfeed.live/api/) | §11 | `https://tweetfeed.live/taxii2/` | **TAXII 2.1 ouvert** ; Cloudflare refuse les User-Agent `python-urllib` et `libwww-perl` |
| [SiberKapan](https://siberkapan.org/taxii/) | §2.1 | `https://siberkapan.org/taxii/` (API root `…/taxii/api-root/`) | **TAXII 2.1 ouvert** ; trois collections : toutes menaces, score ≥ 75, honeypots |
| [TI-Collector — CTAC MY](https://github.com/r4y79/ti-feed) | — | `taxii2/api/collections/<id>/` sur GitHub | arbre TAXII 2.1 **statique** (fichiers JSON servis par `raw.githubusercontent.com`) ; voir §2.2 |
| [EclecticIQ — collections publiques](https://www.eclecticiq.com/public-feed-manual) | §7.1 (Europe) | `https://cti.eclecticiq.com/taxii/discovery` (POST) · `…/taxii/poll` | **TAXII 1.1**, sans authentification, contenu livré en STIX 2.1, STIX 1.2 ou eiq-json. OpenCTI ne parle que TAXII 2.x : passer par un client TAXII 1 puis importer les bundles |
| [DigitalSide](https://osint.digitalside.it/taxiiserver.html) | §11 | `https://osint.digitalside.it/taxii2` (`guest` / `guest`) | **injoignable** à la revue |
| [Pulsedive](https://docs.pulsedive.com/taxii/overview) | §11 | serveur TAXII 2.1 | **plan Pro ou Feed requis** ; une collection de test avec données réelles est accessible avec une clé de compte gratuit |
| [Q-Feeds](https://qfeeds.com/taxii-feeds-server/) | §7.1 (Europe) | serveur TAXII 2.1 | **licence Enterprise** ; l'édition Community ne l'inclut pas |
| [isMalicious](https://ismalicious.com/data/stix-taxii) | §7.2 (C2) | TAXII 2.1 | **plans Pro et Enterprise**, clé API |
| [CISA — AIS](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/automated-indicator-sharing-ais) | §3 (États-Unis) | connexion TAXII 2.1 bidirectionnelle | **sous convention** : *Terms of Use* pour les organisations non fédérales, MISA pour les fédérales |

### 2.5 STIX 2.1 sous licence

Éditeurs dont la sortie est nativement STIX 2.1 (le connecteur OpenCTI ne fait que relayer), mais derrière une clé commerciale.

| Source | § README | Ce qui est documenté |
|---|---|---|
| [Gatewatcher — LastInfoSec](https://www.gatewatcher.com/) | §7.1 (Europe) | trois flux STIX 2.1 (IOC, CVE horaire, rapports), *direct bundle import without transformation* ; clé à demander à l'éditeur |
| [Dark Web Informer](https://darkwebinformer.com/) | §12 | bundles STIX 2.1 pré-générés (`feed`, `ransomware`, `iocs`), régénérés toutes les 30 minutes ; clé API des paliers payants |
| [ReversingLabs](https://docs.reversinglabs.com/Integrations/OpenCTI/feed-configuration/) | — | flux TAXII (ransomware, malware) activables dans OpenCTI ; licence Spectra |

### 2.6 STIX 1.x — non ingérable tel quel

| Source | § README | Point d'entrée | Dernière donnée |
|---|---|---|---|
| [Citizen Lab](https://github.com/citizenlab/malware-indicators) | §7.2 (Mobile) · §9 | `<enquête>/stix.xml` | 21 fichiers, dernier dossier 2020-06 (DarkBasin) ; dépôt figé 2020-10 |
| [Meta](https://github.com/facebook/threat-research) | §7.1 (Amérique du Nord) | `indicators/stix1/*.xml` | 13 fichiers, dernier 2023-05 ; le dépôt reste actif sur d'autres formats |

---

## 3. Pièges

- **« Présent dans les *default feeds* de MISP » ne veut pas dire « feed MISP ».** ELLIO, Bambenek, DataPlane, IPsum, Phishing.Database, threatview.io, hole.cert.pl, eCrimeLabs, APNIC Honeynet, OpenPhish, PhishTank y figurent en `freetext` ou `csv` : ce sont des blocklists que MISP découpe lui-même.
- **Un dépôt vivant ne garantit pas un flux vivant.** ESET pousse du code toutes les semaines mais n'a pas rafraîchi d'événement MISP depuis juin 2026 ; APTtrail annonce une génération horaire et date d'un mois ; DigitalSide affiche une organisation soignée pour un pipeline arrêté depuis octobre 2024. Vérifier la date du contenu, pas celle du dépôt.
- **Un réemballage n'est pas une source.** Rösti, APTtrail, xfeeds, TI-Collector et ThreatCluster livrent du STIX ou du MISP impeccable, fabriqué à partir des rapports ou des listes d'autrui. Leur valeur est la commodité ; la confiance se porte sur l'amont.
- **Les miroirs ne sont pas des sources.** `blackorbird/APT_REPORT` (§11) contient une dizaine de `.stix2` copiés de MVT et d'Amnesty Tech ; `CyberMonitor/APT_CyberCriminal_Campagin_Collections` (§11) archive des STIX et des événements MISP joints à d'anciens rapports ; `DigiDNA/iMazing-Indicators-Of-Compromise` publie un seul bundle propre (KingsPawn, 2023) et un index de ceux des autres.
- **Une vitrine commerciale a un retard.** Le feed OSINT de PrecisionSec est le feed payant moins 30 jours ; les collections de test de Pulsedive sont là pour vendre le plan Feed.
- **Un index de feeds n'est pas un feed.** `rodanmaharjan/ThreatIntelligence` (§11) publie un `MISP_Feed_index.json` de 118 définitions, chargeable d'un bloc — 117 en `freetext`, 1 en `csv`, aucune native.
- **Sekoia.io** (§7.1) publie un unique `IOCs/apt31/2021-11-10 APT31 - STIX2.jsonl` dans son dépôt *Community* : une exception de 2021, pas une pratique.

## 4. Méthode et angles morts

Ce que la revue du 2026-09-19 a balayé, pour qu'on sache ce qu'elle ne couvre pas.

**Balayé.** Les *default feeds* MISP (branches `2.4`, `2.5`, `develop`) ; les 92 dépôts et 107 organisations GitHub du catalogue (arborescence complète) ; la recherche de code GitHub sur les empreintes `manifest.json`+`Orgc`, `hashes.csv`, `*.stix2`, `stix-bundle.json`, `misp_event.json`, `x_opencti_score`, `taxii2`, ainsi que les dépôts par sujet (`misp-feed`, `stix2`, `taxii`) et par description ; les 170 connecteurs *external-import* d'OpenCTI (pour remonter aux sources qui émettent du STIX en amont) ; les listes `awesome-threat-intelligence`, `Open-Source-Threat-Intel-Feeds`, `threat-intelligence-feeds` (kraloveckey), la page *communities* de MISP, le guide Cosive ; le web en anglais, français, allemand, espagnol, italien, portugais, polonais, néerlandais, turc, russe, ukrainien, japonais, coréen, chinois et arabe.

**Constaté sans résultat.** Aucun feed MISP ni STIX public chez : NCSC-NL (qui impose STIX/TAXII 2.1 à l'administration néerlandaise depuis le 2026-07-01 sans rien publier), CCB, CERT.at, NCSC-FI, CERT-EE, CERT Polska (n6 et MISP fermés), BSI, NCSC-UK, CCCS, ACSC (CTIS fermé), CERT NZ, CSA Singapour, JPCERT/CC, KrCERT, CERT-In, CERT.br (promeut MISP sans feed), USOM (liste retirée, republiée par SiberKapan). Les CERT slovaque, indien et chilien opèrent des MISP fermés. Les recherches en japonais, coréen, chinois et arabe ne remontent que de la documentation générique : pas de feed natif public identifié dans ces espaces.

**Morts.** `rosti.64617461.xyz`, `urlabuse.com/public/misp`, `dragnet.dev`, `osint.digitalside.it` ; Anomali Limo et Hail a TAXII, souvent cités, n'ont pas été retestés.

**Non exploré.** Le contenu des instances MISP sur compte (ICS-CSIRT.io, PISAX, AusCERT) ; les exports STIX/MISP à la pièce des bacs à sable (ANY.RUN exporte en MISP sur abonnement, Joe Sandbox et Hybrid Analysis derrière un compte) ; l'API OTX d'AlienVault, qui sert du STIX sur clé.

## 5. Ajouts au catalogue issus de cette revue

Vingt-sept sources trouvées par leur format ont été ajoutées au [README](README.md), une par ligne, dans leur section : CSIRT Italia / ACN (§3), SiberKapan et DoGoodCybersecurity (§2.1), PhishDestroy, chrome-mal-ids et Red Flag Domains (§2.2), ICS-CSIRT.io (§5), HvS-Consulting, Q-Feeds et Gatewatcher (§7.1 Europe), Rectifyq (§7.1 Asie), Criminal IP, BeaconBeagle, PrecisionSec, isMalicious et Pulsedive (§7.2), RansomFeed (§10), Rösti, ThreatCluster, APTtrail, xfeeds, cybershujin et The Hunter's Ledger (§11), Dark Web Informer (§12), DISARM Foundation (§13), ScanMalware (§15), Filigran (§1). Les lignes DigitalSide, ESET, Deutsche Telekom, Infoblox, Elastic, TweetFeed, CIRCL et CERT-FR ont été corrigées ou complétées.

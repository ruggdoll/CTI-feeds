# Flux CTI structurés : MISP et STIX 2.1

Ce fichier recense les sources du [catalogue](README.md) qui se chargent telles quelles dans une plateforme de renseignement : feeds au format MISP, bundles STIX 2.1, serveurs TAXII 2.1. Aucun convertisseur à écrire — on prend l'URL, on l'abonne, ça s'importe.

Il est organisé pour un cas précis : **peupler un OpenCTI vide, pour un CSIRT qui démarre**. La première partie dit par quoi commencer et dans quel ordre ; la seconde, en annexe, classe les mêmes flux par format, ce qui sert surtout côté MISP.

Chaque entrée donne le point d'entrée exact, le volume et la date de la dernière donnée (état au 2026-09-19), et ce qu'il faut savoir avant de l'ingérer : provenance, rythme, retard, conditions d'accès.

**Deux rappels.** OpenCTI n'a pas de format à lui : il lit le STIX 2.1, un standard public, en fichier (*bundle*) ou par TAXII 2.1 ; il lit aussi les feeds MISP par son connecteur `misp-feed`. Et la liste de feeds livrée avec MISP ([`defaults.json`](https://github.com/MISP/MISP/blob/2.5/app/files/feed-metadata/defaults.json), 107 entrées en 2.5) contient surtout des fichiers texte et CSV : seules 18 entrées sont au format MISP, les autres sont des blocklists que MISP découpe lui-même et qui restent au §2.2 du catalogue.

---

## 1. Par quoi commencer

Quatre paliers. Les trois premiers se branchent dans cet ordre ; le quatrième ne se branche pas dans OpenCTI. Le réglage de fenêtre compte autant que le choix du flux : une machine modeste ne tient pas 170 000 indicateurs.

### 1.1 Le socle — à charger une fois, avant tout le reste

Les objets auxquels les rapports vont se rattacher. Sans eux, chaque rapport crée ses propres acteurs, secteurs et techniques.

| Flux | Ce qu'il apporte | Connecteur OpenCTI | Réglage | Détail |
|---|---|---|---|---|
| **MITRE ATT&CK** | techniques, groupes, logiciels, campagnes | `mitre` (ou `taxii2` sur `attack-taxii.mitre.org`) | tout | §B.1, §B.4 |
| **MISP Galaxy** | la table des alias d'acteurs et de familles | arrive avec les tags galaxy des événements MISP (`misp-feed`) | — | §A.3 |
| **Filigran — datasets** | secteurs, pays, régions normalisés | `opencti` (import natif) | tout | §B.3 |
| CAPEC · ATLAS · DISARM | modèles d'attaque applicatifs · menaces sur l'IA · manipulation de l'information | `mitre` (option CAPEC) · `mitre-atlas` · `disarm-framework` | seulement si le périmètre le demande | §B.3 |

### 1.2 La connaissance — ce qui fait une base de renseignement

Des événements contextualisés : un rapport, un acteur, des indicateurs reliés. C'est le palier le plus maigre de la liste, et le plus précieux.

| Flux | Ce qu'il apporte | Connecteur OpenCTI | Réglage | Détail |
|---|---|---|---|---|
| **CIRCL — feed OSINT** | 1 680 événements tagués galaxy, TLP:CLEAR, depuis 2011 | `misp-feed` | tout | §A.1 |
| **Le CERT de rattachement** | CERT-FR (18 événements, dernier 2024-06) · CSIRT Italia (fenêtre glissante quotidienne) | `misp-feed` | tout | §A.1 |
| **CISA — avis conjoints (AA)** | un bundle STIX 2.1 par avis : rapport, techniques ATT&CK, indicateurs, acteurs, vulnérabilités (AA25-141B : 556 objets) | import de fichier STIX, un par avis | tout | §B.1 |
| **Cisco Talos** | un bundle par billet de recherche depuis 2022 (134) : rapport, techniques, indicateurs | import de fichier STIX | tout ; STIX 2.0 | §B.1 |
| NCSC-UK — rapports d'analyse de malware | bundle STIX 2.1 joint à certains rapports (Cyclops Blink : 352 objets) | import de fichier STIX | ponctuel | §B.1 |
| **ESET** | 60 événements attribués par acteur (Turla, Winnti, Gelsemium…) | import de fichier (pas de manifeste) | tout | §A.2 |
| **Rösti** | un événement par rapport public, IOC extraits, lien vers la source ; 9 636 événements depuis juin 2026 | `misp-feed` | fenêtre 90 jours, confiance basse : réemballage | §A.1 |
| MVT · Amnesty Tech · AssoEchap | spyware mobile, stalkerware | import de fichier STIX | si le périmètre inclut le mobile ou la société civile | §B.1 |
| Rectifyq | renseignement centré sur la Malaisie | `misp-feed` | si le périmètre le demande | §A.1 |
| AFRINTEL | incidents et acteurs visant l'Afrique, un bundle par mois (`incident`, `threat-actor`, `report`) | import de fichier STIX | si le périmètre inclut l'Afrique | §B.1 |
| FDC Threat Intelligence | 28 enquêtes originales (phishing, hébergement *bulletproof*), STIX 2.1 et MISP | import de fichier | complément | §B.1 |

### 1.3 La détection — indicateurs frais, à scoper

Pour corréler avec les journaux. Volume élevé, valeur courte : sans fenêtre, ils noient le graphe.

| Flux | Ce qu'il apporte | Connecteur OpenCTI | Réglage | Détail |
|---|---|---|---|---|
| **ThreatFox** | C2 et botnets, tagués par famille | `threatfox` ou `misp-feed` | 30 jours | §A.1 |
| URLhaus | URL de distribution de malware | `urlhaus` | 7 à 30 jours ; plutôt côté MISP | §A.1 |
| MalwareBazaar | hash d'échantillons | `malwarebazaar-recent-additions` | plutôt côté MISP : sans les échantillons, un hash ne dit que « connu » | §A.1 |
| Elastic Security Labs | indicateurs par campagne, sans rapport ni acteur dans le bundle | import de fichier STIX | complément | §B.1 |
| TweetFeed | IOC relayés sur X par la communauté, non vérifiés | `tweetfeed` ou `taxii2` | 7 jours, confiance basse | §A.1, §B.4 |

### 1.4 Hors OpenCTI

Pas du renseignement, ou pas à cette échelle. Leur place est un RPZ DNS, un pare-feu ou une warninglist MISP.

| Flux | Pourquoi | Où le mettre |
|---|---|---|
| PhishDestroy (122 617 indicateurs) · APTtrail (172 923) · xfeeds · chrome-mal-ids | blocklists | DNS RPZ, pare-feu, MISP en feed `freetext` |
| MISP warninglists · Deutsche Telekom | faux positifs et plages de scanners | MISP (OpenCTI n'en fait rien) |
| DigitalSide · CyberMonitor · blackorbird · Citizen Lab et Meta (STIX 1.x) | arrêtés, miroirs ou format non lu | — |
| NOCACTI · cyberdefense.blue · TI-Collector | producteur inconnu ou capteur unique | — |
| Gatewatcher · Pulsedive · Q-Feeds · isMalicious · Dark Web Informer · ReversingLabs | sous licence | quand le budget existe |

En une ligne, pour un CSIRT qui démarre : **ATT&CK → Galaxy → datasets → CIRCL → CERT national → avis CISA → ESET → Talos → Rösti (90 j) → ThreatFox (30 j)**. Dix flux, tous sans compte.

---

## 2. Annexe — les mêmes flux, par format

## A. MISP

### A.1 Feeds MISP complets

Un `manifest.json` et un fichier par événement : abonnables tels quels dans *Sync Actions → Feeds* (pointer le répertoire, MISP ajoute `/manifest.json`).

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [CIRCL](https://www.circl.lu/doc/misp/feed-osint/) | §2.1 · §3 (LU) | `https://www.circl.lu/doc/misp/feed-osint/` | 1 680 événements, 2011-09-22 → 2026-08-13 | produit par l'éditeur de MISP, premier feed de sa liste par défaut ; agrège plusieurs organisations contributrices. Le même feed est **converti en STIX 2.1** par CIRCL (§B.1) |
| [abuse.ch — URLhaus](https://urlhaus.abuse.ch/downloads/misp/) | §2.1 | `https://urlhaus.abuse.ch/downloads/misp/` | 1 949 événements, dernier 2026-09-18 | un événement par jour ; accès sans authentification |
| [abuse.ch — ThreatFox](https://threatfox.abuse.ch/downloads/misp/) | §2.1 | `https://threatfox.abuse.ch/downloads/misp/` | 1 993 événements, dernier 2026-09-18 | idem ; abuse.ch propose aussi une URL de feed personnelle (Auth-Key, compte gratuit), le chemin anonyme reste accessible |
| [abuse.ch — MalwareBazaar](https://bazaar.abuse.ch/downloads/misp/) | §2.1 | `https://bazaar.abuse.ch/downloads/misp/` | 1 918 événements, dernier 2026-09-07 | échantillons du jour |
| [Botvrij.eu](https://www.botvrij.eu/data/feed-osint/) | §2.1 | `https://www.botvrij.eu/data/feed-osint/` | 435 événements, 2013-08-07 → 2026-02-03 | feed OSINT de Koen Van Impe ; relaie aussi des événements ESET |
| [CSIRT Italia / ACN](https://www.acn.gov.it/portale/en/csirt-italia/misp) | §3 (Italie) | `https://www.csirt.gov.it/feed-misp/` | 60 événements, 2026-09-16 → 2026-09-19 (fenêtre glissante) | CSIRT national italien ; tout IoC TLP:CLEAR de l'agence passe par ce feed, renouvelé quotidiennement |
| [CERT-FR / ANSSI](https://misp.cert.ssi.gouv.fr/feed-misp/) | §3 (France) | `https://misp.cert.ssi.gouv.fr/feed-misp/` | 18 événements, dernier daté 2024-06-04 (fichiers régénérés 2026-04-09) | feed public annoncé par [CERTFR-2022-IOC-001](https://www.cert.ssi.gouv.fr/ioc/CERTFR-2022-IOC-001/) ; dormant depuis mi-2024 mais toujours servi, avec un `hashes.csv` agrégé |
| [Infoblox](https://github.com/infobloxopen/threat-intelligence/tree/main/indicators/misp) | §7.1 (Amérique du Nord) | `https://raw.githubusercontent.com/infobloxopen/threat-intelligence/main/indicators/misp` | 46 événements, 2022-04-08 → 2026-08-13 | un événement par campagne DNS (malvertising, *drop catch*, smishing) ; dépôt actif (2026-09-15) |
| [TweetFeed](https://tweetfeed.live/feeds/) | §11 | `https://tweetfeed.live/misp` (miroir `0xDanielLopez/TweetFeed`, `misp/`) | 365 événements (un par jour, fenêtre glissante d'un an), dernier 2026-09-19 | régénéré toutes les 15 minutes ; CC0. Publie **aussi** des bundles STIX 2.1 et un serveur TAXII 2.1 (§B) |
| [Rösti](https://rosti.dev/misp) | §11 | `https://misp.rosti.dev/` | 9 636 événements, 2026-06-16 → 2026-09-18 | *Repackaged Öpen Source Threat Intelligence* (Johannes Bader, auteur de bin.re) : un événement par rapport public, IOC extraits automatiquement de 292 sources. **Réemballage**, pas production : la provenance est celle du rapport cité. Remplace `rosti.64617461.xyz`, mort |
| [PrecisionSec — OSINT](https://precisionsec.com/free-misp-feed/) | §7.2 (C2) | `https://misp-osint.precisionsec.com/` | 864 événements, 2026-07-25 → 2026-08-22 | présenté par l'éditeur comme « a subset of PrecisionSec's premium feed » (couverture ClickFix), **retardé de 30 jours**, fenêtre glissante de 30 jours |
| [Rectifyq](https://rectifyq.com/) | §7.1 (Asie du Sud-Est) | `https://feeds.rectifyq.com/MISP2026/` (aussi `MISP2024/`, `MISP2025/`, `MISP-ICS-OT/`, `MISP-MY/`) | 867 événements en 2026 (→ 2026-07-30) ; 1 283 en 2025 ; 551 en 2024 ; ICS-OT 101 ; Malaisie 214 | initiative malaisienne, un événement par entrée de renseignement ; cinq feeds par année et par thème |
| [SiberKapan](https://siberkapan.org/misp-feed/) | §2.1 | `https://siberkapan.org/misp-feed/` | 60 événements, 2026-07-22 → 2026-09-19 | plateforme communautaire turque (honeypots, capteurs FortiGate) ; publie **aussi** un bundle STIX 2.1 et un serveur TAXII 2.1 (§B), et **republie la liste USOM** que l'agence ne diffuse plus en clair (§3, Turquie) |
| [ThreatCluster](https://threatcluster.io/) | §11 | `https://threatcluster.io/misp` | 9 événements, 2026-09-13 → 2026-09-16 (fenêtre glissante) | agrégateur (20 000 sources, résumés IA, selon le site) |
| [chrome-mal-ids](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids) | §2.2 | `https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/formats/misp-feed` | 187 événements, régénérés 2026-09-18 | identifiants d'extensions Chrome malveillantes, agrégés depuis les publications des éditeurs ; publie **aussi** un bundle STIX 2.1 (§B.1) |
| [APTtrail](https://trilwu.github.io/apttrail/) | §11 | `https://trilwu.github.io/apttrail/misp-feed/` | 340 événements (un par groupe), générés 2026-08-15 | **réemballage des trails APT de Maltrail** (§2.2) avec correspondance ATT&CK ; annoncé « horaire », dernière génération datée d'un mois |
| [xfeeds](https://github.com/neilweitzel/xfeeds) | §11 | `https://raw.githubusercontent.com/neilweitzel/xfeeds/main/feeds` (`misp-manifest.json`) | 1 événement, 2026-09-19 | agrégat de blocklists IP ne retenant que les IP corroborées par plusieurs sources indépendantes ; publie **aussi** un bundle STIX 2.1 |
| [NOCACTI](https://misp-feed.nocacti.com/Intrusion/) | — | `https://misp-feed.nocacti.com/Intrusion/` · `…/AdversaryInfrastructure/` | 3 + 1 événements, 2026-09-01 | dans les *default feeds* MISP depuis la 2.5.31 ; le site n'expose qu'une page de connexion MISP, aucune information sur le producteur — hors catalogue pour cette raison |
| [cyberdefense.blue](https://github.com/RedBlue232/threat-feed-publisher) | — | `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/misp-feed` | 3 événements (un par périmètre), 2026-04-27 | IP vues par un seul capteur CrowdSec/Suricata en France, fenêtre de 7 jours (« best-effort feed derived from a single self-hosted sensor », selon l'auteur) — hors catalogue |
| [DigitalSide](https://github.com/davidonzo/Threat-Intel/tree/master/digitalside-misp-feed) | §11 | `https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/` | 1 062 événements, 2022-10-03 → **2024-10-18** | **arrêté.** Le site ne répond plus et le dépôt GitHub n'a plus reçu de commit depuis le 2024-10-18. Reste dans les *default feeds* MISP |

### A.2 Événements MISP isolés

Pas de manifeste : des exports d'événement à importer un par un (*Import from MISP export*).

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [ESET](https://github.com/eset/malware-ioc) | §7.1 (Europe) | `eset/malware-ioc`, fichiers `*misp*.json` | 60 fichiers d'événement dans 26 des 148 dossiers ; dernière mise à jour d'un événement 2026-06-09 | le dépôt est très actif (2026-09-17) mais les campagnes récentes ne sont livrées qu'en `samples.sha256` : l'export MISP est intermittent. Couvre Turla, Winnti, Gelsemium, BackdoorDiplomacy, Winter Vivern… |
| [HvS-Consulting](https://github.com/hvs-consulting/ioc_signatures) | §7.1 (Europe) | `hvs-consulting/ioc_signatures`, fichiers `*Misp-Event.json` | 4 événements : Black Basta (2024-04, 2024-11), feed T3 2024, BlueHammer (2026-04-08, 5 attributs) | société de réponse à incident allemande ; un export MISP par rapport, à côté des YARA et CSV. Un export XML plus ancien (APT27, 2021) |
| [AssoEchap — stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | §7.2 (Mobile) | `generated/misp_event.json` | 1 événement, 1 692 objets MISP, régénéré 2026-06-21 | événement unique tenu à jour ; publie **aussi** un bundle STIX 2.1 (§B.1) |
| [GovCERT.ch](https://github.com/govcert-ch/CTI) | §3 (Suisse) | `20241202_LummaStealer/misp.event.31002.json` | 1 événement, 112 attributs, 2024-12-02 | export `restSearch` complet ; ponctuel, le reste du dépôt est en CSV/TXT |
| [TTC-CERT](https://github.com/ttc-cert/TTC-CERT-MISP-Shared-Events) | §3 (Thaïlande) | `ttc-cert/TTC-CERT-MISP-Shared-Events` | 9 événements, figé 2024-05-23 | Sharp Panda, Mustang Panda, infostealers visant la Thaïlande |

### A.3 Contenu MISP natif hors événements

Ni IOC ni rapports : les référentiels (alias d'acteurs, familles) et les listes de faux positifs que MISP applique aux feeds.

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [MISP Galaxy](https://github.com/MISP/misp-galaxy) | §1 | `MISP/misp-galaxy`, `clusters/` | 135 clusters, 2026-09-18 | la table de correspondance des alias ; également consommée par OpenCTI |
| [MISP warninglists](https://github.com/MISP/misp-warninglists) | §16 | `MISP/misp-warninglists` | 2026-09-08 | listes de faux positifs |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/usage/api) | §1 | `https://malpedia.caad.fkie.fraunhofer.de/api/get/misp` | ~4 Mo, sans clé | vue courante de Malpedia **au format galaxy cluster MISP** ; le reste de l'API demande une clé |
| [Deutsche Telekom](https://github.com/telekom-security/misp-warning-lists) | §6 | `telekom-security/misp-warning-lists`, `lists/` | 229 warninglists, 2026-09-19 | plages IP de scanners et de fournisseurs cloud, mises à jour quotidiennement ; production distincte de T-Pot |

### A.4 MISP sous condition

Instances ou feeds qui existent mais ne s'obtiennent pas par une URL publique.

| Source | § README | Modalité |
|---|---|---|
| [ICS-CSIRT.io](https://www.ics-csirt.io/threats.html) | §5 | communauté ICS animée depuis la Belgique (cudeso.be) : adhésion **gratuite** sur demande, puis synchronisation MISP ou export CSV/JSON/TXT/STIX |
| [CERT-AGID](https://cert-agid.gov.it/tag/ioc/) | §3 (Italie) | flux IoC réservé aux administrations publiques accréditées : instance MISP ou client CNTI de l'agence |
| [AusCERT](https://auscert.org.au/services/threat-intelligence/) | — | instance MISP réservée aux membres, incluant le flux CTIS de l'ACSC |
| [CSIRT de Gobierno](https://csirt.gob.cl/servicios/intercambio-de-indicadores-de-compromiso/) | §3 (Chili) | serveur MISP partagé avec les services publics chiliens connectés |
| [PISAX](https://misp.pisax.org/) | — | ISAC paneuropéen des points d'échange Internet ; instance MISP sur compte |
| [CSIRTAmericas](https://csirtamericas.org/en/services) | §3 (OEA) | *feeds hub* et MISP régional réservés aux équipes membres du réseau |
| [CERT-UA](https://cert.gov.ua) | §3 (Ukraine) | instance MISP accessible sur demande |
| [CERT.LV](https://www.cert.lv/en/data-feed) | §3 (Lettonie) | *data feed* national sur demande, contenu réservé |
| [RST Cloud](https://github.com/rstcloud/rstcloud_misp) | §1 | importateur officiel créant événements, attributs et clusters dans MISP — depuis un flux commercial sous licence |

---

## B. STIX 2.1

### B.1 Bundles STIX 2.1 publiés — production propre

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) | §1 | `mitre-attack/attack-stix-data` (`enterprise-attack/`, `mobile-attack/`, `ics-attack/`, `index.json`) | 2026-08-05 | ATT&CK Enterprise, Mobile et ICS en STIX 2.1 ; versionné, avec un index machine |
| [Elastic Security Labs](https://github.com/elastic/labs-releases) | §7.1 (Amérique du Nord) | `elastic/labs-releases`, `indicators/<campagne>/stix-bundle.json` | 23 bundles, dépôt actif 2026-09-11 | un bundle par famille ou campagne (BLISTER, BITSLOTH, WARMCOOKIE, SHELLTER…) |
| [CISA — avis conjoints](https://www.cisa.gov/news-events/cybersecurity-advisories) | §3 (États-Unis) | fichier `AA<xx>-<nnn><L>.stix_.json` joint à chaque avis (ex. [AA26-204A](https://www.cisa.gov/sites/default/files/2026-07/AA26-204A.stix_.json), [AA25-141B](https://www.cisa.gov/sites/default/files/2025-05/AA25-141B-Threat-Actors-Deploy-LummaC2-Malware-to-Exfiltrate-Sensitive-Data-from-Organizations.stix_.json)) | AA26-204A : 113 objets · AA25-141B : 556 · AA26-097A : 48 ; mis à jour avec l'avis (AA25-071A régénéré 2026-08) | rapport, `attack-pattern` ATT&CK, `indicator`, `malware`, `threat-actor`, `vulnerability` reliés ; pas de flux, un fichier par avis sur la page de l'avis ; le STIX 1.x XML est fourni en parallèle |
| [NCSC-UK — Malware Analysis Reports](https://www.ncsc.gov.uk/section/keep-up-to-date/malware-analysis-reports) | §3 (Royaume-Uni) | fichier joint au rapport (ex. [Cyclops Blink](https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cyclops-Blink-STIX2.1.json), [Small Sieve](https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-Malware-Analysis-Report-Small-Sieve.json)) | Cyclops Blink : 352 objets · Small Sieve : 77 ; rapports de 2022 | `attack-pattern`, `indicator`, relations ; CSV et YARA à côté ; Open Government Licence v3. Les rapports récents (Cisco 2025, CHOSEN BRICK 2026) sont publiés en PDF |
| [Cisco Talos — IOCs](https://github.com/Cisco-Talos/IOCs) | §7.1 (Amérique du Nord) | `Cisco-Talos/IOCs`, `<année>/<mois>/<billet>.json` | 134 bundles, 2022-04 → 2026-09 (27 en 2026) | un bundle par billet de recherche : `report`, `attack-pattern`, `indicator`, `vulnerability` ; **STIX 2.0** exporté de MISP (objets `x-misp-attribute`), à côté des TXT |
| [AFRINTEL](https://github.com/Hatchepsoute/AFRINTEL) | §10 | `stix/<année>/<mois>/afrintel_<mois>_<année>_opencti.json` · semestriels | 42 bundles, janvier 2024 → septembre 2026 ; H1 2026 : 1 651 objets (294 `incident`, 147 `threat-actor`, 36 `report`) | incidents visant les organisations africaines (54 pays), observés sur les sites de fuite et forums ; type, statut, confiance et impact séparés ; FR/EN, MIT |
| [FDC Threat Intelligence](https://github.com/freedatacenter/threat-intelligence) | §11 | `reports/<date>-<sujet>/iocs.stix2.json` (+ `iocs.misp.json`, PDF EN/RU) | 28 enquêtes, dernière 2026-09-17 | recherche indépendante (Aleksei Fokin) : phishing ciblant des ONG, hébergement *bulletproof*, honeypots ; un bundle STIX et un événement MISP par rapport |
| [PhishDestroy](https://github.com/phishdestroy/destroylist) | §2.2 | `destroylist`, `stix/bundle.json` · dossiers de preuves `*-evidence/data/ioc/stix-bundle.json` | 122 617 indicateurs (2026-08-17) ; ShortDot 5 006 ; NameSilo, NICENIC, Trustname | blocklist de phishing et d'arnaque (205 000 domaines) ; les dossiers *evidence* documentent l'abus par registrar ou par TLD avec un bundle par dossier |
| [MVT — mvt-indicators](https://github.com/mvt-project/mvt-indicators) | §7.2 (Mobile) | `mvt-project/mvt-indicators`, `<campagne>/*.stix2` | 14 bundles, dépôt actif 2026-08-27 | spyware mobile (Predator, Triangulation, Candiru, Cellebrite, EagleMsgSpy, Spyrtacus, Coruna, DarkSword…) |
| [Amnesty Tech](https://github.com/AmnestyTech/investigations) | §7.2 (Mobile) | `AmnestyTech/investigations`, `<enquête>/*.stix2` | 5 bundles, dernier 2024-12-16 (NoviSpy / Serbie) | rythme dicté par les publications |
| [AssoEchap — stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | §7.2 (Mobile) | `generated/stalkerware.stix2` | 12 320 objets (6 073 indicateurs, 174 malwares), 2026-06-21 | bundle unique régénéré ; publie en parallèle l'événement MISP du même corpus |
| [chrome-mal-ids](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids) | §2.2 | `formats/chrome-mal-ids-stix.json` | 7 398 indicateurs, 55 objets `malware`, 2026-09-18 | extensions Chrome malveillantes ; même corpus que le feed MISP |
| [Threat Actors' use of AI (cybershujin)](https://github.com/cybershujin/Threat-Actors-use-of-Artifical-Intelligence) | §11 | `stix/threat-actors-ai-stix2.1.json` | 1 659 objets dont 115 `intrusion-set`, 209 indicateurs ; 2026-09-14 | recension de l'usage de l'IA par les acteurs (rapports OpenAI, Anthropic, Google…) structurée en STIX ; bundle généré depuis le README |
| [DoGoodCybersecurity](https://github.com/leeg0010/DoGoodCybersecurity-STIX-Threat-Intel-Feed) | §2.1 | `daily/<date>.json` | 382 bundles quotidiens ; 2 715 indicateurs le 2026-09-17 | IP vues par un réseau de honeypots distribué ; le site du projet ne répond pas, le dépôt est le seul point d'accès |
| [SiberKapan](https://siberkapan.org/api-docs) | §2.1 | `https://siberkapan.org/api/v1/stix` | bundle courant (188 Ko), sans clé | même corpus que le feed MISP et la collection TAXII |
| [TweetFeed](https://tweetfeed.live/feeds/) | §11 | `https://tweetfeed.live/stix/today.json` · `week.json` · `month.json` (`manifest.json` les décrit) | 64 indicateurs le 2026-09-19 (jour) | même corpus que le feed MISP |
| [CIRCL — feed OSINT en STIX 2.1](https://codeberg.org/adulau/misp-circl-feed) | §2.1 | `feeds/circl/stix-2.1/<uuid>.json` (Codeberg) | un bundle par événement (ex. 991 objets) ; dernier commit 2026-02-02 | conversion du feed MISP par `misp-stix`, publiée par CIRCL |
| [The Hunter's Ledger](https://github.com/PixelatedContinuum/Threat-Intel-Reports) | §11 | `stix/*.json` | 43 bundles, dépôt actif 2026-09-19 | recherche originale d'un analyste indépendant (RAT, open directories, sites de fuite) ; bundles exportés d'OpenCTI (`x_opencti_*`) |
| [CTID — Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/example_flows/) | §9 | `.../corpus/<nom>.json` (le dépôt ne versionne que les `.afb`) | 41 flux, dépôt actif 2026-09-09 | extension *attack-flow* : les SDO/SCO standards s'ingèrent, les objets `attack-action` / `attack-flow` demandent la définition d'extension livrée dans le bundle |
| [DigitalSide](https://github.com/davidonzo/Threat-Intel/tree/master/stix2) | §11 | `davidonzo/Threat-Intel`, `stix2/` | 1 000+ bundles, **figé 2024-10-18** | même arrêt que le feed MISP |

### B.2 Bundles STIX 2.1 — agrégats et réemballages

Ingérables ; la provenance est celle des sources amont, indiquée dans la dernière colonne.

| Source | § README | Point d'entrée | Volume / dernière donnée | Amont |
|---|---|---|---|---|
| [APTtrail](https://trilwu.github.io/apttrail/) | §11 | release `apttrail_threat_feed_stix.json` (164 Mo) | 172 923 indicateurs, 340 `intrusion-set` ; généré 2026-08-15 | trails APT de Maltrail (§2.2), enrichis d'identifiants ATT&CK |
| [xfeeds](https://github.com/neilweitzel/xfeeds) | §11 | `feeds/stix-bundle.json` | 8 429 indicateurs, 2026-09-19 | blocklists IP publiques, corroboration multi-sources |
| [TI-Collector — CTAC MY](https://github.com/r4y79/ti-feed) | — | `taxii2/` (arbre TAXII 2.1 statique) · `feeds/*.txt` | 2 005 indicateurs sur 24 h, 2026-09-18 | feeds amont republiés (certificats SSLBL, domaines, hash) + CISA KEV 30 jours ; producteur non identifié — hors catalogue |
| [Rösti](https://rosti.dev/feeds) | §11 | API v2, sur clé de compte — STIX annoncé ; le feed MISP (§A.1) est public | — | rapports publics de 292 sources |
| [Threat Actor Intelligence Profiles (tm-ho)](https://github.com/proshiba/threatactor-intel-analysis) | §11 | `profiles/<acteur>/generated/profile.stix2.json` | 689 profils, dépôt actif 2026-09-19 ; Kimsuky : 161 objets (campagnes, malwares, techniques, rapport de 76 références) | rapports publics et jeux de données OSINT, structurés par des agents sous règles de génération avec file de revue humaine ; profils en japonais, `confidence` et `claim-audit.json` par affirmation |
| [VigilIntel](https://github.com/kidrek/VigilIntel) | §11 | `<année>/<mois>/<date>-report.stix.json` (FR et EN) | 268 bundles quotidiens, 2026-02 → 2026-09 | synthèse quotidienne de flux RSS par un modèle de langage ; le bundle ne contient qu'un objet `report` sans objets référencés ; CC BY-NC |
| [CyberNetSec](https://github.com/jaybodecode/netsecops.github.io) | — | `stix/<article>-STIX.json` | 1 000 bundles, 2026 | articles d'actualité extraits automatiquement en STIX ; producteur non identifié — hors catalogue |

### B.3 Référentiels STIX 2.1

Pas d'observables : les cadres à charger une fois, qui donnent aux rapports leurs `attack-pattern`, `identity` et `location`.

| Source | § README | Point d'entrée | Volume / dernière donnée | Commentaire |
|---|---|---|---|---|
| [MITRE CAPEC](https://github.com/mitre/cti/tree/master/capec/2.1) | §1 | `mitre/cti`, `capec/2.1/stix-capec.json` | 2 666 objets (615 `attack-pattern`), 2023-01-30 | le dépôt `mitre/cti` porte aussi ATT&CK en STIX 2.0 ; pour ATT&CK, préférer `attack-stix-data` |
| [MITRE ATLAS](https://github.com/mitre-atlas/atlas-navigator-data) | §1 | `dist/stix-atlas.json` · `dist/stix-atlas-attack-enterprise.json` | 538 objets (170 `attack-pattern`, 35 `course-of-action`), 2026-04-30 | tactiques et techniques contre les systèmes d'IA ; `atlas-data` (source) actif 2026-09-15 |
| [DISARM Foundation](https://github.com/DISARMFoundation/DISARMframeworks) | §13 | `generated_files/DISARM_STIX/DISARM.json` | 698 objets (391 `attack-pattern`, 16 tactiques), 2024-11-22 | cadre de description des opérations de manipulation de l'information ; connecteur OpenCTI officiel |
| [CTID — Sensor Mappings to ATT&CK](https://github.com/center-for-threat-informed-defense/sensor-mappings-to-attack) | §9 | `mappings/stix/enterprise/*.json` | 7 bundles (Sysmon, Auditd, Zeek, CloudTrail, OSQuery, WinEvtx…), 2025-06-21 | objets `x-mitre-sensor-mapping` : quelle source de journal couvre quelle composante de donnée ATT&CK |
| [MBC — Malware Behavior Catalog](https://github.com/MBCProject/mbc-stix2) | §1 | `mbc/mbc.json` | 1 738 objets (617 `attack-pattern`, 38 `malware`), 2023-10 | comportements de malware, complément d'ATT&CK pour l'analyse d'échantillons |
| [CTI-Driven — LOLBins](https://github.com/CTI-Driven/LOLBins) | §11 | `lolbins/stix2/<binaire>.json` | un bundle par binaire, 2024-04 | binaires Windows détournés, avec `report`, techniques et acteurs les utilisant |
| [Filigran — OpenCTI datasets](https://github.com/OpenCTI-Platform/datasets) | §1 | `data/sectors.json` · `geography.json` · `companies.json` | secteurs : 121 objets (72 `identity`) ; 2026-06-07 | référentiels de secteurs, pays et régions que les connecteurs OpenCTI utilisent |
| [VIGINUM — Doctrine OpenCTI](https://github.com/VIGINUM-FR/Doctrine-OpenCTI) | §3 (France) · §13 | `SGDSN_VIGINUM_DoctrineOpenCTI.pdf` (FR/EN) | 2025-04-24 | pas de données : le cadre de capitalisation de la menace informationnelle dans OpenCTI publié par le SGDSN |

### B.4 TAXII

| Source | § README | Point d'entrée | État |
|---|---|---|---|
| [MITRE ATT&CK](https://attack-taxii.mitre.org/api/v21/) | §1 | `https://attack-taxii.mitre.org/api/v21/collections/` | **TAXII 2.1 ouvert**, sans authentification ; collections Enterprise / Mobile / ICS. Exige l'en-tête `Accept: application/taxii+json;version=2.1` — sans lui le serveur renvoie 400 |
| [TweetFeed](https://tweetfeed.live/api/) | §11 | `https://tweetfeed.live/taxii2/` | **TAXII 2.1 ouvert** ; Cloudflare refuse les User-Agent `python-urllib` et `libwww-perl` |
| [SiberKapan](https://siberkapan.org/taxii/) | §2.1 | `https://siberkapan.org/taxii/` (API root `…/taxii/api-root/`) | **TAXII 2.1 ouvert** ; trois collections : toutes menaces, score ≥ 75, honeypots |
| [TI-Collector — CTAC MY](https://github.com/r4y79/ti-feed) | — | `taxii2/api/collections/<id>/` sur GitHub | arbre TAXII 2.1 **statique** (fichiers JSON servis par `raw.githubusercontent.com`) ; voir §B.2 |
| [EclecticIQ — collections publiques](https://www.eclecticiq.com/public-feed-manual) | §7.1 (Europe) | `https://cti.eclecticiq.com/taxii/discovery` (POST) · `…/taxii/poll` | **TAXII 1.1**, sans authentification, contenu livré en STIX 2.1, STIX 1.2 ou eiq-json. OpenCTI ne parle que TAXII 2.x : passer par un client TAXII 1 puis importer les bundles |
| [DigitalSide](https://osint.digitalside.it/taxiiserver.html) | §11 | `https://osint.digitalside.it/taxii2` (`guest` / `guest`) | **injoignable** |
| [Pulsedive](https://docs.pulsedive.com/taxii/overview) | §11 | serveur TAXII 2.1 | **plan Pro ou Feed requis** ; une collection de test avec données réelles est accessible avec une clé de compte gratuit |
| [Q-Feeds](https://qfeeds.com/taxii-feeds-server/) | §7.1 (Europe) | serveur TAXII 2.1 | **licence Enterprise** ; l'édition Community ne l'inclut pas |
| [isMalicious](https://ismalicious.com/data/stix-taxii) | §7.2 (C2) | TAXII 2.1 | **plans Pro et Enterprise**, clé API |
| [CISA — AIS](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/automated-indicator-sharing-ais) | §3 (États-Unis) | connexion TAXII 2.1 bidirectionnelle | **sous convention** : *Terms of Use* pour les organisations non fédérales, MISA pour les fédérales |

### B.5 STIX 2.1 sous licence

Éditeurs dont la sortie est nativement STIX 2.1, derrière une clé commerciale.

| Source | § README | Ce qui est documenté |
|---|---|---|
| [Gatewatcher — LastInfoSec](https://www.gatewatcher.com/) | §7.1 (Europe) | trois flux STIX 2.1 (IOC, CVE horaire, rapports), *direct bundle import without transformation* ; clé à demander à l'éditeur |
| [Dark Web Informer](https://darkwebinformer.com/) | §12 | bundles STIX 2.1 pré-générés (`feed`, `ransomware`, `iocs`), régénérés toutes les 30 minutes ; clé API des paliers payants |
| [ReversingLabs](https://docs.reversinglabs.com/Integrations/OpenCTI/feed-configuration/) | — | flux TAXII (ransomware, malware) activables dans OpenCTI ; licence Spectra |
| [ESET Threat Intelligence](https://help.eset.com/eti_portal/en-US/taxii_feeds.html) | §7.1 (Europe) | *data feeds* servis en STIX par TAXII depuis le portail ETI ; abonnement (distinct des événements MISP gratuits du dépôt `malware-ioc`, §A.2) |

### B.6 STIX 1.x

| Source | § README | Point d'entrée | Dernière donnée |
|---|---|---|---|
| [Citizen Lab](https://github.com/citizenlab/malware-indicators) | §7.2 (Mobile) · §9 | `<enquête>/stix.xml` | 21 fichiers, dernier dossier 2020-06 (DarkBasin) ; dépôt figé 2020-10 |
| [Meta](https://github.com/facebook/threat-research) | §7.1 (Amérique du Nord) | `indicators/stix1/*.xml` | 13 fichiers, dernier 2023-05 ; le dépôt reste actif sur d'autres formats |

---

## C. Avant d'ingérer

- **Figurer dans les *default feeds* de MISP ne fait pas un feed MISP.** ELLIO, Bambenek, DataPlane, IPsum, Phishing.Database, threatview.io, hole.cert.pl, eCrimeLabs, APNIC Honeynet, OpenPhish, PhishTank y sont en `freetext` ou `csv` : des blocklists que MISP découpe lui-même.
- **Un dépôt vivant ne fait pas un flux vivant.** ESET pousse du code toutes les semaines mais n'a pas rafraîchi d'événement MISP depuis juin 2026 ; APTtrail annonce une génération horaire et date d'un mois ; DigitalSide n'a plus de commit depuis octobre 2024. La date qui compte est celle du contenu, pas celle du dépôt.
- **Un réemballage n'est pas une source.** Rösti, APTtrail, xfeeds, TI-Collector et ThreatCluster livrent du STIX ou du MISP fabriqué à partir des rapports ou des listes d'autrui, et le disent (« Repackaged », « republished from upstream feeds »). La provenance à retenir est celle de l'amont.
- **Un miroir n'est pas une source.** `blackorbird/APT_REPORT` (§11) contient une dizaine de `.stix2` copiés de MVT et d'Amnesty Tech ; `CyberMonitor/APT_CyberCriminal_Campagin_Collections` (§11) archive des STIX et des événements MISP joints à d'anciens rapports ; `DigiDNA/iMazing-Indicators-Of-Compromise` publie un seul bundle propre (KingsPawn, 2023) et un index de ceux des autres.
- **Certains flux gratuits sont des extraits d'une offre payante, et l'éditeur le dit.** PrecisionSec décrit son feed OSINT comme « a subset of PrecisionSec's premium feed … delayed 30 days » ; Pulsedive présente sa collection TAXII de test sous le titre « Try before you buy ».
- **Un index de feeds n'est pas un feed.** `rodanmaharjan/ThreatIntelligence` (§11) publie un `MISP_Feed_index.json` de 118 définitions, chargeable d'un bloc — 117 en `freetext`, 1 en `csv`, aucune native.
- **Sekoia.io** (§7.1) publie un unique `IOCs/apt31/2021-11-10 APT31 - STIX2.jsonl` dans son dépôt *Community* ; c'est le seul fichier STIX du dépôt, daté de 2021.

## D. Ce qu'on ne trouvera pas

**Chez les CERT nationaux.** Aucun feed MISP ni STIX public chez NCSC-NL (STIX/TAXII 2.1 sont obligatoires pour l'administration néerlandaise depuis le 2026-07-01, sans feed public pour autant), CCB, CERT.at, NCSC-FI, CERT-EE, CERT Polska (n6 et MISP fermés), BSI, NCSC-UK, CCCS, ACSC (CTIS réservé), CERT NZ, CSA Singapour, JPCERT/CC, KrCERT, CERT-In, CERT.br. USOM a retiré sa liste publique ; SiberKapan la republie. Les CERT slovaque, indien et chilien opèrent des MISP fermés. En Europe, seuls CERT-FR, CSIRT Italia, CIRCL et GovCERT.ch publient du MISP en clair.

**Dans les espaces non anglophones.** Aucun feed MISP ou STIX public connu dans les espaces japonais, coréen, chinois et arabe.

**Dans la recherche académique.** Les jeux de données aCTIon (204 rapports en STIX, NEC Laboratories) et « A Structured CTI Dataset Using STIX 2.1 » (150 rapports, 4 777 entités) sont décrits sur arXiv sans dépôt de téléchargement.

**Chez les sandboxes.** ANY.RUN exporte en MISP sur abonnement ; Joe Sandbox et Hybrid Analysis derrière un compte ; à la pièce, pas en flux.

**Chez les agences qui relaient.** L'ACSC (Australie) et les PDF de `media.defense.gov` (NSA) reprennent les avis conjoints avec le bundle STIX de CISA ; il n'y a pas de production STIX distincte. Le Honeynet Project (GreedyBear) sert ses feeds de honeypots en TXT et JSON, pas en STIX. L'instance OpenCTI publique de NetmanageIT est hors ligne.

**Sur les adresses mortes.** `rosti.64617461.xyz` (remplacé par `misp.rosti.dev`), `urlabuse.com/public/misp`, `dragnet.dev`, `osint.digitalside.it`.

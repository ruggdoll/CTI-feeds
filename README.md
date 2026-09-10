# CTI-feeds

Liste de sources de renseignement concernant la menace d'origine cyber.

> Dernière revue : 2026-09-10 — 775 sources actives, une par ligne, et 60 écartées (§18). Décompte par section : sommaire ci-dessous.
>
> Les sources ne sont pas restreintes à l'anglais. La langue est indiquée entre crochets — p. ex. `[ZH]`, `[RU]`, `[KO]` — lorsqu'elle n'est ni le français ni l'anglais.
>
> Aucune source n'est écartée en raison de son pays d'origine ou de son affiliation. Le recoupement des informations et la prise en compte du contexte propre à chaque source relèvent de l'analyste. Chaque section ouvre par le **biais** propre à la famille de producteurs : c'est la première chose à garder en tête au recoupement.

## Lire une ligne

| Colonne | Valeurs |
|---|---|
| **Contenu** | `IOC` = observables exploitables (hash, IP, domaines, URL, adresses, règles) · `RENS` = analyses, rapports, attribution, contexte · `IOC+RENS` = les deux. Le tag `IOC` est réservé aux sources qui publient effectivement des observables, pas à celles qui en parlent. « IOC non vérifiés » : la source en publie probablement (PDF, site en JavaScript, robots bloqués) sans que cela ait pu être constaté. |
| **Accès** | `feed` (TXT/CSV/JSON/STIX/MISP, URL stable) · `repo` (GitHub/GitLab) · `API` · `RSS` (flux disponible) · `web` (pas de flux) · `PDF` · `inscr.` (compte requis) · `bot` (site vivant mais bloque les robots : ouvrir dans un navigateur) · `géo` (filtrage géographique probable) |
| **Activité** | date du dernier commit pour les dépôts ; sinon « vivant » = site répondant à la dernière revue |
| **Source** | une organisation ou un compte par ligne ; les liens secondaires d'une même organisation (dépôt d'IOC, flux, rapport annuel) restent sur sa ligne. Les comptes WeChat sont des lignes à part : leur contenu diffère du site de l'éditeur |
| **Vecteurs** | WeChat : flux `wechat2rss.xlab.app/feed/<id>.xml` (passerelle Wechat2RSS, §11) · Mastodon : `https://<instance>/@<compte>.rss` · Telegram : aperçu public `t.me/s/<canal>` · Medium : `<publication>/feed` · Bluesky : `bsky.app/profile/<handle>/rss` |

`feed`, `repo` et `API` se consomment par machine ; `RSS` et `web` se lisent.

## Sommaire

1. [Référentiels et annuaires](#1-référentiels-et-annuaires) — 16 sources
2. [Feeds communautaires, fondations et lutte anti-abus](#2-feeds-communautaires-fondations-et-lutte-anti-abus) — 50 sources
3. [CERT / CSIRT nationaux et organisations régionales](#3-cert--csirt-nationaux-et-organisations-régionales) — 124 sources
4. [Police, justice, sanctions et attribution officielle](#4-police-justice-sanctions-et-attribution-officielle) — 8 sources
5. [CERT sectoriels, ISAC et infrastructures critiques](#5-cert-sectoriels-isac-et-infrastructures-critiques) — 18 sources
6. [Infrastructure Internet : registres, RIR, NREN, cloud, opérateurs](#6-infrastructure-internet--registres-rir-nren-cloud-opérateurs) — 29 sources
7. [Éditeurs et laboratoires de recherche privés](#7-éditeurs-et-laboratoires-de-recherche-privés) — 301 sources
8. [Réponse à incident, conseil, assurance](#8-réponse-à-incident-conseil-assurance) — 13 sources
9. [Recherche académique et datasets](#9-recherche-académique-et-datasets) — 19 sources
10. [Cybercriminalité : trackers, sites de fuite, victimologie](#10-cybercriminalité--trackers-sites-de-fuite-victimologie) — 13 sources
11. [Chercheurs indépendants, communautés et agrégateurs](#11-chercheurs-indépendants-communautés-et-agrégateurs) — 87 sources
12. [Journalistes et médias spécialisés](#12-journalistes-et-médias-spécialisés) — 42 sources
13. [Ingérence numérique et abus de plateformes](#13-ingérence-numérique-et-abus-de-plateformes) — 10 sources
14. [Bases d'incidents, think tanks et rapports de référence](#14-bases-dincidents-think-tanks-et-rapports-de-référence) — 13 sources
15. [Sandboxes et dépôts d'échantillons](#15-sandboxes-et-dépôts-déchantillons) — 15 sources
16. [Règles de détection](#16-règles-de-détection) — 17 sources
17. [Angles morts](#17-angles-morts)
18. [Sources écartées](#18-sources-écartées) — 60 sources
19. [Origine de la liste et contribution](#19-origine-de-la-liste-et-contribution)

**Total actif (§1-16) : 775 sources.**

---

## 1. Référentiels et annuaires

*Biais : aucun observable frais ; mais sans table d'alias, le recoupement entre éditeurs est impossible (un même acteur porte 5 à 10 noms).*

| Source | Pays | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|---|
| [MITRE ATT&CK — STIX](https://github.com/mitre-attack/attack-stix-data) · [Groups](https://attack.mitre.org/groups/) · [Campaigns](https://attack.mitre.org/campaigns/) | US | RENS | repo/web | vivant | référentiel de techniques, groupes, logiciels et campagnes |
| [MISP Galaxy](https://github.com/MISP/misp-galaxy) | LU/EU | RENS | repo (JSON) | 2026-08-31 | référentiel canonique d'acteurs, outils, campagnes ; **la** table de correspondance des alias |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) · [acteurs](https://malpedia.caad.fkie.fraunhofer.de/actors) | DE | IOC+RENS | web/API, inscr. | vivant | familles de malware, règles YARA, références (Fraunhofer FKIE) |
| [ETDA / ThaiCERT APT Encyclopedia](https://apt.etda.or.th) | TH | RENS | web | vivant | fiches groupes et outils APT |
| [APT Groups and Operations (F. Roth)](https://apt.threattracking.com) | DE | RENS | web (Google Sheets) | vivant | tableur historique des alias APT par pays |
| [SOCRadar Threat Actor DB](https://socradar.io/threat-actors/) | TR | RENS | web | vivant | fiches d'acteurs gratuites |
| [ORKL](https://orkl.eu) | EU | RENS | web/API | vivant | bibliothèque de rapports CTI indexés |
| [lazarus.day](https://lazarus.day) | — | IOC+RENS | web | vivant | index des rapports sur les groupes nord-coréens |
| [RST Cloud — awesome-threat-actor-resources](https://github.com/rstcloud/awesome-threat-actor-resources) | — | RENS | repo | vivant | méta-liste de profils d'acteurs et datasets |
| [Trusted Introducer](https://www.trusted-introducer.org) · [export JSON](https://www.trusted-introducer.org/trusted-introducer/directory/downloads/json/teams/) | EU | RENS | JSON | vivant | annuaire de 554 équipes (contacts, PGP, constituency) ; le seul export machine européen |
| [FIRST](https://www.first.org) · [API](https://api.first.org/data/v1/teams?limit=100) · [blog (RSS)](https://www.first.org/blog/rss.xml) | — | RENS | API | vivant | 879 équipes mondiales, paginé par 100 ; diff mensuel recommandé (§19) |
| [Onetracker](https://onetracker.org/ti) | — | RENS | web | vivant | annuaire d'échantillons, PCAP, feeds, blocklists |
| [hslatman — awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence) | — | RENS | repo | vivant | liste de référence (sources CTI) |
| [sroberts — awesome-iocs](https://github.com/sroberts/awesome-iocs) | — | RENS | repo | vivant | liste de référence (IOC) |
| [InQuest — awesome-yara](https://github.com/InQuest/awesome-yara) | — | RENS | repo | vivant | liste de référence (YARA) |
| [Threatfeeds.io](https://threatfeeds.io) | — | RENS | web | ~2019 | annuaire de feeds, peu mis à jour |

## 2. Feeds communautaires, fondations et lutte anti-abus

*Biais : mesurent le volume et l'opportunisme (spam, scans, phishing de masse), pas le ciblé ; les listes de blocage produisent des faux positifs par conception. Les agrégateurs recyclent : vérifier la provenance avant d'empiler.*

### 2.1 Fondations et projets de référence

| Source | Pays | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|---|
| [abuse.ch](https://abuse.ch) — [URLhaus](https://urlhaus.abuse.ch), [MalwareBazaar](https://bazaar.abuse.ch), [ThreatFox](https://threatfox.abuse.ch), [Feodo Tracker](https://feodotracker.abuse.ch), [SSLBL](https://sslbl.abuse.ch) · [Mastodon](https://ioc.exchange/@abuse_ch) | CH | IOC | feed/API (CSV/JSON/MISP/Suricata) | vivant | hébergé par la Haute école spécialisée bernoise ; site bloque les robots, les feeds non |
| [AlienVault OTX](https://otx.alienvault.com) | US | IOC+RENS | API | vivant | pulses communautaires, très gros volume |
| [Shadowserver](https://www.shadowserver.org/what-we-do/network-reporting/) · [dashboard](https://dashboard.shadowserver.org) | US | IOC+RENS | inscr. | vivant | ONG ; rapports quotidiens gratuits pour votre ASN |
| [SANS ISC / DShield](https://isc.sans.edu) · [feeds](https://www.dshield.org/howto.html) | US | IOC+RENS | feed | vivant | IP de scan et d'attaque, blocklists quotidiennes, diary |
| [Spamhaus DROP / EDROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | CH/UK | IOC | feed (TXT/JSON) | vivant | plages IP détournées ou criminelles |
| [CIRCL — feed MISP OSINT](https://www.circl.lu/doc/misp/feed-osint/) · [GitHub](https://github.com/CIRCL) | LU | IOC+RENS | feed (MISP) | vivant | éditeur de MISP, AIL, Passive DNS/SSL |
| [Botvrij.eu](https://www.botvrij.eu) | NL | IOC | feed (MISP/CSV) | vivant | |
| [Stratosphere Laboratory](https://www.stratosphereips.org) | CZ | IOC+RENS | feed/repo | vivant | datasets CTU-13, IoT-23, blocklists, IDS Slips (CTU Prague) |
| [The Honeynet Project](https://www.honeynet.org) | — | RENS | web | vivant | outils, challenges, données honeypot |
| [APNIC Community Honeynet](https://feeds.honeynet.asia) | AU | IOC | feed | vivant | honeypots Asie-Pacifique |
| [DataPlane.org](https://dataplane.org) | US | IOC | feed (TXT) | vivant | ONG ; honeypots SSH/SIP/DNS/VNC |
| [Project Honey Pot / http:BL](https://www.projecthoneypot.org) | US | IOC | API DNS | vivant | harvesters, spammers |
| [HoneyDB](https://honeydb.io) | — | IOC | API | vivant | honeypots communautaires |
| [CyberGreen](https://cybergreen.net/) | US | RENS | RSS | vivant | métriques d'hygiène par pays/ASN |
| [Global Cyber Alliance](https://globalcyberalliance.org/) | US | RENS | RSS | vivant | honeyfarm AIDE, DMARC |
| [APWG](https://apwg.org/) | US | RENS | PDF ; eCrime eXchange inscr. | vivant | rapports trimestriels phishing |
| [Global Anti-Scam Alliance](https://gasa.org/) | — | RENS | PDF | vivant | rapports scam par pays |

### 2.2 Blocklists IP / domaines

| Source | Pays | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|---|
| [blocklist.de](https://www.blocklist.de) | DE | IOC | feed | vivant | IP signalées via fail2ban |
| [CINS Score / CI Army](https://cinsscore.com) | US | IOC | feed | vivant | |
| [stamparm — Ipsum](https://github.com/stamparm/Ipsum) | RS | IOC | repo | 2026-09-01 | IP scorées par le nombre de listes qui les signalent |
| [stamparm — Maltrail trails](https://github.com/stamparm/trails) | RS | IOC | repo | 2026-09-06 | trails statiques par famille (C2, DGA, scanners) ; sortis du dépôt `maltrail` vers `stamparm/trails` (release `trails.csv.gz`) |
| [Emerging Threats — compromised-ips](https://rules.emergingthreats.net/blockrules/compromised-ips.txt) | US | IOC | feed | vivant | |
| [Binary Defense banlist](https://binarydefense.com/banlist.txt) | US | IOC | feed | vivant | |
| [GreenSnow](https://blocklist.greensnow.co/greensnow.txt) | FR | IOC | feed | vivant | brute-force, scans |
| [BruteForceBlocker](https://danger.rulez.sk/projects/bruteforceblocker/blist.php) | SK | IOC | feed | vivant | SSH |
| [Phishing Army](https://phishing.army) | IT | IOC | feed | vivant | domaines de phishing |
| [OpenPhish](https://openphish.com) | — | IOC | feed | vivant | flux public d'URL de phishing (version communautaire limitée) |
| [PhishTank](https://phishtank.org) | US | IOC | feed | vivant | URL de phishing validées par la communauté (Cisco) ; enregistrement requis |
| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) | ZA | IOC | repo | 2026-08-23 | domaines/IP/liens de phishing |
| [Inversion DNSBL Blocklists](https://github.com/elliotwutingfeng/Inversion-DNSBL-Blocklists) | SG | IOC | repo | 2026-09-01 | URL malveillantes issues de scans originaux (ses dépôts `ThreatFox-IOC-*` sont des miroirs) |
| [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) | DE | IOC | repo (hosts/ABP/RPZ) | 2026-09-01 | liste TIF pour DNS-RPZ |
| [The Block List Project](https://blocklistproject.github.io/Lists/) | — | IOC | repo | 2026-07-20 | |
| [FireHOL IP lists](https://iplists.firehol.org) · [repo](https://github.com/firehol/blocklist-ipsets) | — | IOC | repo | 2026-09-01 | agrégation scorée de ~400 listes ; plutôt warninglist / comparaison de couverture |
| [SURBL](https://www.surbl.org) | US | IOC | DNSBL, licence | vivant | URI de spam et phishing |
| [URIBL](https://uribl.com) | US | IOC | DNSBL, licence | vivant | URI de spam ; usage libre à faible volume |
| [CleanTalk](https://cleantalk.org/blacklists) | — | IOC | API | vivant | |
| [AbuseIPDB](https://www.abuseipdb.com) | — | IOC | API, bot | vivant | signalements communautaires |
| [Stop Forum Spam](https://www.stopforumspam.com/downloads) | — | IOC | feed | vivant | |
| [dan.me.uk Tor list](https://www.dan.me.uk/torlist/) | UK | IOC | feed (1 req/30 min) | vivant | nœuds Tor ; à charger en warninglist |
| [threatview.io](https://threatview.io) | — | IOC | feed | vivant | IP/domaines/hash/C2 quotidiens |
| [ELLIO](https://ellio.tech) | CZ | IOC | inscr. ; blog RSS | vivant | IP de scans massifs |
| [hole.cert.pl](https://hole.cert.pl) | PL | IOC | feed | vivant | blocklist de domaines CERT Polska |
| [FGRibreau — mailchecker](https://github.com/FGRibreau/mailchecker) | FR | IOC | repo | vivant | domaines d'emails jetables |

### 2.3 Crypto / Web3

| Source | Pays | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|---|
| [Scam Sniffer — scam-database](https://github.com/scamsniffer/scam-database) | — | IOC | repo (JSON) | 2026-09-01 | domaines de drainers, adresses ; quotidien |
| [MetaMask — eth-phishing-detect](https://github.com/MetaMask/eth-phishing-detect) | US | IOC | repo (JSON) | 2026-09-01 | liste du wallet |
| [polkadot-js phishing](https://github.com/polkadot-js/phishing) | — | IOC | repo (JSON) | 2026-08-01 | non-EVM |
| [PhishFort lists](https://github.com/phishfort/phishfort-lists) | — | IOC | repo | 2025-08-05 | ralenti |
| [TRM Labs — Chainabuse](https://chainabuse.com) | US | IOC | web/API | vivant | adresses signalées, pas d'export bulk gratuit |
| [SlowMist / 慢雾](https://hacked.slowmist.io) · [Knowledge-Base](https://github.com/SlowMist/Knowledge-Base) | CN | RENS | web/repo | 2026-08-12 | base d'incidents Web3 `[ZH/EN]` |
| [慢雾科技 SlowMist (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/9e9c3c70e598266a1ac993e50458a10a6d853eb7.xml) | CN | IOC+RENS | RSS (WeChat) | 2026-09 | hash et indicateurs défangés des incidents Web3 `[ZH]` |

## 3. CERT / CSIRT nationaux et organisations régionales

*Biais : mandat public, IOC souvent tardifs mais fiables ; l'attribution est parfois politique (voir §17 sur les contre-narratifs). Beaucoup publient dans des avis web plutôt qu'en feed.*

### France

| Source | Contenu | Accès | Commentaire |
|---|---|---|---|
| [CERT-FR / ANSSI](https://www.cert.ssi.gouv.fr/ioc) · [GitHub ANSSI-FR](https://github.com/ANSSI-FR) | IOC+RENS | feed (MISP) / repo | feed IOC officiel ; outils DFIR (DFIR-ORC, DFIR-OGRE) |
| [VIGINUM](https://github.com/VIGINUM-FR/Rapports-Techniques) | IOC+RENS | repo | ingérence numérique étrangère (dernière MAJ sept. 2025) |
| [Cybermalveillance.gouv.fr](https://www.cybermalveillance.gouv.fr/) | RENS | web, bot | alertes grand public, rapport annuel |
| [Phishing Initiative](https://phishing-initiative.eu/contrib/) | IOC | web | signalement d'URL de phishing |
| [Signal Spam](https://www.signal-spam.fr/) | IOC | web | signalement de spam |

### Organisations régionales et supranationales

| Source | Contenu | Accès | Commentaire |
|---|---|---|---|
| [ENISA — CSIRTs Network](https://github.com/enisaeu/CNW) · [publications](https://www.enisa.europa.eu/publications) (UE) | IOC+RENS | repo / PDF | avis agrégés des CSIRT de l'UE ; Threat Landscape annuel |
| [CERT-EU](https://cert.europa.eu/publications/threat-intelligence) · [`droid`](https://github.com/certeu/droid) (UE) | IOC+RENS | web / repo | institutions de l'UE ; gestion de règles Sigma |
| [Europol — newsroom](https://www.europol.europa.eu/media-press/newsroom) (UE) | RENS | web | démantèlements, infrastructures saisies |
| [NATO CCDCOE](https://ccdcoe.org/library/publications/) | RENS | PDF | recherche cyber-conflit |
| [Trusted Introducer / TF-CSIRT](https://www.trusted-introducer.org) (Europe) | RENS | JSON | voir §1 |
| [APCERT](https://www.apcert.org) (Asie-Pacifique) | RENS | web | organisation régionale |
| [ASEAN Regional CERT](https://www.csa.gov.sg/news-events/press-releases/establishment-of-asean-regional-computer-emergency-response-team/) | RENS | web | organisation régionale, hébergée par la CSA de Singapour |
| [AfricaCERT](https://www.africacert.org) | RENS | web | organisation régionale |
| [OEA — CSIRTAmericas](https://csirtamericas.org) | RENS | web | organisation régionale `[ES/EN/PT]` |
| [OIC-CERT](https://oic-cert.org) | RENS | web | organisation régionale ; parfois injoignable hors région |
| [FIRST](https://www.first.org) | RENS | API | voir §1 |
| [UNODC cybercrime](https://www.unodc.org/unodc/en/cybercrime/) | RENS | web | rapports, pas d'observables |
| [ITU-D](https://www.itu.int/itu-d/sites/cybersecurity/) | RENS | web | rapports, pas d'observables |

### États membres de l'UE

| Pays | Source | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| Allemagne | [BSI / CERT-Bund](https://github.com/BSI-Bund) · [wid.cert-bund.de](https://wid.cert-bund.de) · [Lagebericht](https://www.bsi.bund.de/DE/Service-Navi/Publikationen/Lagebericht/lagebericht_node.html) | IOC+RENS | repo/web/PDF | honeypot MADCAT, CSAF ; rapport annuel `[DE]` |
| Autriche | [CERT.at](https://www.cert.at) | RENS | web, blog bot | opéré par nic.at `[DE/EN]` |
| Belgique | [CCB / CERT.be](https://cert.be) | RENS | web, bot | IOC non vérifiés |
| Bulgarie | [CERT Bulgaria](https://govcert.bg) | IOC+RENS | web | `[BG]` |
| Chypre | [CSIRT-CY](https://csirt.cy) | RENS | web | `[EL/EN]` |
| Croatie | [CERT.hr](https://www.cert.hr) | RENS | web | `[HR]` |
| Danemark | [CFCS](https://www.cfcs.dk) | RENS | web | redirige vers samsik.dk `[DA/EN]` |
| Espagne | [CCN-CERT](https://www.ccn-cert.cni.es) | RENS | web, inscr., bot | rapports APT ; accès réservé, IOC non vérifiés `[ES]` |
| Espagne | [INCIBE-CERT](https://www.incibe.es/en/incibe-cert) | RENS | web | avis sans observables `[ES]` |
| Estonie | [CERT-EE / RIA](https://github.com/cert-ee) | RENS | repo | outils (Cuckoo3, S4A), pas d'IOC |
| Finlande | [NCSC-FI / Traficom](https://www.kyberturvallisuuskeskus.fi) | RENS | web | `[FI/SV/EN]` |
| Grèce | [NCSA / EL CSIRT](https://cyber.gov.gr) | RENS | web | `[EL/EN]` |
| Hongrie | [NKI / NBSZ](https://nki.gov.hu) | IOC+RENS | web | `[HU]` |
| Irlande | [NCSC-IE](https://www.ncsc.gov.ie) | RENS | web | |
| Irlande | [IRISSCERT](https://iriss.ie/) | RENS | RSS | CERT non lucratif |
| Italie | [CERT-AGID](https://cert-agid.gov.it) | IOC | feed, inscr. | malware/phishing visant l'Italie, quotidien `[IT]` |
| Lettonie | [CERT.LV](https://www.cert.lv/en/data-feed) | IOC | feed, sur demande | data feed national (sinkhole, IP/domaines compromis) ; contenu réservé |
| Lituanie | [NKSC](https://www.nksc.lt) | RENS | web, bot | `[LT/EN]` |
| Luxembourg | [CIRCL](https://www.circl.lu) | IOC+RENS | feed | voir §2.1 |
| Malte | [CSIRTMalta](https://csirtmalta.gov.mt) | RENS | web, géo | |
| Pays-Bas | [NCSC-NL](https://github.com/NCSC-NL) | IOC | repo | IOC et scripts par campagne |
| Pologne | [CERT Polska](https://github.com/CERT-Polska) · [publikacje](https://cert.pl/publikacje/) | IOC+RENS | repo / Atom | mwdb, drakvuf, Artemis ; hole.cert.pl (§2.2) `[PL/EN]` |
| Pologne | [NASK — raporty](https://www.nask.pl/raporty) | RENS | PDF | rapports annuels de l'institut de tutelle du CERT Polska `[PL]` |
| Portugal | [CNCS / CERT.PT](https://www.cncs.gov.pt) | RENS | web | `[PT]` |
| Roumanie | [DNSC](https://www.dnsc.ro) | RENS | web, bot | `[RO/EN]` |
| Slovaquie | [SK-CERT](https://www.sk-cert.sk) | IOC+RENS | web | `[SK/EN]` |
| Slovénie | [SI-CERT](https://www.cert.si) | IOC+RENS | web | `[SL/EN]` |
| Suède | [CERT-SE](https://www.cert.se) | RENS | web | `[SV/EN]` |
| Tchéquie | [NÚKIB](https://nukib.gov.cz/en/) | RENS | web | |

### Autres pays

| Pays | Source | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| Albanie | [AKSK](https://aksk.gov.al) | RENS | web | `[SQ/EN]` |
| Arabie saoudite | [Saudi CERT](https://cert.gov.sa) | RENS | web | `[AR/EN]` |
| Argentine | [CERT.ar](https://www.argentina.gob.ar/jefatura/innovacion-ciencia-y-tecnologia/centro-nacional-de-ciberseguridad/certar) | RENS | web | `[ES]` |
| Australie | [ACSC / ASD](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories) | RENS | web, bot | IOC non vérifiés (503 au robot) |
| Azerbaïdjan | [CERT.AZ](https://cert.az) | RENS | web | `[AZ/EN]` |
| Bangladesh | [BGD e-GOV CIRT](https://www.cirt.gov.bd) | IOC+RENS | web, bot | très actif |
| Bélarus | [CERT.BY](https://cert.by) | RENS | web | `[RU]` |
| Bolivie | [CGII / CSIRT-Bolivia](https://csirt.gob.bo) | RENS | web | `[ES]` |
| Brésil | [CERT.br](https://cert.br) | RENS | web | honeypots, spam, statistiques agrégées (pas d'IOC publiés) `[PT/EN]` |
| Canada | [CCCS](https://github.com/CybercentreCanada) · [avis](https://www.cyber.gc.ca/en/alerts-advisories) · [National Cyber Threat Assessment](https://www.cyber.gc.ca/en/guidance/national-cyber-threat-assessment-2025-2026) | IOC+RENS | repo/web | AssemblyLine, extracteurs de config ; évaluation biennale |
| Chili | [CSIRT de Gobierno](https://csirt.gob.cl) | RENS | web, bot | très régulier ; IOC non vérifiés `[ES]` |
| Chine | [CNCERT/CC](https://www.cert.org.cn/publish/english/index.html) | RENS | web | rapports et contre-attribution `[ZH/EN]` |
| Chine | [CNCERT风险评估 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/c6662e88d278561b8293a607dcdcbe26aea98e04.xml) | IOC+RENS | RSS (WeChat) | compte WeChat du CNCERT ; publie des IOC (2026-09-02 : 15 IP) `[ZH]` |
| Chine | [CVERC](https://www.cverc.org.cn) | IOC+RENS | web | rapports de contre-attribution `[ZH]` |
| Chine | [关键基础设施安全应急响应中心 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/1aa5b8c8e4fb27ccb905694f7563b5529cd12269.xml) | RENS | RSS (WeChat) | CERT des infrastructures critiques ; dernier billet 2024-09 `[ZH]` |
| Colombie | [colCERT](https://www.colcert.gov.co) | RENS | web | `[ES]` |
| Corée du Sud | [KrCERT / KISA](https://www.krcert.or.kr) · [보호나라 alertes](https://www.boho.or.kr/kr/bbs/list.do?bbsId=B0000133) | RENS | web (JS) | IOC non vérifiés `[KO]` |
| Côte d'Ivoire | [CI-CERT](https://www.artci.ci) | RENS | web | |
| Égypte | [EG-CERT](https://egcert.eg) | RENS | web, géo | `[AR/EN]` |
| Émirats arabes unis | [aeCERT](https://aecert.ae) | RENS | web | `[AR/EN]` |
| Équateur | [EcuCERT](https://www.ecucert.gob.ec) | RENS | web | `[ES]` |
| États-Unis | [CISA](https://github.com/cisagov) · [KEV](https://github.com/cisagov/kev-data) · [avis](https://www.cisa.gov/news-events/cybersecurity-advisories) | IOC+RENS | repo/web | |
| États-Unis | [CERT/CC](https://github.com/CERTCC) | IOC+RENS | repo/web | |
| États-Unis | [NSA Cybersecurity](https://github.com/nsacyber) | IOC+RENS | repo/web | |
| Géorgie | [CERT.GOV.GE](https://cert.dga.gov.ge) | RENS | web | `[KA/EN]` |
| Ghana | [CSA / CERT-GH](https://www.csa.gov.gh) | RENS | web | |
| Hong Kong | [HKCERT](https://www.hkcert.org) | RENS | web | bulletins de vulnérabilités, pas d'IOC `[ZH/EN]` |
| Inde | [CERT-In](https://www.cert-in.org.in) | RENS | web (JS) | IOC non vérifiés |
| Inde | [CSK](https://www.csk.gov.in) | IOC+RENS | web (JS) | |
| Inde | [NCIIPC](https://nciipc.gov.in) | RENS | web (JS) | IOC non vérifiés ; surtout accessible depuis l'Inde |
| Inde | [MH-CERT](https://github.com/MH-CERT) | IOC | repo | `Indicator-of-Compromise-IOC-`, activité faible |
| Indonésie | [BSSN](https://www.bssn.go.id) | RENS | web, bot | `[ID]` |
| Iran | [Maher / CERT.ir](https://cert.ir) | RENS | web, géo | `[FA]` ; voir §17 |
| Islande | [CERT-IS](https://www.cert.is) | RENS | web | `[IS/EN]` |
| Israël | [INCD](https://www.gov.il/en/departments/israel_national_cyber_directorate) | RENS | web, bot | `[HE/EN]` |
| Japon | [JPCERT/CC](https://github.com/JPCERTCC) · [blog « Eyes »](https://blogs.jpcert.or.jp/en/) · [JSAC](https://jsac.jpcert.or.jp/) | IOC+RENS | repo / Atom | phishurl-list, YARA, LogonTracer ; hash dans les billets `[JP/EN]` |
| Japon | [NCO](https://www.cyber.go.jp/) | RENS | web | ex-NISC `[JP]` |
| Japon | [IPA 10大脅威](https://www.ipa.go.jp/security/10threats/) | RENS | PDF | top 10 annuel des menaces `[JP]` |
| Japon | [フィッシング対策協議会](https://www.antiphishing.jp/) | RENS | Atom | alertes phishing quasi quotidiennes ; URL dans les alertes (IOC non vérifiés) `[JP]` |
| Jordanie | [NCSC-JO](https://ncsc.jo) | RENS | web | `[AR/EN]` |
| Kazakhstan | [KZ-CERT](https://cert.gov.kz) | RENS | web | `[KK/RU/EN]` |
| Kenya | [National KE-CIRT/CC](https://ke-cirt.go.ke) | RENS | web | |
| Macédoine du Nord | [MKD-CIRT](https://mkd-cirt.mk) | IOC+RENS | web | `[MK/EN]` |
| Malaisie | [MyCERT](https://www.mycert.org.my) | RENS | web, bot | |
| Maroc | [DGSSI / maCERT](https://www.dgssi.gov.ma) | RENS | web | `[FR/AR]` |
| Maurice | [CERT-MU](https://cert-mu.govmu.org) | RENS | web | |
| Mexique | [CERT-MX](https://www.gob.mx/gncertmx) | RENS | web | `[ES]` |
| Moldavie | [CERT-GOV-MD](https://cert.gov.md) | RENS | web | `[RO/EN]` |
| Monténégro | [CIRT.ME](https://cirt.gov.me) | RENS | web | `[CNR/EN]` |
| Nigeria | [ngCERT](https://cert.gov.ng) | RENS | web, bot | |
| Norvège | [NSM / NCSC-NO](https://nsm.no) | RENS | web | `[NO/EN]` |
| Nouvelle-Zélande | [NCSC-NZ](https://www.ncsc.govt.nz) | IOC+RENS | web | IP dans certaines alertes (ponctuel) |
| Oman | [OCERT](https://www.cert.gov.om) | RENS | web | `[AR/EN]` |
| Ouzbékistan | [UZCERT](https://uzcert.uz) | RENS | web | `[UZ/RU]` |
| Pakistan | [PKCERT](https://pkcert.gov.pk) | RENS | web | |
| Panama | [CSIRT Panamá](https://cert.pa) | RENS | web | `[ES]` |
| Paraguay | [CERT-PY](https://www.cert.gov.py) | IOC+RENS | web | notifications `malware_url` avec IP et URL `[ES]` |
| Pérou | [PeCERT](https://pecert.gob.pe) | RENS | web | `[ES]` |
| Philippines | [CERT-PH / NCERT](https://ncert.gov.ph) | RENS | web, bot | |
| Qatar | [NCSA / Q-CERT](https://www.ncsa.gov.qa) | RENS | web | `[AR/EN]` |
| République dominicaine | [CNCS / CSIRT-RD](https://cncs.gob.do) | RENS | web | `[ES]` |
| Royaume-Uni | [NCSC-UK — threat reports](https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports) · [blog](https://www.ncsc.gov.uk/section/keep-up-to-date/ncsc-blog) · [GitHub](https://github.com/ukncsc) | IOC+RENS | web/repo | |
| Russie | [NKTsKI / GosSOPKA](https://safe-surf.ru) | RENS | web, géo | `[RU]` |
| Serbie | [Nacionalni CERT](https://www.cert.rs) | RENS | web | `[SR/EN]` |
| Singapour | [SingCERT / CSA](https://www.csa.gov.sg/singcert) | RENS | web | |
| Sri Lanka | [Sri Lanka CERT](https://www.cert.gov.lk) | RENS | web | `[SI/TA/EN]` |
| Suisse | [GovCERT.ch — CTI](https://github.com/govcert-ch/CTI) | IOC+RENS | repo | actif |
| Tadjikistan | [CERT.TJ](https://cert.tj/) | RENS | RSS | seul CERT d'Asie centrale avec flux `[RU/TJ]` |
| Taïwan | [TWCERT/CC](https://www.twcert.org.tw) | RENS | web | `[ZH/EN]` |
| Thaïlande | [TTC-CERT](https://github.com/ttc-cert) | IOC | repo, figé 2024 | blocklist, Sigma/YARA, events MISP (télécom) |
| Thaïlande | [ThaiCERT](https://www.thaicert.or.th/) | RENS | RSS | agence nationale |
| Tunisie | [ANCS / tunCERT](https://www.ancs.tn) | RENS | web, géo | `[FR/AR]` |
| Turquie | [USOM → Siber Güvenlik Başkanlığı](https://www.usom.gov.tr) | RENS | web | **l'ancienne liste publique `url-list.txt` redirige vers une API Swagger (siberguvenlik.gov.tr/api) : plus de feed ouvert** `[TR]` |
| Ukraine | [CERT-UA](https://cert.gov.ua) | IOC+RENS | web (JS) + MISP sur demande | sections « Індикатори компрометації » (URL défangées, hash) dans chaque article ; très prolifique sur l'activité russe `[UA/EN]` |
| Ukraine | [SSSCIP](https://cip.gov.ua/en) | RENS | web | autorité de tutelle, rapports semestriels |
| Uruguay | [CERTuy](https://www.cert.uy) | RENS | web | `[ES]` |
| Vietnam | [VNCERT/CC](https://vncert.vn) | RENS | web | `[VI]` |

## 4. Police, justice, sanctions et attribution officielle

*Biais : attribution nominative et sélective (ce qui est judiciarisable ou sanctionnable) ; excellent pour les noms, tardif pour les IOC.*

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [警察庁 サイバー警察局 (NPA)](https://www.npa.go.jp/publications/statistics/cybersecurity/) | JP | RENS | web/PDF | rapport semestriel + 注意喚起 nominatives (MirrorFace…) ; édition 令和7年 en mars 2026 `[JP]` |
| [OFAC — recent actions](https://ofac.treasury.gov/recent-actions) | US | RENS | web | sanctions : personnes, mixers, hébergeurs (adresses crypto et domaines dans les désignations, non extraits) |
| [DOJ — press releases](https://www.justice.gov/news) | US | RENS | web | actes d'accusation |
| [IC3](https://www.ic3.gov/) | US | RENS | web, bot | rapport annuel |
| [ODNI](https://www.dni.gov/) | US | RENS | web, bot | rapports annuels |
| [Europol](https://www.europol.europa.eu/media-press/newsroom) | UE | RENS | web | voir §3 |
| [Interpol — cyber threat assessments](https://www.interpol.int/Crimes/Cybercrime/Cyber-threat-assessments) | — | RENS | PDF, bot | seule synthèse régionale Afrique |
| [Access Now — Digital Security Helpline](https://www.accessnow.org/help/) | — | RENS | RSS | société civile : spyware et phishing ciblant ONG/journalistes |

## 5. CERT sectoriels, ISAC et infrastructures critiques

*Biais : partage restreint aux membres ; la partie publique est mince mais parfois unique (SektorCERT/Zyxel). Les 63 CERT bancaires et 216 CERT d'entreprise listés dans TI ne publient rien : plafond structurel de la veille ouverte.*

| Source | Pays | Secteur | Contenu | Accès | Commentaire |
|---|---|---|---|---|---|
| [SektorCERT](https://sektorcert.dk/) | DK | infrastructures critiques | RENS | RSS | analyse de l'attaque Zyxel 2023 (IOC dans le PDF, non vérifiés) |
| [KraftCERT](https://www.kraftcert.no/no/) | NO | énergie | RENS | web | `[NO]` |
| [Cert-IST](https://www.cert-ist.com/public/) | FR | industrie/services | RENS | web | avis publics partiels |
| [CERTFin](https://www.certfin.it/) | IT | finance | RENS | web | ABI Lab |
| [Z-CERT](https://www.z-cert.nl/) | NL | santé | RENS | web, bot | |
| [SHARE CERT](https://www.sharecert.rs/) | RS | société civile, médias | RENS | RSS | `[SR]` |
| [FS-ISAC Insights](https://www.fsisac.com/insights) | US | finance | RENS | RSS | |
| [Health-ISAC](https://health-isac.org/resources-and-news/) | US | santé | RENS | RSS | |
| [MS-ISAC (CIS)](https://www.cisecurity.org/ms-isac) | US | collectivités | IOC+RENS | web | |
| [WaterISAC](https://www.waterisac.org/) | US | eau | RENS | RSS | |
| [RH-ISAC](https://rhisac.org/) | US | retail | IOC+RENS | RSS | |
| [Aviation ISAC](https://www.a-isac.com/) | US | aviation | RENS | web | |
| [Auto-ISAC](https://automotiveisac.com/) | US | automobile | RENS | web | |
| [EE-ISAC](https://www.ee-isac.eu/) | EU | énergie | RENS | web, bot | URL corrigée 2026-09-06 (`eeisac.eu`→`ee-isac.eu`) |
| [ER-ISAC](https://er.isacs.eu/) | EU | rail | RENS | web, bot | URL corrigée 2026-09-06 (`er-isac.eu`→`er.isacs.eu`) |
| [Cyber Threat Alliance](https://www.cyberthreatalliance.org/resources/) | US | multi | RENS | web | rapports conjoints ; ses communiqués listent les membres |
| [ECSO](https://www.ecso.org/) | EU | multi | RENS | RSS | |
| [Kaspersky ICS-CERT](https://ics-cert.kaspersky.com) | RU | OT | RENS | web | IOC en PDF, non vérifiés ; voir aussi §7.2 |

## 6. Infrastructure Internet : registres, RIR, NREN, cloud, opérateurs

*Biais : vision réseau que personne d'autre n'a ; conflit d'intérêt évident sur l'abus qu'ils hébergent ou enregistrent.*

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [ICANN DAAR](https://www.icann.org/octo-ssr/daar) | US | RENS | PDF | mesure mensuelle de l'abus par TLD |
| [NetBeacon Institute](https://netbeacon.org/) | US | IOC+RENS | RSS | ex-DNS Abuse Institute |
| [AFNIC — Observatoire](https://www.afnic.fr/observatoire-ressources/) | FR | RENS | RSS | abus du .fr |
| [SIDN Labs](https://www.sidnlabs.nl/en/news-and-blogs) | NL | RENS | web | recherche DNS/abus .nl |
| [Nominet](https://nominet.uk/news/) | UK | RENS | web | suspensions .uk |
| [SWITCH-CERT](https://www.switch.ch/en/cert) | CH | RENS | web | abus .ch, universités |
| [TWNIC](https://twnic.tw/blog/) | TW | RENS | web | `[ZH]` |
| [RNIDS](https://www.rnids.rs/) | RS | RENS | web | registre .rs |
| [NIX.CZ](https://nix.cz/) | CZ | RENS | web | IXP tchèque |
| [Nameshield](https://blog.nameshield.com/fr/) | FR | RENS | RSS | registrar : typosquatting |
| [RIPE Labs](https://labs.ripe.net/) | NL | RENS | RSS | hijacks BGP, mesures |
| [APNIC Blog](https://blog.apnic.net/) | AU | RENS | RSS | |
| [LACNIC CSIRT](https://www.lacnic.net/csirt) | UY | RENS | web | `[ES/EN]` |
| [CERN CERT](https://security.web.cern.ch/) | CH | RENS | web | |
| [EGI CSIRT](https://csirt.egi.eu/) | EU | RENS | web | grille de calcul européenne |
| [SURFcert](https://www.surf.nl/en/services/security/surfcert) | NL | RENS | web | NREN |
| [REN-ISAC](https://www.ren-isac.net/) | US | RENS | web / RSS | NREN |
| [Cloudflare — security](https://blog.cloudflare.com/tag/security/) · [Radar](https://radar.cloudflare.com) | US | RENS | RSS / bot | DDoS, botnets |
| [Akamai — security research](https://www.akamai.com/blog/security-research) | US | RENS | web, bot | IOC non vérifiés |
| [Fastly — security](https://www.fastly.com/blog/category/security) | US | IOC+RENS | RSS | |
| [AWS Security Blog](https://aws.amazon.com/blogs/security/) | US | RENS | RSS | honeypot MadPot, takedowns |
| [Telefónica Tech](https://telefonicatech.com/en/blog) | ES | RENS | web | |
| [CERT Orange Polska](https://cert.orange.pl) | PL | IOC+RENS | RSS | alertes ; la blocklist CyberTarcza n'est pas publiée `[PL]` |
| [Exatel](https://exatel.pl/blog/) | PL | RENS | RSS | opérateur d'État `[PL]` |
| [CHT Security](https://www.chtsecurity.com/news) | TW | RENS | web | Chunghwa Telecom `[ZH]` |
| [IIJ — wizSafe](https://wizsafe.iij.ad.jp) | JP | RENS | RSS | bilans mensuels `[JP]` |
| [Viettel Cyber Security](https://blog.viettelcybersecurity.com) | VN | IOC+RENS | web | hash et IP dans les billets `[VI/EN]` |
| [CUJO AI](https://cujo.com/blog/) | US | RENS | RSS | télémétrie IoT domestique via FAI |
| [Deutsche Telekom — T-Pot](https://github.com/telekom-security/tpotce) | DE | — | repo | outil honeypot (pas de feed public) |

## 7. Éditeurs et laboratoires de recherche privés

*Biais : marketing, fragmentation des noms d'acteurs, « early share » sélectif entre membres d'alliances ; biais d'échantillon (leur base clients). Le meilleur volume d'IOC frais reste ici.*

### 7.1 Généralistes, par région

**Amérique du Nord**

| Source | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|
| [Cisco Talos](https://blog.talosintelligence.com) · [IOCs](https://github.com/Cisco-Talos/IOCs) | IOC+RENS | RSS / repo | vivant | |
| [Palo Alto Unit 42](https://unit42.paloaltonetworks.com) · [Article IOCs](https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information) · [timely-threat-intel](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel) | IOC+RENS | RSS / repo | 2026-09-01 | `pan-unit42/iocs` archivé |
| [Google Cloud Threat Intelligence / Mandiant](https://cloud.google.com/blog/topics/threat-intelligence) · [M-Trends](https://cloud.google.com/security/mandiant) · [TAG/GTIG](https://blog.google/security/) | IOC+RENS | web | vivant | le dépôt `mandiant/iocs` est archivé (2019) |
| [Microsoft Security / MSTIC](https://www.microsoft.com/en-us/security/blog/) · [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) | IOC+RENS | web / repo | vivant | |
| [Meta — threat-research](https://github.com/facebook/threat-research) | IOC | repo | vivant | |
| [SentinelLABS](https://www.sentinelone.com/labs/) | IOC+RENS | web | vivant | |
| [BlackBerry — Research & Intelligence](https://blogs.blackberry.com/en/category/research-and-intelligence) | IOC+RENS | web | 2026-09-02 | analyses de campagnes ; IOC non vérifiés (flux inaccessible aux robots) |
| [Zscaler ThreatLabz](https://github.com/ThreatLabz/iocs) | IOC | repo | vivant | |
| [Sophos](https://github.com/sophoslabs/IoCs) | IOC | repo | vivant | blog bloque les robots ; absorbe Secureworks CTU |
| [Broadcom / Symantec Threat Hunter](https://www.security.com/threat-intelligence) · [protection bulletins](https://www.broadcom.com/support/security-center/protection-bulletin) | IOC+RENS | RSS / web | vivant | |
| [Trend Micro Research](https://www.trendmicro.com/en_us/research.html) | IOC+RENS | web (IOC en PDF) | vivant | dépôt GitHub figé 2024-11 |
| [Fortinet FortiGuard Labs](https://www.fortinet.com/blog/threat-research) | IOC+RENS | web | vivant | |
| [Proofpoint Threat Insight](https://www.proofpoint.com/us/blog/threat-insight) | IOC+RENS | web | vivant | |
| [Recorded Future / Insikt](https://www.recordedfuture.com/research) · [flux](https://www.recordedfuture.com/feed) | IOC+RENS | web / RSS | vivant | hash et indicateurs défangés dans les rapports Insikt (via le flux) ; dépôt `Insikt-Group/Research` figé 2023 ; média du groupe The Record au §12 |
| [CrowdStrike](https://www.crowdstrike.com/en-us/blog/) · [rapports](https://www.crowdstrike.com/en-us/resources/reports/) | IOC+RENS | web/PDF | vivant | |
| [Elastic Security Labs](https://www.elastic.co/security-labs) · [labs-releases](https://github.com/elastic/labs-releases) | IOC+RENS | web / repo | 2026-09-01 | |
| [Netskope Threat Labs](https://www.netskope.com/blog) · [IOCs](https://github.com/netskopeoss/NetskopeThreatLabsIOCs) | IOC+RENS | RSS / repo | 2026-09-01 | abus de services cloud |
| [Huntress](https://www.huntress.com/blog) · [threat-intel](https://github.com/huntresslabs/threat-intel) | IOC+RENS | web / repo | 2026-08-19 | télémétrie MDR PME |
| [Wiz Research](https://www.wiz.io/blog/tag/research) · [IOCs](https://github.com/wiz-sec-public/wiz-research-iocs) | IOC+RENS | web / repo | 2026-08-06 | cloud |
| [Datadog Security Labs](https://securitylabs.datadoghq.com) · [malicious-software-packages-dataset](https://github.com/datadog/malicious-software-packages-dataset) | IOC+RENS | repo | 2026-08-31 | supply chain PyPI/npm, quotidien |
| [Infoblox](https://github.com/infobloxopen/threat-intelligence) | IOC+RENS | repo | vivant | DNS |
| [Cybereason](https://www.cybereason.com/blog) | IOC+RENS | RSS | vivant | IOC défangés dans les billets |
| [Rapid7](https://www.rapid7.com/blog/) · [Emergent Threat Response](https://www.rapid7.com/blog/tag/emergent-threat-response/rss/) | IOC+RENS | RSS | vivant | IOC dans les billets ; le sous-flux Emergent Threat Response est le plus dense |
| [Arctic Wolf](https://arcticwolf.com/resources/blog/) | IOC+RENS | RSS | vivant | IOC dans les billets |
| [ReliaQuest](https://reliaquest.com/blog/) | IOC+RENS | RSS | vivant | |
| [Varonis](https://www.varonis.com/blog/tag/threat-research) | RENS | RSS | vivant | |
| [Uptycs](https://www.uptycs.com/blog) | RENS | RSS | vivant | |
| [Morphisec](https://www.morphisec.com/blog/) | RENS | RSS | vivant | |
| [Malwarebytes Labs](https://www.malwarebytes.com/blog/category/threat-intel) | IOC+RENS | RSS | vivant | |
| [eSentire TRU](https://www.esentire.com/resources/blog) | IOC+RENS | web | vivant | |
| [Deep Instinct](https://www.deepinstinct.com/blog) | IOC+RENS | web | vivant | |
| [Aqua Nautilus](https://www.aquasec.com/blog/) | IOC+RENS | RSS | vivant | cloud / conteneurs |
| [Sucuri](https://blog.sucuri.net/) | IOC+RENS | RSS | vivant | web/CMS (IP) |
| [Red Canary](https://redcanary.com/resources-center/category/blog/) | RENS | RSS | vivant | techniques, pas d'IOC |
| [LevelBlue SpiderLabs](https://www.levelblue.com/blogs/spiderlabs-blog) | IOC+RENS | RSS | vivant | ex-Trustwave |
| [Intel 471](https://www.intel471.com/blog) | IOC+RENS | RSS | vivant | underground ; hash dans les billets |
| [Flashpoint](https://flashpoint.io/blog/) | RENS | web | vivant | underground |
| [Cyware](https://www.cyware.com/resources/threat-briefings) | RENS | web | vivant | briefings |
| [Trinity Cyber](https://www.trinitycyber.com/blog) | IOC+RENS | RSS | vivant | membre CTA ; hash dans les billets |
| [SonicWall Capture Labs](https://www.sonicwall.com/blog) | RENS | RSS | vivant | membre CTA |
| [WatchGuard Threat Lab](https://www.watchguard.com/wgrd-news/blog) | RENS | RSS | vivant | membre CTA |
| [ExtraHop](https://www.extrahop.com/blog) | RENS | web | vivant | membre CTA |
| [SecurityScorecard](https://securityscorecard.com/resources/research/) | RENS | web | vivant | membre CTA |
| [Aryaka](https://www.aryaka.com/blog/) | RENS | web | vivant | Transparent Tribe / APT36 |
| [Trellix ARC](https://www.trellix.com/blogs/research/) | RENS | web, bot | — | dépôt IOC figé 2021 |
| [Imperva Threat Research — Weekly TI](https://imperva.substack.com/) | RENS | RSS | vivant | hebdo + podcast ; seule ouverture de la famille adtech / anti-bot |
| [Zvelo](https://zvelo.com/) | RENS | RSS | vivant | catégorisation d'URL, phishing |

**Europe (hors Russie)**

| Source | Pays | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|---|
| [Nextron Systems / Florian Roth (blog)](https://www.nextron-systems.com/feed/) | DE | IOC+RENS | RSS | 2026-08-12 | 11 SHA-256, 27 défangés dans les billets ; complète `Neo23x0/signature-base` (§16) |
| [EclecticIQ](https://blog.eclecticiq.com/rss.xml) | NL | RENS | RSS | 2026-08-21 | éditeur TIP, rapports d'acteurs |
| [watchTowr Labs](https://labs.watchtowr.com/rss/) | UK/SG | RENS | RSS | 2026-08-14 | exploitation d'appliances de périmètre (Citrix, Ivanti, Fortinet), utile en anticipation |
| [ESET — WeLiveSecurity](https://www.welivesecurity.com) · [malware-ioc](https://github.com/eset/malware-ioc) | SK | IOC+RENS | web / repo | vivant | |
| [Gen Digital / Avast Threat Labs](https://www.gendigital.com/blog/insights) · [ioc](https://github.com/avast/ioc) | CZ | IOC+RENS | RSS / repo | 2026-06-01 | |
| [Bitdefender](https://github.com/bitdefender/malware-ioc) | RO | IOC | repo | vivant | |
| [WithSecure Labs](https://www.withsecure.com/en/resources-hub/w-labs/) · [iocs](https://github.com/WithSecureLabs/iocs) | FI | IOC+RENS | web / repo | 2026-08-27 | ex-F-Secure |
| [Sekoia.io](https://blog.sekoia.io) · [Community](https://github.com/SEKOIA-IO/Community) | FR | IOC+RENS | web / repo | 2026-08-24 | IOC + Sigma dans le dépôt |
| [HarfangLab](https://github.com/HarfangLab/iocs) | FR | IOC | repo | vivant | |
| [TEHTRIS](https://tehtris.com/en/blog/) | FR | IOC+RENS | web | vivant | honeypots mondiaux ; hash dans les billets |
| [Intrinsec](https://www.intrinsec.com/blog/) | FR | RENS | RSS | vivant | infra ransomware, bulletproof hosting ; IOC en PDF, non vérifiés |
| [OWN Security](https://www.own.security/ressources) | FR | IOC+RENS | web | vivant | |
| [Wavestone RiskInsight](https://www.riskinsight-wavestone.com/) | FR | RENS | RSS | vivant | |
| [Synetis](https://www.synetis.com/blog/) | FR | RENS | RSS | vivant | |
| [SysDream](https://sysdream.com/propos/blog/) | FR | RENS | web | vivant | |
| [Check Point Research](https://research.checkpoint.com) · [TI reports](https://research.checkpoint.com/category/threat-intelligence-reports/) | IL | IOC+RENS | web | vivant | absorbe Avanan |
| [Sygnia](https://www.sygnia.co/blog/) | IL | IOC+RENS | RSS | vivant | IOC ponctuels |
| [ClearSky](https://www.clearskysec.com/blog/) | IL | RENS | web | vivant | site JS, IOC non vérifiés |
| [KELA](https://www.kelacyber.com/blog/) | IL | RENS | RSS | vivant | underground |
| [IRONSCALES](https://ironscales.com/blog) | IL | RENS | RSS | vivant | |
| [G DATA](https://blog.gdatasoftware.com) | DE | IOC+RENS | web | vivant | hash dans les billets |
| [HiSolutions Research](https://research.hisolutions.com/) | DE | RENS | RSS | vivant | |
| [DCSO CyTec](https://medium.com/@DCSO_CyTec) | DE | RENS | RSS | vivant | `blog.dcso.de` mort, blog déplacé sur Medium ; Cyber Conflict Briefing trimestriel + recherche technique |
| [Kaspersky — Securelist](https://securelist.com) · [Securelist RU](https://securelist.ru) · [Telegram](https://t.me/s/kasperskylab_ru) | RU/CH | IOC+RENS | web | vivant | GReAT ; MD5 et indicateurs défangés en fin de rapport ; l'édition russe publie des rapports absents de l'anglaise (GOFFEE contre des cibles russes) et inversement |
| [Certego](https://www.certego.net/blog/) | IT | IOC+RENS | RSS | vivant | `[IT/EN]` |
| [Cleafy](https://www.cleafy.com/labs) | IT | IOC+RENS | web | vivant | IOC ponctuels `[IT/EN]` |
| [Yoroi Z-Lab](https://yoroi.company/research/) | IT | RENS | web | vivant | site JS, IOC non vérifiés `[IT/EN]` |
| [Yarix](https://www.yarix.com/en) | IT | RENS | web | vivant | `[IT/EN]` |
| [HWG Sababa](https://www.hwgsababa.com/blog/) | IT | RENS | web | vivant | `[IT/EN]` |
| [Tinexta Cyber](https://www.tinextacyber.com/) | IT | RENS | web | vivant | `[IT/EN]` |
| [Telsy](https://www.telsy.com/en/blog/) | IT | RENS | web, bot | vivant | bloque les robots `[IT/EN]` |
| [Maltiverse](https://maltiverse.com) | ES | IOC | API, inscr. | vivant | plateforme IOC ouverte |
| [Lab52 / S2 Grupo](https://lab52.io) | ES | RENS | web | vivant | site JS, IOC non vérifiés `[ES/EN]` |
| [Mnemo](https://mnemo.com/blog-ciberseguridad/) | ES | RENS | RSS | vivant | `[ES]` |
| [Versia](https://www.versia.com/blog) | ES | RENS | web | vivant | `[ES]` |
| [Aiuken](https://www.aiuken.com/blog) | ES | RENS | web | vivant | `[ES]` |
| [S21sec](https://www.s21sec.com/blog/) | ES | RENS | RSS | vivant | `[ES/EN]` |
| [Fox-IT](https://blog.fox-it.com/) | NL | IOC+RENS | RSS | vivant | hash dans les billets |
| [ThreatFabric](https://www.threatfabric.com/blogs) | NL | IOC+RENS | RSS | vivant | centaines de hash dans les billets (malware bancaire mobile) |
| [NCC Group](https://www.nccgroup.com/research/) | UK | RENS | web, bot | vivant | bloque les robots |
| [Northwave](https://northwave-cybersecurity.com/threat-intel-research) | NL | IOC+RENS | web | vivant | |
| [Tesorion](https://www.tesorion.nl/en) | NL | RENS | web | vivant | |
| [NVISO Labs](https://blog.nviso.eu/) | BE | IOC+RENS | RSS | vivant | hash dans le flux |
| [Truesec](https://www.truesec.com/hub/blog) | SE | RENS | web | vivant | |
| [Conscia](https://conscia.com/blog/) | DK | RENS | web | vivant | |
| [mnemonic](https://www.mnemonic.io/resources/blog/) | NO | RENS | web, bot | vivant | bloque les robots |
| [Nord Security](https://nordsecurity.com/blog) | LT | RENS | web | vivant | |
| [NRD Cyber Security](https://www.nrdcs.lt/) | LT | RENS | web | vivant | |
| [CERT Polska — voir §3](https://cert.pl) | PL | | | | |
| [ComCERT](https://www.comcert.pl/aktualnosci/) | PL | RENS | RSS | vivant | `[PL]` |
| [RedTeam.pl](https://blog.redteam.pl/) | PL | RENS | RSS | vivant | `[PL]` |
| [Safetech](https://safetech.ro/blog/) | RO | RENS | RSS | vivant | `[RO/EN]` |
| [Bit Sentinel](https://bit-sentinel.com/blog/) | RO | RENS | RSS | vivant | `[RO/EN]` |
| [certSIGN](https://www.certsign.ro/ro/) | RO | RENS | RSS | vivant | `[RO]` |
| [CrySyS Lab](https://blog.crysys.hu/) | HU | RENS | RSS | vivant | académique, APT Europe centrale |
| [Obrela](https://www.obrela.com/resources/blog) | GR | RENS | RSS | vivant | |
| [Oneconsult](https://oneconsult.com/en/blog/) | CH | IOC+RENS | RSS | vivant | hash dans les billets |
| [Acronis TRU](https://www.acronis.com/en/tru/) | CH | IOC+RENS | RSS | vivant | hash dans les billets |
| [Open Systems](https://www.open-systems.com/blog/) | CH | RENS | web | vivant | |
| [Threatray](https://www.threatray.com) | CH | IOC+RENS | web | vivant | |
| [Brandefense](https://brandefense.io/blog/) | TR | IOC+RENS | web | vivant | `[TR/EN]` |
| [SOCRadar](https://socradar.io/blog/) | TR | RENS | web | vivant | `[EN]` |
| [Barikat](https://www.barikat.com.tr/blog) | TR | IOC+RENS | web | vivant | `[TR]` |
| [Orange Cyberdefense](https://www.orangecyberdefense.com/global/blog) | FR | RENS | web, bot | — | Security Navigator |
| [Silobreaker](https://www.silobreaker.com/blog/) | UK | RENS | web | vivant | plateforme de veille |

**Russie**

| Source | Contenu | Accès | Commentaire |
|---|---|---|---|
| [BI.ZONE](https://bi.zone) · [bizone-ti-lib](https://github.com/bi-zone/bizone-ti-lib) · [Telegram](https://t.me/s/bizone_channel) | RENS | web / repo (lib) / Telegram | groupe Sber ; IOC non vérifiés `[EN/RU]` |
| [Positive Technologies](https://github.com/PositiveTechnologies) · [AttackDetection](https://github.com/ptresearch/AttackDetection) | RENS | repo (Suricata figé 2022), site bot | `[EN/RU]` |
| [Doctor Web](https://news.drweb.com) | IOC+RENS | web | indicateurs défangés dans les analyses `[RU/EN]` |
| [F6](https://www.f6.ru) | RENS | web, géo | injoignable au robot : IOC non vérifiés `[RU]` |
| [Solar 4RAYS](https://solar4rays.ru) · [Solar analytics](https://rt-solar.ru/analytics/reports/) | RENS | web, géo | injoignable au robot : IOC non vérifiés `[RU]` |
| [Security Vision](https://www.securityvision.ru/blog/) | RENS | web, géo | `[RU]` |
| [Infosecurity/Softline](https://www.infosec.ru/glavnye-temy/) | RENS | web, géo | `[RU]` |
| [Group-IB](https://www.group-ib.com/blog/) | IOC+RENS | web | siège Singapour ; hash et IP dans les billets `[EN]` |

**Chine**

| Source | Contenu | Accès | Commentaire |
|---|---|---|---|
| [QiAnXin / 奇安信](https://ti.qianxin.com) · [RedDrip7](https://github.com/RedDrip7) | IOC+RENS | web (bot) / repo | IOC via le dépôt `APT_Digital_Weapon` ; le site bloque les robots `[ZH]` |
| [奇安信威胁情报中心 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/b93962f981247c0091dad08df5b7a6864ab888e9.xml) | IOC+RENS | RSS (WeChat) | compte WeChat principal de QiAnXin ; IOC dans les articles (2026-09-04 : 47 SHA-256, 94 défangés, 21 IP) `[ZH]` |
| [奇安信CERT (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/981c000a01bbdc1f128d260cc91c15d3a6afb530.xml) | RENS | RSS (WeChat) | avis de vulnérabilité `[ZH]` |
| [奇安信病毒响应中心 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/7874947663d806190d77bdca6f8f6855f65a1b20.xml) | RENS | RSS (WeChat) | réponse aux malwares `[ZH]` |
| [360 高级威胁研究院 / 威胁情报中心](https://ti.360.net) | RENS | web | hebdo « 每周高级威胁情报解读 », nommage APT-C-xx ; 360 Netlab est devenu QiAnXin XLab (ligne dédiée) `[ZH]` |
| [360漏洞云 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/ca1fddd8505a3473feed12c0bee898e97d4d5eae.xml) | RENS | RSS (WeChat) | vulnérabilités (2026-09-03) `[ZH]` |
| [360Quake空间测绘 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/fd912d34201eea9dbaaa73e22bffee21636c0f9e.xml) | RENS | RSS (WeChat) | mesure d'exposition (2026-09-03) `[ZH]` |
| [Antiy / 安天](https://www.antiy.net) | IOC+RENS | web / RSS | hash dans les rapports `[ZH]` |
| [DBAPPSecurity / 安恒](https://ti.dbappsecurity.com.cn/blog/) | IOC+RENS | web / RSS | hash dans les rapports `[ZH]` |
| [NSFOCUS / 绿盟](https://nsfocusglobal.com/blog/) | RENS | web (JS) | site JS `[ZH/EN]` |
| [绿盟科技研究通讯 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/21b46d78e363b85d6927970267ecea4904f06bc8.xml) | RENS | RSS (WeChat) | compte WeChat de NSFOCUS, lisible et daté (2026-09-04), IOC insuffisants `[ZH]` |
| [Knownsec 404](https://paper.seebug.org) | RENS | web, parfois géo | IOC non vérifiés `[ZH]` |
| [Sangfor / 深信服](https://www.sangfor.com.cn/security-tech) | RENS | web, parfois géo | site JS, IOC non vérifiés `[ZH]` |
| [Tencent 御见](https://tix.qq.com) | RENS | web (JS) | site JS `[ZH]` |
| [腾讯安全威胁情报中心 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/034265b14906a59ef7cf1fcbd56699b54a696094.xml) | IOC+RENS | RSS (WeChat) | compte WeChat de Tencent Security ; IOC dans les articles (2026-09-03 : 163 défangés, 27 IP, 52 hash) `[ZH]` |
| [腾讯玄武实验室 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/923c0e2f33b6d39c8a826a90f185725f0edb10e8.xml) | RENS | RSS (WeChat) | labo Tencent, recherche offensive `[ZH]` |
| [腾讯科恩实验室 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/13584cb01e8bf3297943a0dad49e53c6faf20611.xml) | IOC+RENS | RSS (WeChat) | labo Tencent (Keen Lab), recherche offensive `[ZH]` |
| [云鼎实验室 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/d762fbf5f8f256afb63bcfe9a362184072338819.xml) | RENS | RSS (WeChat) | labo Tencent, cloud `[ZH]` |
| [ThreatBook / 微步](https://threatbook.io) | IOC+RENS | web (lookups) | lookups d'observables ; hash dans les billets de recherche `[ZH]` |
| [微步在线研究响应中心 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/ac64c385ebcdb17fee8df733eb620a22b979928c.xml) | IOC+RENS | RSS (WeChat) | compte WeChat de ThreatBook ; IOC dans les articles (2026-09-05 : 7 SHA-256) `[ZH]` |
| [天御攻防实验室 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/8b57281ce8c62c8bf12743aeb0279bfb807eb00d.xml) | RENS | RSS (WeChat) | 2026-09 `[ZH]` |
| [山石网科安全技术研究院 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/dce539f9deadfc68ce8bf82d3be59a4c6d8ddef9.xml) | IOC+RENS | RSS (WeChat) | 2026-09 `[ZH]` |
| [信息安全国家工程研究中心 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/7caad9bdb6b168fe174bc815a9b44b7f52d7198b.xml) | RENS | RSS (WeChat) | 2026-08 `[ZH]` |
| [火绒 Huorong](https://www.huorong.cn/info/) | IOC+RENS | web | `[ZH]` |
| [瑞星 Rising](https://www.rising.com.cn/) | RENS | web | `[ZH]` |
| [QiAnXin XLab (ex-360 Netlab)](https://blog.xlab.qianxin.com/) | IOC+RENS | RSS | botnets, DDoS, IoT ; ex-équipe 360 Netlab ; flux `/rss/` `[ZH/EN]` |
| [奇安信XLab (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/5c7b6eec254fbb0afac7abf4eae95573fc374555.xml) | IOC+RENS | RSS (WeChat) | compte WeChat de XLab, hash et indicateurs défangés `[ZH]` |
| [360威胁情报中心 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/920f171e3dae0c8eeb4c97b366b229ba19807732.xml) | IOC+RENS | RSS (WeChat) | équipe APT-C-xx ; indicateurs défangés `[ZH]` |
| [安恒信息安全研究院 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/a54132c52ec3e562fc896bf803a7fe0aa277bab7.xml) | IOC+RENS | RSS (WeChat) | DBAPPSecurity ; hash et indicateurs défangés `[ZH]` |
| [奇安信技术研究院 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/77a8d89f12dcb0aa75a19731e474a63427089081.xml) | IOC+RENS | RSS (WeChat) | institut de recherche QiAnXin ; indicateurs défangés `[ZH]` |
| [毕方安全实验室 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/e30371f4b2e600a87cb0718d649d6c43411622b3.xml) | IOC+RENS | RSS (WeChat) | listes d'IP de scan `[ZH]` |
| [绿盟科技CERT (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/aa2ff3b0167a3f449f3b116717b5350ab64df8c3.xml) | IOC+RENS | RSS (WeChat) | NSFOCUS CERT ; canal distinct du compte recherche `[ZH]` |
| [火绒安全实验室 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/e6da68c95a8f1e2fb40f6691d0ce9addc51a7532.xml) | IOC+RENS | RSS (WeChat) | Huorong ; canal WeChat du labo `[ZH]` |
| [永安在线情报平台 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/9f7e55c77c8eaf5f2adb43289de4fe194f7d34e5.xml) | RENS | RSS (WeChat) | plateforme de renseignement anti-fraude ; IOC non vérifiés `[ZH]` |
| [腾讯安全应急响应中心 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/7898375f78fd1018302d54577cd0fd05d5ed324f.xml) | RENS | RSS (WeChat) | TSRC, réponse à incident Tencent `[ZH]` |
| [深信服千里目安全实验室 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/027c7f3b98d9d0f2db84513f0cb94f02e9a8a3d7.xml) | RENS | RSS (WeChat) | canal lisible de Sangfor (site filtré) `[ZH]` |
| [天融信阿尔法实验室 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/a9cfdddef757b0ebac0428f629869b69028c43fa.xml) | RENS | RSS (WeChat) | Topsec `[ZH]` |
| [安恒威胁情报中心 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/de09ec267e5c4545e0a759cc62c3da7866ea49e0.xml) | RENS | RSS (WeChat) | DBAPPSecurity, centre de renseignement `[ZH]` |
| [安全威胁情报 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/9823254aff8854917b418bc19efe49ac160669e8.xml) | RENS | RSS (WeChat) | compte CTI `[ZH]` |
| [威胁棱镜 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/63688861efb2362716368e36b7f8b8b61d0394a9.xml) | RENS | RSS (WeChat) | compte CTI `[ZH]` |
| [白泽安全实验室 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/6bdf0d750e8c418f6ddfe8826c7a29f786a74aa4.xml) | RENS | RSS (WeChat) | compte CTI `[ZH]` |
| [安全分析与研究 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/62ba31603ffe26b5a8eca9ddaa434ea612445c10.xml) | RENS | RSS (WeChat) | compte CTI `[ZH]` |
| [青藤云安全 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/f35b2e0c0e9439b0085a851a1514a11c0ad89887.xml) | RENS | RSS (WeChat) | éditeur (sécurité des hôtes) `[ZH]` |
| [长亭安全课堂 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/ae5cf9ab99ae03269527af0f7a6c05ff14d5863c.xml) | IOC+RENS | RSS (WeChat) | Chaitin `[ZH]` |
| [墨菲安全 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/e7d4a6f783d2e42b91a70a9f802e590444d62952.xml) | IOC+RENS | RSS (WeChat) | éditeur (chaîne logicielle) `[ZH]` |
| [默安科技 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/0a0fb079fdb28ad7c49e5a6cbd9cf909c9873d86.xml) | RENS | RSS (WeChat) | éditeur (déception) `[ZH]` |
| [悬镜安全 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/59c134d2e41c3a0724d89cc6fa359bc1abedbc26.xml) | IOC+RENS | RSS (WeChat) | éditeur (DevSecOps) `[ZH]` |
| [斗象智能安全 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/5b72c7dcf37ab8e8c6e5745ecf2701b4ba3cd355.xml) | RENS | RSS (WeChat) | éditeur (Tophant, FreeBuf) `[ZH]` |

**Japon, Corée, Taïwan**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [ITOCHU C&I](https://blog-en.itochuci.co.jp) · [blog JA](https://blog.itochuci.co.jp/) | JP | IOC+RENS | RSS | ~200 hash dans les billets ; le blog japonais est un corpus distinct (PureRAT/PureLogs, malspam, règles EDR non traduits) `[JP/EN]` |
| [Macnica](https://security.macnica.co.jp/) | JP | IOC+RENS | web | hash dans les billets `[JP]` |
| [nao-sec](https://nao-sec.org) | JP | IOC+RENS | RSS | hash dans les billets `[JP/EN]` |
| [IIJ-SECT](https://sect.iij.ad.jp/) | JP | IOC+RENS | RSS | hash dans les billets `[JP]` |
| [LAC WATCH](https://www.lac.co.jp/lacwatch/) | JP | RENS | web | `[JP]` |
| [MBSD](https://www.mbsd.jp/research/) | JP | RENS | web | `[JP]` |
| [NRI Secure](https://www.nri-secure.co.jp/blog) | JP | RENS | web | `[JP]` |
| [NEC](https://jpn.nec.com/cybersecurity/blog/) | JP | RENS | web | `[JP]` |
| [Hitachi HIRT](https://www.hitachi.com/en/hirt/) | JP | RENS | web | `[JP/EN]` |
| [SecureBrain](https://www.securebrain.co.jp/top/) | JP | RENS | web | `[JP]` |
| [Cyber Defense Institute](https://www.cyberdefense.jp/) | JP | RENS | web | `[JP]` |
| [AhnLab ASEC](https://asec.ahnlab.com/en/) · [flux coréen](https://asec.ahnlab.com/ko/feed/) | KR | IOC+RENS | RSS | MD5 et indicateurs défangés ; fort sur les APT nord-coréennes ; **le flux `ko` publie les IOC retirés de la version anglaise** (2026-09-04 : 49 défangés, 5 hash) `[KO/EN]` |
| [Genians](https://www.genians.co.kr/en/blog/threat_intelligence) | KR | IOC+RENS | web | ~50 indicateurs par lot d'articles ; APT nord-coréennes `[KO/EN]` |
| [NSHC ThreatRecon](https://threatrecon.nshc.net) | KR | IOC+RENS | RSS | hash dans les billets `[KO/EN]` |
| [EST Security / ESRC](https://blog.alyac.co.kr) | KR | IOC+RENS | RSS | indicateurs défangés dans les billets `[KO]` |
| [ENKI WhiteHat](https://www.enki.co.kr/en/media-center/blog) | KR | IOC+RENS | web (JS) | `[KO]` |
| [S2W](https://s2w.inc/en/resource) | KR | RENS | web (JS) | IOC non vérifiés `[KO/EN]` |
| [Penta Security](https://www.pentasecurity.com/blog/) | KR | RENS | RSS | `[KO/EN]` |
| [Cloudbric](https://www.cloudbric.com/blogs/) | KR | RENS | web | `[KO/EN]` |
| [SANDS Lab](https://sandslab.io/) | KR | RENS | web | `[KO]` |
| [IGLOO](https://www.igloo.co.kr/) | KR | RENS | web, bot | `[KO]` |
| [SK shieldus](https://www.skshieldus.com/) | KR | RENS | web, bot | `[KO]` |
| [TeamT5](https://teamt5.org/en/) | TW | IOC+RENS | web | APT nexus-Chine ; hash dans les billets `[ZH/EN]` |
| [CyCraft](https://www.cycraft.com/blog) | TW | IOC+RENS | web | `[ZH/EN]` |
| [ZUSO](https://www.zuso.ai/blog) | TW | RENS | web | `[ZH/EN]` |
| [ISSDU](https://www.issdu.com.tw/en) | TW | RENS | web | `[ZH/EN]` |
| [TXOne](https://www.txone.com/resources/blog/) | TW | RENS | web | OT/ICS `[ZH/EN]` |
| [Canon MJ / ESET — サイバーセキュリティ情報局](https://eset-info.canon-its.jp/malware_info/) | JP | IOC+RENS | RSS | distributeur ESET au Japon ; rapports mensuels マルウェアレポート ; flux `RSS.rdf` `[JP]` |
| [Cybereason Japan](https://www.cybereason.co.jp/blog/) | JP | RENS | RSS | contenu propre à l'équipe japonaise |
| [Kaspersky Daily JP](https://blog.kaspersky.co.jp/) | JP | RENS | RSS | édition japonaise du blog Kaspersky `[JP]` |
| [NTT Security Japan — tech blog](https://jp.security.ntt/tech_blog/) | JP | IOC+RENS | web | `[JP]` |
| [INCA Internet — ISARC](https://isarc.tachyonlab.com/) | KR | RENS | RSS | rapport mensuel malware `[KO]` |
| [Monitorapp — 위협 인텔리전스 보고서](https://www.monitorapp.com/ko/resources/report) | KR | RENS | web (JS) | rapport TI mensuel (WAF) `[KO]` |
| [Theori](https://theori.io/ko/blog) | KR | RENS | web | recherche offensive `[KO/EN]` |
| [Hauri](https://www.hauri.co.kr/security/issue.html) | KR | RENS | web | éditeur antivirus historique `[KO]` |

**Inde, Asie du Sud-Est, Océanie**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [CyRadar](https://cyradar.com/feed/) | VN | IOC+RENS | RSS | éditeur vietnamien `[VI]` |
| [VinCSS (Vingroup)](https://blog.vincss.net) | VN | RENS | web | recherche vietnamienne ; flux Blogger instable `[VI/EN]` |
| [CloudSEK](https://www.cloudsek.com/blog) | IN | IOC+RENS | web | hash et IP dans les billets |
| [Cyble](https://cyble.com/blog/) | IN | IOC+RENS | RSS | hash et IP dans les billets |
| [CYFIRMA](https://www.cyfirma.com/research/) | IN | IOC+RENS | RSS | hash et IP dans les billets |
| [Seqrite](https://www.seqrite.com/blog/) | IN | IOC+RENS | RSS | hash et IP dans les billets |
| [K7 Labs](https://labs.k7computing.com) | IN | RENS | web (JS) | IOC non vérifiés |
| [Sequretek](https://www.sequretek.com/resources/threat-advisory) | IN | RENS | web, bot | IOC non vérifiés |
| [FalconFeeds](https://falconfeeds.io) | IN | RENS | web | |
| [Ensign InfoSecurity](https://www.ensigninfosecurity.com/resources) | SG | RENS | web | |
| [Group-IB](https://www.group-ib.com/blog/) | SG | RENS | web | |
| [Red Piranha](https://redpiranha.net/news-events) | AU | IOC+RENS | web | |
| [CyberCX](https://cybercx.com.au/blog/) | AU | RENS | web | |
| [Tata Communications](https://www.tatacommunications.com/blog/) | IN | RENS | RSS | opérateur ; blog sécurité |
| [Innefu Labs](https://innefu.com/) | IN | RENS | RSS | éditeur indien |

**Moyen-Orient et Afrique**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [CTM360](https://www.ctm360.com) | BH | IOC+RENS | web | Golfe ; domaines défangés dans les billets |
| [Help AG](https://www.helpag.com) | AE | RENS | RSS présent, blog 404 | à vérifier en navigateur |
| [DTS Solution](https://www.dts-solution.com) | AE | RENS | RSS présent, blog 404 | à vérifier en navigateur |
| [LMPS](https://www.lmps-group.com/fr/blog/) | MA | RENS | web | `[FR]` |
| [Raiseguard](https://raiseguard.com/blog) | TN | RENS | web | `[FR]` |
| [Serianu](https://www.serianu.com/) | KE | RENS | PDF | rapport annuel Afrique |
| [Cyberint (Check Point)](https://cyberint.com/blog/) | IL | IOC+RENS | web | renseignement externe ; hash et IP dans les billets ; racheté par Check Point |

**Amérique latine**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [CronUp](https://www.cronup.com/blog/) | CL | RENS | web | IOC non vérifiés (site JS) `[ES]` |
| [Metabase Q — Ocelot](https://www.metabaseq.com) | MX | RENS | web | `[ES/EN]` |
| [Scitum](https://www.scitum.com.mx/) | MX | RENS | web | `[ES]` |
| [SILIKN](https://www.silikn.com/) | MX | RENS | RSS | `[ES]` |
| [ISH Tecnologia](https://ish.com.br/blog/) | BR | RENS | RSS | `[PT]` |
| [Tempest](https://www.tempest.com.br/blog) | BR | RENS | RSS | `[PT]` |
| [Apura](https://apura.io/) | BR | RENS | web | `[PT]` |
| [Base4](https://base4sec.com/insights/) | AR | RENS | web | `[ES]` |
| [INSSIDE](https://www.insside.net/blog-ciberseguridad-insside/) | AR | RENS | RSS | `[ES]` |
| [B-Secure](https://www.b-secure.co/blog) | CO | RENS | RSS | surtout du marketing `[ES]` |
| [Datasec](https://datasec-soft.com/blog/) | UY | RENS | web | surtout du marketing `[ES]` |
| [Cyberseg](https://www.cyberseg.com/blog) | GT | RENS | web | surtout du marketing `[ES]` |
| [SISAP](https://www.sisap.com/) | GT | RENS | web | surtout du marketing `[ES]` |
| [GBM](https://www.gbm.net/) | CR | RENS | web | surtout du marketing `[ES]` |
| [Canvia](https://www.canvia.com/blog/) | PE | RENS | web | surtout du marketing ; CronUp et Metabase Q restent les vraies sources CTI de la région `[ES]` |

### 7.2 Spécialisés, par thème

**ICS / OT**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [Dragos](https://www.dragos.com/blog) | US | RENS | RSS | rapports de groupes, Year in Review ; IOC réservés à WorldView |
| [Claroty Team82](https://claroty.com/team82) | US/IL | RENS | Atom (disclosures) | vulnérabilités |
| [Nozomi Networks Labs](https://www.nozominetworks.com/labs) | US/CH | RENS | web | |
| [Forescout Vedere Labs](https://www.forescout.com/research-labs/) | US | RENS | web, bot | |
| [TXOne Networks](https://www.txone.com/resources/blog/) | TW | RENS | web | |
| [Kaspersky ICS-CERT](https://ics-cert.kaspersky.com) · [rapports RU](https://ics-cert.kaspersky.ru/publications/reports/) | RU | IOC+RENS | web / RSS | rapports trimestriels APT et cybercrime visant l'industrie, édition russe avec flux `[EN/RU]` |
| [谛听ditecting (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/e91ca0416d5a5dfc93ce14c0598416d4df1a3bf2.xml) | CN | RENS | RSS (WeChat) | honeypot ICS universitaire (Northeastern University) `[ZH]` |
| [威努特工控安全 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/ee4960f396fadae69f69e0711da85f1196e03651.xml) | CN | RENS | RSS (WeChat) | Winicssec, sécurité OT `[ZH]` |

**Mobile**

| Source | Pays | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|---|
| [Amnesty Tech — investigations](https://github.com/AmnestyTech/investigations) | — | IOC | repo (STIX) | fin 2024 | Pegasus, Predator |
| [Citizen Lab — malware-indicators](https://github.com/citizenlab/malware-indicators) | CA | IOC+RENS | repo | vivant | |
| [MVT — mvt-indicators](https://github.com/mvt-project/mvt-indicators) | — | IOC | repo (STIX) | vivant | |
| [AssoEchap — stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | FR | IOC | repo | vivant | |
| [Zimperium zLabs](https://zimperium.com/blog) · [IOC](https://github.com/Zimperium/IOC) | US | IOC+RENS | RSS / repo | 2026-08-25 | IOC dans le dépôt (pas dans les billets) ; banking trojans, malware Android |
| [ThreatFabric](https://www.threatfabric.com/blogs) | NL | IOC+RENS | RSS | vivant | trojans bancaires ; ~75 hash par lot de billets |
| [Cleafy Labs](https://www.cleafy.com/labs) | IT | IOC+RENS | web | vivant | IOC ponctuels |
| [Lookout Threat Lab](https://www.lookout.com/threat-intelligence) | US | IOC+RENS | web | vivant | surveillanceware |
| [Apple — Threat notifications](https://support.apple.com/en-us/102174) | US | RENS | web | vivant | spyware mercenaire |

**Sécurité mail et phishing**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [Proofpoint — voir 7.1] | US | IOC+RENS | web | hash dans les billets |
| [Cloudmark](https://www.cloudmark.com/en/blog) | US | RENS | web | |
| [Cofense](https://cofense.com/blog/) | US | RENS | RSS | aucun hash/IP dans les billets |
| [Abnormal](https://abnormal.ai/blog) | US | RENS | web | aucun hash/IP dans les billets |
| [Barracuda](https://blog.barracuda.com/) | US | RENS | RSS | aucun hash/IP dans les billets |
| [INKY](https://www.inky.com/en/blog) | US | RENS | RSS | aucun hash/IP dans les billets |
| [KnowBe4](https://blog.knowbe4.com/) | US | IOC+RENS | RSS | domaines défangés dans les billets ; absorbe Egress |
| [Validity](https://www.validity.com/blog/) | US | RENS | web | aucun hash/IP dans les billets |
| [Mailgun](https://www.mailgun.com/blog/) | US | RENS | web | aucun hash/IP dans les billets |
| [Data443 / Cyren](https://data443.com/cyren-threat-intelligence/) | US | RENS | web | aucun hash/IP dans les billets ; Data443 a repris Cyren |
| [Mimecast](https://www.mimecast.com/blog/) | UK | RENS | web | |
| [Hornetsecurity](https://www.hornetsecurity.com/en/blog/) | DE | IOC+RENS | RSS | absorbe Vade |
| [Retarus](https://www.retarus.com/blog/en/) | DE | RENS | web | |
| [Libraesva](https://www.libraesva.com/blog) | IT | RENS | web | |
| [Fortra (Agari, PhishLabs)](https://www.fortra.com/) | US | RENS | bot | rapports phishing de référence |
| [Netcraft](https://www.netcraft.com/resources/blog) | UK | RENS | web | |
| [Abusix](https://abusix.com/blog/) | DE | RENS | RSS | |

**Infrastructure, C2, pDNS, scans**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [Silent Push](https://www.silentpush.com/blog/) | US | IOC+RENS | RSS / web ; feed payant | IOC dans les billets ; pivots infra |
| [Validin](https://www.validin.com/blog/) | US | IOC+RENS | web / API ; payant | pivots pDNS et bannières |
| [Hunt.io](https://hunt.io/blog) | US | IOC+RENS | web ; feed payant | IP et hash en clair dans les billets (>100) |
| [Team Cymru](https://www.team-cymru.com/blog) | US | IOC+RENS | web ; feed payant | télémétrie réseau (Pure Signal) ; IOC dans les billets |
| [DomainTools](https://www.domaintools.com/blog) | US | IOC+RENS | RSS | domaines défangés dans les billets |
| [Spur](https://spur.us/blog) | US | RENS | web | bloque les robots |
| [Censys](https://censys.com/resources/blog/) | US | IOC+RENS | RSS / web / API | hash dans le flux ; balayage Internet |
| [GreyNoise](https://www.greynoise.io/blog) | US | IOC+RENS | web / API | IP de scan de masse (contexte « bruit ») |
| [Bitsight](https://www.bitsight.com/blog) | US | IOC+RENS | RSS | |
| [drb-ra C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds) | — | IOC | repo | tracker C2 automatisé (CSV, IP/domaines) |
| [Xanderux C2watcher](https://github.com/Xanderux/C2watcher) | — | IOC | repo | tracker C2 |
| [ViriBack](https://tracker.viriback.com) | — | IOC | feed | panneaux C2 et malware (CSV) |
| [CyberCrime Tracker](https://cybercrime-tracker.net) | — | IOC | feed | URL de panneaux C2 ; `montysecurity/C2-Tracker` archivé avril 2026 |
| [Bambenek](https://osint.bambenekconsulting.com) | US | IOC | sur demande | feeds DGA et C2 |
| [EcrimeLabs](https://ecrimelabs.net) | DK | IOC | sur demande | |
| [Critical Path Security](https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds) | US | IOC | repo (Zeek Intel) | 2026-09-01 |

**Vulnérabilités et exploitation**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [CISA KEV](https://github.com/cisagov/kev-data) | US | IOC+RENS | repo | catalogue des vulnérabilités activement exploitées (JSON) |
| [VulnCheck](https://www.vulncheck.com/blog) | US | IOC+RENS | RSS / API | exploitation observée, KEV enrichi ; IOC non vérifiés (API sur inscription) |
| [Rapid7 AttackerKB / DB](https://www.rapid7.com/db/) | US | IOC+RENS | web | évaluation d'exploitabilité |
| [ZDI](https://www.zerodayinitiative.com/blog) | US | RENS | Atom | divulgations coordonnées |
| [Exploit-DB](https://www.exploit-db.com/) | US | RENS | web | PoC et exploits publics (OffSec) |
| [Horizon3.ai — Attack Research](https://horizon3.ai/attack-research/) | US | RENS | RSS | analyses d'exploitation et PoC sur vulnérabilités récentes |
| [Vulners](https://vulners.com/) | — | RENS | API | agrégat de bulletins de vulnérabilités |
| [Wiz Vulnerability DB](https://www.wiz.io/vulnerability-database) | US | RENS | web | contexte cloud |
| [Google Project Zero — 0days in the wild](https://github.com/googleprojectzero/0days-in-the-wild) | US | RENS | repo | 2026-08-10 |
| [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) | — | IOC | repo | 2026-09-01 |
| [DEVCORE / Orange Tsai](https://blog.orange.tw/) | TW | RENS | Atom | recherche offensive |

**Crypto / Web3** — voir §2.3.

## 8. Réponse à incident, conseil, assurance

*Biais : échantillon limité à leurs clients et leurs sinistres ; excellents sur les TTP réels, rares sur les IOC.*

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [The DFIR Report](https://thedfirreport.com) · [Sigma](https://github.com/The-DFIR-Report/Sigma-Rules) | — | IOC+RENS | web / repo | rapports d'intrusion détaillés ; hash et IP en clair |
| [Kroll Cyber](https://www.kroll.com/en/insights/cyber) | US | RENS | RSS | |
| [S-RM](https://www.s-rminform.com/cyber-intelligence-briefing) | UK | RENS | web | briefing hebdomadaire |
| [PwC TI](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence.html) | UK | RENS | web | |
| [GuidePoint GRIT](https://www.guidepointsecurity.com/blog/) | US | IOC+RENS | RSS | hash et domaines défangés dans les billets |
| [Coveware](https://coveware.com/ransomware-blog/) | US | RENS | RSS | négociation ransomware, rapports trimestriels |
| [Halcyon](https://www.halcyon.ai/blog) | US | RENS | web | rapports ransomware |
| [Coalition](https://www.coalitioninc.com/blog) | US | RENS | web | assureur |
| [Cyber Threat Alliance — voir §5] | — | | | |
| [Virus Bulletin](https://www.virusbulletin.com/virusbulletin/) | UK | RENS | RSS | actes de conférence |
| [Botconf](https://www.botconf.eu/) | FR | RENS | web | actes de conférence |
| [FIRST papers](https://www.first.org/resources/papers/) | — | RENS | web | actes de conférence |
| [JSAC — voir §3] | JP | | | |

## 9. Recherche académique et datasets

*Biais : rigueur, mais latence ; peu d'observables frais.*

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [Canadian Institute for Cybersecurity (UNB)](https://www.unb.ca/cic/datasets/) | CA | — | datasets | IDS, malware Android, DoH |
| [CAIDA](https://www.caida.org/catalog/datasets/) | US | — | datasets, partiellement sur demande | télescope réseau |
| [Citizen Lab](https://github.com/citizenlab) | CA | IOC+RENS | repo | voir §7.2 mobile |
| [Stratosphere — voir §2.1](https://www.stratosphereips.org) | CZ | — | datasets | CTU-13, IoT-23 |
| [UNSW Canberra — ToN_IoT](https://research.unsw.edu.au/projects/toniot-datasets) | AU | — | datasets | télémétrie IoT/OT étiquetée |
| [SecRepo](https://secrepo.com) | — | — | datasets | index de datasets sécurité |
| [theZoo](https://github.com/ytisf/theZoo) | — | — | repo | échantillons de malware vivants (recherche) |
| [VirusShare](https://virusshare.com) | — | — | inscr. | dépôt d'échantillons, accès sur invitation |
| [DARPA OpTC](https://github.com/FiveDirections/OpTC-data) | US | — | datasets | traces host/réseau étiquetées (2019) |
| [IMPACT Cyber Trust](https://www.impactcybertrust.org) | US | — | datasets | catalogue DHS, accès sur demande |
| [Los Alamos](https://csr.lanl.gov/data/) | US | — | datasets | logs d'authentification et de flux |
| [Malpedia — voir §1] | | | | |
| [Honeynet Project — voir §2.1] | | | | |
| [CrySyS Lab](https://blog.crysys.hu/) | HU | RENS | RSS | |
| [mdecrevoisier — EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | — | — | repo | EVTX mappés ATT&CK |
| [CTID Attack Flow](https://github.com/center-for-threat-informed-defense/attack-flow) | US | RENS | repo | 2026-08-13 |
| [安全学术圈 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/8c5d5f0004e7231abeb01dac49cac5da4ec6933d.xml) | CN | RENS | RSS (WeChat) | veille académique sécurité chinoise `[ZH]` |
| [安全研究GoSSIP (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/ac4004481c5b78892663e13bb3af8422d4ebeb68.xml) | CN | RENS | RSS (WeChat) | groupe de recherche de Shanghai Jiao Tong `[ZH]` |
| [DataCon大数据安全分析比赛 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/4ebcb3d5a0bdb5fada48eb901a77910f8cbef585.xml) | CN | RENS | RSS (WeChat) | compétition d'analyse de données sécurité (QiAnXin / Tsinghua) ; datasets d'exercice, pas de renseignement à ingérer `[ZH]` |

## 10. Cybercriminalité : trackers, sites de fuite, victimologie

*Biais : **observables adverses**. Les revendications d'attaquants sont gonflées, recyclent de vieilles fuites, inventent des victimes. À collecter, jamais à promouvoir en indicateur sans recoupement.*

| Source | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|
| [Ransomware.live](https://www.ransomware.live/api) | IOC+RENS | API (50 req/j gratuit) | vivant | victimes et groupes ; victimologie, pas d'IOC réseau |
| [RansomLook](https://www.ransomlook.io/) | RENS | RSS / API | vivant | leak sites, forums, Telegram ; open source ; victimologie, pas d'IOC réseau |
| [ransomwatch](https://ransomwatch.telemetry.ltd/) · [repo](https://github.com/joshhighet/ransomwatch) | RENS | repo (JSON) | 2026-03-03 | historique depuis 2021 |
| [ecrime.ch](https://ecrime.ch/) | RENS | web | vivant | victimologie |
| [DarkFeed](https://app.darkfeed.io/mainpage) | RENS | web | vivant | victimologie |
| [Hackmanac](https://hackmanac.com/) | RENS | web | vivant | victimologie |
| [ransom-db](https://www.ransom-db.com/) | RENS | web | vivant | victimologie |
| [fastfire — deepdarkCTI](https://github.com/fastfire/deepdarkCTI) | RENS | repo | vivant | deep/dark web ; la copie `Cyberfury101` est inactive depuis 2021 |
| [FalconFeeds](https://falconfeeds.io) | RENS | web | vivant | revendications, hacktivisme |
| [BushidoUK — Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix) | RENS | repo | 2026-08-29 | outils par groupe |
| [databreaches.net](https://databreaches.net/) | RENS | RSS | vivant | journalisme sur les fuites |
| [Have I Been Pwned — breaches](https://haveibeenpwned.com/feed/breaches/) | RENS | RSS / API | vivant | |
| [cyberwarfare.live](https://cyberwarfare.live/) | RENS | RSS | vivant | hacktivisme ; à recouper |

## 11. Chercheurs indépendants, communautés et agrégateurs

*Biais : rapides, non vérifiés, disparaissent ; les agrégateurs d'agrégateurs recyclent des IOC périmés.*

| Source | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|
| [Netresec (Erik Hjelmvik)](https://www.netresec.com/rss.ashx) | IOC+RENS | RSS | 2026-08-31 | analyse PCAP (NetworkMiner, CapLoader) ; 114 IP, 84 hash sur les 6 derniers billets — plus d'IOC par article que la plupart des labos commerciaux |
| [malware-traffic-analysis.net (Brad Duncan)](https://www.malware-traffic-analysis.net/blog-entries.rss) | IOC+RENS | RSS | 2026-09-04 | PCAP + IOC quasi quotidiens ; le site, distinct du dépôt `malware-traffic/indicators` ci-dessous |
| [Didier Stevens](https://blog.didierstevens.com/feed/) | IOC+RENS | RSS | 2026-09-01 | outils d'analyse (oledump, pdf-parser) et hash d'échantillons |
| [Embee Research](https://www.embeeresearch.io/rss/) | IOC+RENS | RSS | 2024-10 | chasse au C2, déobfuscation ; 112 indicateurs défangés ; rythme ralenti |
| [bin.re](https://bin.re/feed.xml) | IOC+RENS | RSS | 2024-12 | analyse de malware, DGA ; ralenti |
| [Zerophage](https://zerophagemalware.com/feed/) | IOC | RSS | 2019 | archive de kits d'exploitation ; historique seulement |
| [Hexacorn](https://www.hexacorn.com/blog/feed/) | RENS | RSS | 2026-06-07 | persistance Windows (série « Beyond good ol' Run key »), référence pour la détection |
| [cocomelonc](https://cocomelonc.github.io/feed.xml) | RENS | RSS | 2026-09-05 | techniques d'implants, très actif `[EN/RU]` |
| [Xavier Mertens (rootshell.be)](https://blog.rootshell.be/feed/) | RENS | RSS | 2023 (blog) ; actif comme handler SANS ISC |  |
| [struppigel / Malware Analysis Spotlight (K. Hahn)](https://struppigel.blogspot.com/feeds/posts/default) | RENS | Atom | 2025-12 | analyse statique PE |
| [Pentest Partners](https://www.pentestpartners.com/feed/) | RENS | RSS | 2026-09 | recherche offensive |
| [Assetnote](https://www.assetnote.io/resources/research/rss.xml) | RENS | RSS | 2026-09 | recherche offensive (appliances, SaaS) |
| [ProjectDiscovery](https://projectdiscovery.io/rss.xml) | RENS | RSS | 2026-09 | recherche offensive, éditeur de Nuclei (§7.2) |
| [hackyboiz](https://hackyboiz.github.io/rss2.xml) | RENS | RSS | 2026-08-30 | collectif de chercheurs coréens `[KO]` |
| [malware-log (はてな)](https://malware-log.hatenablog.com/feed) | RENS | RSS | 2026-09-04 | chronologie d'incidents et de familles, tenue par un indépendant `[JP]` |
| [Wechat2RSS — bundle sécurité (OPML, 326 comptes)](https://wechat2rss.xlab.app/opml/sec.opml) · [dépôt](https://github.com/ttttmr/wechat2rss) | RENS | RSS (OPML) | 2026-07-31 (dépôt) ; flux vivants | passerelle WeChat (微信公众号) → RSS : le seul moyen d'abonnement aux comptes des labos chinois (§7.1 Chine) ; importable dans un lecteur ou un connecteur RSS ; auto-hébergeable `[ZH]` |
| [洞见 Doonsec](https://www.doonsec.com/) | RENS | web | vivant | moteur de recherche des articles sécurité WeChat, analyse LLM ; pas de flux public `[ZH]` |
| [Sec.Today](https://sec.today/pulses/) | IOC+RENS | web | vivant | agrégateur avec résumés ; complète gm7.org et tanjiti `[ZH]` |
| [先知社区 (Alibaba)](https://xz.aliyun.com/feed) | RENS | RSS | 2026-09-06 | communauté de recherche technique d'Alibaba, 100 items par flux `[ZH]` |
| [二道情报贩子 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/86512202e74d01447788f355c4a4171a3c86740a.xml) | RENS | RSS (WeChat) | 2026-09 | analyste CTI indépendant `[ZH]` |
| [情报小蜜蜂 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/78f3da7a79babd1ab1a2831f37718630f41b77b5.xml) | RENS | RSS (WeChat) | 2026-09 | analyste CTI indépendant `[ZH]` |
| [qz安全情报分析 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/1bbe066c89588a1aff71eb8b6a4446c7c422499f.xml) | RENS | RSS (WeChat) | 2026-04 | analyste CTI indépendant `[ZH]` |
| [丁爸情报分析师的工具箱 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/4fad165589ac854de97e576a6dbcfbd8b9f75320.xml) | RENS | RSS (WeChat) | 2026-09 | outillage d'analyste CTI `[ZH]` |
| [看雪学院 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/0e026637254d450ae84c59f87d4e4fb4616651ca.xml) | RENS | RSS (WeChat) | 2026-09 | communauté reverse / vulnérabilités `[ZH]` |
| [Seebug漏洞平台 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/be2795d741304af2370cbf8d31d1e5d3675f8e85.xml) | IOC+RENS | RSS (WeChat) | 2026-09 | vulnérabilités (Knownsec) `[ZH]` |
| [SecPulse安全脉搏 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/3bd096819fedf4e94ef23d95c24dd7b2644f3d10.xml) | RENS | RSS (WeChat) | 2026-07 | communauté sécurité `[ZH]` |
| [吾爱破解论坛 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/90c827b8290310a96ef80a13df9dbcc06ab69892.xml) | IOC+RENS | RSS (WeChat) | 2026-09 | forum reverse `[ZH]` |
| [Bert-JanP — Open-Source-Threat-Intel-Feeds](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds) | IOC | repo | vivant | |
| [spydisec — spydithreatintel](https://github.com/spydisec/spydithreatintel) | IOC | repo | vivant | agrégat d'IOC quotidien |
| [EndlessFractal — Threat-Intel-Feed](https://github.com/EndlessFractal/Threat-Intel-Feed) | IOC | repo | vivant | agrégat d'IOC |
| [rodanmaharjan — ThreatIntelligence](https://github.com/rodanmaharjan/ThreatIntelligence) | IOC | repo | 2025-09 | agrégat, ralenti |
| [Intezer — community-intelligence](https://github.com/intezer/community-intelligence) | IOC | repo | vivant | IOC communautaires |
| [GithubInfosec — latest-malware-IoC](https://github.com/GithubInfosec/latest-malware-IoC) | IOC | repo | mi-2025 | ralenti |
| [malware-traffic — indicators](https://github.com/malware-traffic/indicators) | IOC | repo | vivant | IOC des analyses de malware-traffic-analysis.net |
| [PRODAFT](https://github.com/prodaft) | IOC | repo | vivant | IOC et outils publiés par l'éditeur |
| [DigitalSide](https://github.com/davidonzo/Threat-Intel) · [site](https://osint.digitalside.it) | IOC | repo / feed | 2026-09-06 | OSINT.DigitalSide (STIX / MISP / CSV) ; sous-domaine `osint.digitalside.it` intermittent → privilégier le dépôt GitHub `davidonzo/Threat-Intel` |
| [TweetFeed](https://tweetfeed.live) | IOC | web / API | vivant | IOC partagés sur X, agrégés et datés |
| [0xDanielLopez](https://github.com/0xDanielLopez) | IOC | repo | vivant | phishunt, phishing_kits |
| [curated-intel](https://github.com/curated-intel) · [newsletter](https://www.curatedintel.org/) | IOC+RENS | repo / Atom | vivant | listes par campagne ; la newsletter reprend des indicateurs défangés |
| [mthcht — ThreatIntel-Reports](https://github.com/mthcht) | IOC+RENS | repo | vivant | ThreatIntel-Reports, listes de détection |
| [blackorbird — APT_REPORT](https://github.com/blackorbird/APT_REPORT) | IOC+RENS | repo | vivant | collection de rapports APT |
| [despacito420 — The-Feed](https://github.com/despacito420/The-Feed) | IOC+RENS | repo | vivant | agrégat d'IOC |
| [APTnotes](https://github.com/aptnotes/data) | RENS | repo | figé 2024 | archive de rapports APT |
| [CyberMonitor](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections) | RENS | repo | figé 2024 | archive de rapports APT et cybercrime |
| [vx-underground](https://vx-underground.org) · [Telegram](https://t.me/s/vxunderground) | IOC+RENS | web, bot / Telegram | vivant | l'aperçu public du canal Telegram est lisible, le site non |
| [gm7.org — 信息安全知识库](https://www.gm7.org) | IOC+RENS | RSS | vivant | agrégateur chinois `[ZH]` |
| [tanjiti — sec_profile](https://github.com/tanjiti/sec_profile) | RENS | repo | vivant | agrégateur chinois `[ZH]` |
| [安全内参 secrss](https://www.secrss.com/articles?tag=APT) | IOC+RENS | web | vivant | agrégateur chinois `[ZH]` |
| [安全客](https://www.anquanke.com/) | RENS | web | vivant | agrégateur chinois `[ZH]` |
| [Habr — infosecurity](https://habr.com/ru/hubs/infosecurity/articles/) | IOC+RENS | RSS | vivant | `[RU]` |
| [Xakep](https://xakep.ru/) | RENS | RSS | vivant | `[RU]` |
| [piyolog](https://piyolog.hatenadiary.jp/) | IOC+RENS | RSS | vivant | chronologies d'incidents japonais `[JP]` |
| [Midnight Slayer — start.me](https://start.me/p/wMPxqX/cyber-threat-intelligence) | RENS | web, bot | vivant | |
| [dragnet](https://github.com/dragnet-dev) | IOC | repo | annoncé | à surveiller |
| [Mr Looquer](https://iocfeed.mrlooquer.com) | IOC | feed | 2023 | peu ou pas maintenu |
| [xxspell — ctifeeds](https://gitlab.com/xxspell/ctifeeds) | IOC | repo | 2024 | peu ou pas maintenu |
| [黑鸟 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/f22e132bbbc4e8070cd51c0a84802f940e131a20.xml) | IOC+RENS | RSS (WeChat) | 2026-09 | analyste indépendant ; indicateurs défangés et IP `[ZH]` |
| [ChaMd5安全团队 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/ffb536c22df3989d8077ce9babb475f41719d62d.xml) | IOC+RENS | RSS (WeChat) | 2026-09 | équipe communautaire `[ZH]` |
| [漕河泾小黑屋 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/f38c9a9f230e19f49918faefc5d0d0fc71e52d29.xml) | IOC+RENS | RSS (WeChat) | 2026-09 | analyste indépendant `[ZH]` |
| [kernsec (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/4767e1bec36c42a1c1cf1c991a3a1a027d1b49a5.xml) | RENS | RSS (WeChat) | 2026-09 | analyste indépendant ; IOC non vérifiés `[ZH]` |
| [有价值炮灰 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/ca9e6f3e905e64301c6f00a21f2e3f135df1e691.xml) | IOC+RENS | RSS (WeChat) | 2026-09 | analyste indépendant `[ZH]` |
| [渊龙Sec安全团队 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/21b0fdc5197bc18c5d0a0c4a5a557a98ae4c01c7.xml) | IOC+RENS | RSS (WeChat) | 2026-09 | équipe communautaire `[ZH]` |
| [RedTeaming (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/e4a8e7ce5182a107ed90452e8738155534dd297a.xml) | IOC+RENS | RSS (WeChat) | 2026-09 | équipe communautaire `[ZH]` |
| [Desync InfoSec (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/9e1ec91d1a8cb22871f812bbe62fb7fe6c7b3e28.xml) | IOC+RENS | RSS (WeChat) | 2026-09 | équipe communautaire `[ZH]` |
| [矛和盾的故事 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/308da52e82d7f7bc2a9f6a5f63633c5567b7af08.xml) | IOC+RENS | RSS (WeChat) | 2026-09 | analyste CTI indépendant `[ZH]` |
| [Detect FYI](https://detect.fyi/feed) | IOC+RENS | RSS (Medium) | 2026-09 | publication collective d'ingénierie de détection ; hash et indicateurs défangés |
| [Emanuele Carlesi](https://infosec.exchange/@ecarlesi) | IOC+RENS | RSS (Mastodon) | 2026-09 | chasseur de phishing ; domaines défangés |
| [1ZRR4H](https://infosec.exchange/@1ZRR4H) | RENS | RSS (Mastodon) | 2024-06 | chasseur de C2 ; inactif depuis 2024 |
| [SecAtor](https://t.me/s/true_secator) | IOC+RENS | Telegram | 2026-08 | canal CTI russophone le plus suivi `[RU]` |
| [Alex Makus](https://t.me/s/alexmakus) | RENS | Telegram | vivant | analyste russophone `[RU]` |
| [Cyber Threat Intel (Telegram)](https://t.me/s/cyber_threat_intel) | RENS | Telegram | vivant | canal russophone `[RU]` |
| [Kevin Beaumont](https://cyberplace.social/@GossiTheDog) | RENS | RSS (Mastodon) | vivant | complète DoublePulsar (Medium, bloque les robots) |
| [This Week in 4n6](https://thisweekin4n6.com/) | RENS | RSS | vivant | revue hebdomadaire DFIR / CTI (Phill Moore) |
| [The Cybersecurity Pulse](https://www.cybersecuritypulse.net/) | RENS | RSS | vivant | newsletter (Darwin Salazar) |
| [Ransomware Sommelier](https://ransomwaresommelier.com/) | RENS | RSS | 2025-08 | Allan Liska ; domaines défangés ponctuels |
| [tl;dr sec](https://tldrsec.com/) | RENS | web | vivant | newsletter |
| [SANS NewsBites](https://www.sans.org/newsletters/newsbites/) | RENS | web | vivant | newsletter |
| [Team Cymru — Dragon News Bytes](https://www.team-cymru.com/dnb) | RENS | web | vivant | newsletter |
| [BrewedIntel — threat-intel-mailing-lists](https://github.com/BrewedIntel/threat-intel-mailing-lists) | RENS | repo | vivant | méta-liste de newsletters |
| [電通総研 tech blog](https://tech.dentsusoken.com/) | RENS | RSS | vivant | comptes rendus de conférences `[JP]` |
| [DEF CON — media archive](https://media.defcon.org/) | RENS | web | vivant | archives de conférence |
| [Hack.lu — archive](https://archive.hack.lu/) | RENS | web | vivant | archives de conférence |
| [SSTIC](https://www.sstic.org/) | RENS | web | vivant | archives de conférence (France) |
| [REcon](https://recon.cx/) | RENS | web | vivant | archives de conférence |
| [POC — Power of Community](https://powerofcommunity.net/) | RENS | web | vivant | archives de conférence (Corée) |
| [AVAR](https://aavar.org/) | RENS | web | vivant | archives de conférence |
| [SANS Summit archives](https://www.sans.org/cyber-security-summit/archives/) | RENS | web | vivant | archives de conférence |

## 12. Journalistes et médias spécialisés

*Biais : sensationnalisme et absence d'IOC ; mais premiers sur les victimes, les infrastructures nommées et les fuites.*

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [DailySecu](https://cdn.dailysecu.com/rss/gn_rss_allArticle.xml) | KR | RENS | RSS | média sécurité coréen, complète Boan News `[KO]` |
| [anti-malware.ru](https://www.anti-malware.ru/analytics/feed) | RU | RENS | RSS | analyses et comparatifs du marché russe `[RU]` |
| [Segu-Info](https://blog.segu-info.com.ar/feeds/posts/default) | AR | IOC+RENS | Atom | blog argentin quotidien depuis 2000 `[ES]` |
| [Krebs on Security](https://krebsonsecurity.com/) · [Mastodon](https://infosec.exchange/@briankrebs) | US | IOC+RENS | RSS | |
| [Zero Day (K. Zetter)](https://www.zetter-zeroday.com/) | US | RENS | RSS | |
| [CyberScoop](https://cyberscoop.com/) | US | RENS | RSS | |
| [SecurityWeek](https://www.securityweek.com/) | US | RENS | RSS | |
| [Risky Business News](https://news.risky.biz/) | AU | RENS | RSS | |
| [The Record](https://therecord.media/) | US | RENS | RSS | média de Recorded Future (§7.1) |
| [BleepingComputer](https://www.bleepingcomputer.com/news/security/) | US | RENS | RSS, bot | |
| [ZATAZ](https://www.zataz.com/) | FR | RENS | RSS | |
| [LeMagIT](https://www.lemagit.fr/actualites/cybersecurite) | FR | RENS | RSS | suivi ransomware très fin |
| [Numerama Cyberguerre](https://www.numerama.com/cyberguerre/) | FR | RENS | web, bot | |
| [Hispasec — una al día](https://unaaldia.hispasec.com/) | ES | RENS | RSS | `[ES]` |
| [Red Hot Cyber](https://www.redhotcyber.com/) | IT | RENS | RSS | `[IT]` |
| [heise Security](https://www.heise.de/security) | DE | RENS | RSS | `[DE]` |
| [Security NEXT](https://www.security-next.com/) | JP | RENS | web | `[JP]` |
| [보안뉴스 Boan News](https://www.boannews.com/) | KR | RENS | RSS | `[KO]` |
| [Bellingcat](https://www.bellingcat.com/) | NL | RENS | web | OSINT |
| [The Hacker News](https://thehackernews.com/) | — | IOC+RENS | RSS | média, volume élevé ; reprend les hash et domaines des rapports cités |
| [Dark Reading](https://www.darkreading.com/) | US | RENS | RSS | média généraliste sécurité, volume élevé |
| [Infosecurity Magazine](https://www.infosecurity-magazine.com/rss/news/) | UK | RENS | RSS | média britannique, actualité quotidienne |
| [The Register — Security](https://www.theregister.com/security/) | UK | RENS | RSS (Atom) | média britannique, ton critique, couvre incidents et fuites |
| [CSO Online](https://www.csoonline.com/) | US | RENS | RSS | média orienté RSSI (IDG) |
| [SC Media](https://www.scworld.com/) | US | RENS | RSS | média sécurité nord-américain |
| [Cybernews](https://cybernews.com/security/) | LT | RENS | web | média lituanien ; flux et pages bloqués aux robots |
| [CyberWire](https://thecyberwire.com/) | US | RENS | web | newsletter et podcast |
| [Catalin Cimpanu](https://infosec.exchange/@campuscodi) | — | RENS | Mastodon | journaliste (Risky Business) |
| [Darknet Diaries](https://darknetdiaries.com/) | US | RENS | podcast (RSS) | |
| [SANS ISC StormCast](https://isc.sans.edu/podcast.html) | US | IOC+RENS | podcast (RSS) | quotidien ; hash et indicateurs des diaries ISC |
| [CNews Безопасность](https://safe.cnews.ru/) | RU | RENS | RSS | relais des rapports F6, PT, Kaspersky `[RU]` |
| [TAdviser — ИБ](https://www.tadviser.ru/) | RU | RENS | web, géo | encyclopédie du marché russe (fiches APT, éditeurs) ; ne résout pas hors Russie `[RU]` |
| [Rocket Boys — セキュリティ対策Lab](https://rocket-boys.co.jp/security-measures-lab/) | JP | RENS | web | chronologie des incidents japonais `[JP]` |
| [中国信息安全 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/567cb1a8cf49f3e2c141d9d8085712f42ffc2fef.xml) | CN | RENS | RSS (WeChat) | publication officielle `[ZH]` |
| [互联网安全内参 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/d5eb8577bf93aacdd7481ad0c3364939096b99a1.xml) | CN | IOC+RENS | RSS (WeChat) | publication para-officielle `[ZH]` |
| [网信军民融合 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/0c01ac36bf3a4f3153d8c568e1255b9e91825688.xml) | CN | RENS | RSS (WeChat) | publication para-officielle `[ZH]` |
| [数世咨询 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/9da87fba8130d0c2dc52cc45b844f045227e06a7.xml) | CN | RENS | RSS (WeChat) | cabinet d'analyse `[ZH]` |
| [安全牛 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/10f1ba549b70cdb4216f7ade606d30a813305aa1.xml) | CN | RENS | RSS (WeChat) | média `[ZH]` |
| [安全419 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/6f33507162907318fd059fb11977ca352ff55d8e.xml) | CN | RENS | RSS (WeChat) | média `[ZH]` |
| [嘶吼专业版 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/d351be711510e0b7ccbcb275cdfab5c4c7e3e839.xml) | CN | RENS | RSS (WeChat) | média `[ZH]` |
| [虎符智库 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/792558edf818ce03d377d1d2677afb4d6537853d.xml) | CN | RENS | RSS (WeChat) | think tank `[ZH]` |
| [榫卯江湖 (WeChat, Wechat2RSS)](https://wechat2rss.xlab.app/feed/d1988b840deaf6a79edd32e83a1b152038f1b6a1.xml) | CN | RENS | RSS (WeChat) | média `[ZH]` |

## 13. Ingérence numérique et abus de plateformes

*Biais : les plateformes ne publient que ce qui les valorise.*

| Source | Contenu | Accès | Commentaire |
|---|---|---|---|
| [VIGINUM — voir §3] | | | |
| [EU DisinfoLab](https://www.disinfo.eu/) | RENS | RSS | FIMI |
| [DFRLab](https://dfrlab.org/) | RENS | RSS | FIMI |
| [Graphika](https://www.graphika.com/reports) | RENS | web | FIMI |
| [Microsoft On the Issues (MTAC)](https://blogs.microsoft.com/on-the-issues/) | RENS | RSS | Digital Defense Report |
| [Meta — newsroom](https://about.fb.com/news/) | RENS | RSS (filtrer « adversarial threat ») | rapports trimestriels |
| [Google TAG / GTIG](https://blog.google/security/) | RENS | web | bulletins |
| [TikTok — covert influence operations](https://www.tiktok.com/safety/en/transparency/covert-influence-operations) | RENS | web | |
| [OpenAI — Disrupting malicious uses of AI](https://openai.com/global-affairs/disrupting-malicious-uses-of-ai/) | RENS | bot | abus des LLM par des acteurs étatiques |
| [Anthropic — threat intelligence](https://www.anthropic.com/news/detecting-countering-misuse-aug-2025) | RENS | web | abus des LLM par des acteurs étatiques |

## 14. Bases d'incidents, think tanks et rapports de référence

*Biais : politiques ou commerciaux ; utiles pour le contexte et les tendances, jamais pour les observables.*

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [EuRepoC](https://eurepoc.eu) | DE | RENS | RSS / exports | base codée d'incidents politiquement pertinents |
| [CFR Cyber Operations Tracker](https://www.cfr.org/cyber-operations/) | US | RENS | web | |
| [CSIS Significant Cyber Incidents](https://www.csis.org/programs/strategic-technologies-program/significant-cyber-incidents) | US | RENS | web | |
| [DCID](https://dcid.online/) | US | RENS | web | dataset d'incidents dyadiques |
| [CyberPeace Institute](https://cyberconflicts.protect.ngo/) | CH | RENS | web / RSS | |
| [RAND](https://www.rand.org/topics/cyber-warfare.html) | US | RENS | RSS | |
| [Atlantic Council Cyber Statecraft](https://www.atlanticcouncil.org/programs/cyber-statecraft-initiative/) | US | RENS | web | |
| [Carnegie](https://carnegieendowment.org/programs/technology-and-international-affairs) | US | RENS | web | |
| [Verizon DBIR](https://www.verizon.com/business/resources/reports/dbir/) | US | RENS | PDF | rapport annuel |
| [IBM X-Force](https://www.ibm.com/reports/threat-intelligence) | US | RENS | PDF | rapport annuel |
| [Picus Red Report](https://www.picussecurity.com/red-report) | — | RENS | PDF | rapport annuel |
| [NETSCOUT](https://www.netscout.com/threatreport) | US | RENS | PDF | rapport annuel |
| [CLUSIT](https://clusit.it/rapporto-clusit/) | IT | RENS | PDF | rapport annuel `[IT]` |

## 15. Sandboxes et dépôts d'échantillons

*Biais : échantillons soumis par des tiers, donc bruités, parfois plantés.*

| Source | Contenu | Accès | Commentaire |
|---|---|---|---|
| [MalShare](https://malshare.com) | IOC | API, inscr. | dépôt d'échantillons gratuit, clé requise |
| MalwareBazaar (voir §2.1) | IOC | API, inscr. | dépôt d'échantillons couvert dans sa section |
| VirusShare (voir §9) | IOC | API, inscr. | dépôt d'échantillons couvert dans sa section |
| [urlscan.io](https://urlscan.io/) | IOC | web / API | compte gratuit |
| [Hybrid Analysis](https://hybrid-analysis.com/) | IOC | web / API | compte gratuit |
| [Triage](https://tria.ge/) | IOC | web / API | compte gratuit |
| [FileScan.io](https://www.filescan.io/) | IOC | web / API | compte gratuit |
| [UnpacMe](https://www.unpac.me/) | IOC | web / API | compte gratuit |
| [PolySwarm](https://polyswarm.io/) | IOC | web / API | compte gratuit |
| [ANY.RUN](https://any.run/cybersecurity-blog/) | IOC+RENS | RSS | |
| [Yomi](https://yomi.yoroi.company/) | IOC+RENS | web | sandbox de Yoroi |
| [Threat.Zone](https://threat.zone/) | IOC+RENS | web | Turquie |
| [OALabs](https://research.openanalysis.net/) | IOC+RENS | RSS | |
| [Joe Sandbox](https://www.joesandbox.com/) | IOC | bot | |
| [CAPE](https://capesandbox.com/) | IOC | bot | |

## 16. Règles de détection

| Source | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|
| [Yamato Security — hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) · [hayabusa (moteur)](https://github.com/Yamato-Security/hayabusa) | IOC | repo | 2026-09-03 | ~4 000 règles de détection Windows (Sigma étendu), équipe japonaise |
| [SigmaHQ](https://github.com/SigmaHQ/sigma) | IOC | repo | vivant | règles Sigma canoniques |
| [elastic detection-rules](https://github.com/elastic/detection-rules) | IOC | repo | vivant | règles Elastic Security |
| [splunk security_content](https://github.com/splunk/security_content) | IOC | repo | vivant | détections Splunk (ESCU) |
| [chronicle detection-rules](https://github.com/chronicle/detection-rules) | IOC | repo | vivant | règles YARA-L (Google SecOps) |
| [Sublime rules](https://github.com/Sublime-Security/sublime-rules) | IOC | repo | vivant | règles de détection e-mail |
| [Neo23x0 signature-base](https://github.com/Neo23x0/signature-base) | IOC | repo | vivant | base YARA de référence (THOR / LOKI) |
| [YARAHQ yara-forge](https://github.com/YARAHQ/yara-forge) | IOC | repo | vivant | agrégat normalisé de règles YARA publiques |
| [Volexity — threat-intel](https://github.com/volexity/threat-intel) | IOC | repo | vivant | YARA et IOC par campagne |
| [RussianPanda — Yara-Rules](https://github.com/RussianPanda95/Yara-Rules) | IOC | repo | 2026-08 | règles sur stealers et loaders |
| [bartblaze — Yara-rules](https://github.com/bartblaze/Yara-rules) | IOC | repo | 2026-01 | règles génériques |
| [ReversingLabs — yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) | IOC | repo | 2025-11 | règles de l'éditeur |
| HarfangLab (voir §7.1) | IOC | repo | — | dépôt YARA couvert dans sa section |
| JPCERT/CC yara (voir §3) | IOC | repo | — | dépôt YARA couvert dans sa section |
| [MISP warninglists](https://github.com/MISP/misp-warninglists) | IOC | repo | vivant | faux positifs ; y ajouter FireHOL level1 et la liste Tor |
| [RuleCheck.io Detections Digest](https://detections-digest.rulecheck.io) | RENS | newsletter | vivant | ctichef.com hors ligne |
| [Nuclei — voir §7.2] | | | | |

## 17. Angles morts

Constats après cinq passes de recherche (IOC, rapports, typologie, annuaires TI/M3AAWG/FIRST). Ces trous sont structurels, pas un défaut de recherche : la répartition des annuaires le montre.

| Zone / famille | Constat |
|---|---|
| **Golfe** | 18 membres FIRST (banques centrales, télécoms, autorités) : aucune publication technique ouverte ; Bahreïn et Koweït sur abonnement. |
| **Iran** | AFTA (`afta.gov.ir`), centres APA (`nsec.ir`, `cert.iut.ac.ir`), Padvish publient des IOC mais répondent 503 hors d'Iran ; 0 membre FIRST. `cert.gov.ir`, `apa.aut.ac.ir`, `shabakeh-mag.com` injoignables : filtrage sortant probable. |
| **Corée** | FSI, NCSC-KR, IGLOO, SK shieldus bloquent hors du pays — sources majeures sur les APT nord-coréennes. |
| **Asie du Sud / Sud-Est, Afrique subsaharienne** | une équipe FIRST par pays (le CERT national). |
| **Asie centrale / Caucase** | CERT.TJ seul flux ; TSARKA et CERT.AM injoignables. |
| **Adtech / anti-bot** (Confiant, HUMAN, DataDome, Imperva) | seule famille à voir le malvertising et les proxies résidentiels ; tous bloquent les robots. |
| **CERT bancaires et industriels** | présents dans TI/FIRST, ne publient pas ; observables réservés aux cercles fermés. |
| **États producteurs de contre-narratifs** (CVERC, NKTsKI, agences occidentales) | attribution miroir, IOC réels mêlés à des récits : recouper systématiquement. |
| **Telegram / Discord / Mastodon** | Telegram lisible seulement via l'aperçu public `t.me/s/<canal>` (la plupart des canaux institutionnels — PT ESC, F6, Solar 4RAYS, CERT-UA, ransomware.live — n'en ont pas) ; Mastodon lisible en RSS ; Bluesky quasi vide de CTI ; Discord non explorable. |
| **Plateformes de code non occidentales** (Gitee, GitCode, AtomGit, GitLink, Coding.net, GitVerse, GitFlic) | miroirs de GitHub ou code métier, aucune production CTI originale. La CTI chinoise et russe passe par des articles — WeChat (§7.1 Chine, via Wechat2RSS §11) et Telegram — pas par des dépôts. |
| **WeChat (微信公众号)** | canal principal des labos chinois, ni indexable ni abonnable nativement ; contourné par la passerelle Wechat2RSS (§11), qui rend lisibles QiAnXin, Tencent, ThreatBook ou CNCERT. |
| **Constructeurs et PSIRT** (Huawei, ZTE, Hikvision, Xiaomi, QNAP, Synology, Zyxel, ASUS, Moxa, Mitsubishi Electric, Samsung, LG, Zoho, Yandex…) | n'émettent que des avis de vulnérabilité, jamais d'observable ni d'analyse d'acteur : hors périmètre. |
| **Plateformes russes** (R-Vision, Security Vision, UserGate, Гарда, Код Безопасности, InfoWatch) | marketing ou blocage ; l'écosystème CTI russe se réduit à Kaspersky, F6, PT, BI.ZONE, Solar, Dr.Web (listés). |
| **SSII indiennes** | hors Quick Heal/Seqrite, K7, CloudSEK, Cyble, CYFIRMA, rien de publié. |
| **Constructeurs japonais** (Panasonic, Omron, Sony, Canon, Fujitsu) | fermés aux robots ; note.com et Hatena ne résolvent pas. |
| **Reddit, Bluesky** | Reddit refuse les robots (403) ; Bluesky quasi vide de CTI. |

## 18. Sources écartées

Rejetées : dépôt figé depuis plus de 18 mois, page morte, miroir, source absorbée, ou aucune production CTI originale.

| Source | Raison |
|---|---|
| NetManageIT — OpenCTI public | instance publique hors ligne en 2026 |
| Threatpost | plus aucune publication depuis août 2022 (absorbé) |
| `mandiant/iocs` | figé ou archivé (2019–2024) |
| `advanced-threat-research/IOCs` (Trellix) | figé ou archivé (2019–2024) |
| `Insikt-Group/Research` | figé ou archivé (2019–2024) |
| `trendmicro/research` | figé ou archivé (2019–2024) |
| `StrangerealIntel/*` | figé ou archivé (2019–2024) |
| `swisscom/detections` | figé ou archivé (2019–2024) |
| `Orange-Cyberdefense/russia-ukraine_IOCs` | figé ou archivé (2019–2024) |
| `CryptoScamDB/blacklist` | figé ou archivé (2019–2024) |
| `Yara-Rules/rules` | figé ou archivé (2019–2024) |
| `InQuest/yara-rules-vt` | figé ou archivé (2019–2024) |
| `KasperskyLab/klara` | figé ou archivé (2019–2024) |
| `kbandla/APTnotes` | figé ou archivé (2019–2024) |
| `0xToxin/Malware-IOCs` | figé ou archivé (2019–2024) |
| `MalGamy/YARA_Rules` | figé ou archivé (2019–2024) |
| `nshc-threatrecon/IoC-List` | figé ou archivé (2019–2024) |
| `montysecurity/C2-Tracker` | figé ou archivé (2019–2024) |
| `executemalware/Malware-IOCs` | activité déclinante (2024–2025) : surveiller |
| `ditekshen/detection` | activité déclinante (2024–2025) : surveiller |
| `ThreatMon-Reports-IOC` | activité déclinante (2024–2025) : surveiller |
| `pr0xylife/*` | activité déclinante (2024–2025) : surveiller |
| `elliotwutingfeng/ThreatFox-IOC-*` | miroir |
| `elliotwutingfeng/URLhaus-IOC` | miroir |
| `Cyberfury101/deepdarkCTI` | miroir |
| Secureworks CTU | absorbé (Sophos) |
| CyberArk Labs | absorbé (Palo Alto) |
| Vade | absorbé (Hornetsecurity) |
| Egress | absorbé (KnowBe4) |
| Avanan | absorbé (Check Point) |
| Zix | absorbé (OpenText) |
| Cyren | absorbé (Data443) |
| CSIS Security Group (DK) | introuvable / fermé |
| Stanford Internet Observatory | fermé |
| Cyber Defense Institute blog | remplacé (site au §7.1 Japon) |
| `SlowMist/SlowMist-Hacked` | remplacé (`hacked.slowmist.io`, §2.3) |
| USOM `url-list.txt` | remplacé (API Swagger de siberguvenlik.gov.tr) |
| Gitee | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| GitCode | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| AtomGit | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| GitLink | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| Coding.net | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| GitVerse | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| GitFlic | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| Codeberg | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| sourcehut | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| Framagit | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| Salsa (Debian) | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| Qiita | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| Zenn | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| Viblo | plateforme de code / de développement sans CTI originale (miroirs GitHub ou hors sujet) |
| MalwareTech | vivant mais 403 aux robots ; à suivre manuellement |
| DoublePulsar (K. Beaumont) | vivant mais 403 aux robots (Medium) ; à suivre manuellement |
| cyb3rops (Medium) | vivant mais 403 aux robots (Medium) ; à suivre manuellement |
| M. Koczwara (Medium) | vivant mais 403 aux robots (Medium) ; à suivre manuellement |
| Marco Ramilli | flux absent ou cassé ; à suivre manuellement |
| Malware Unicorn | flux absent ou cassé ; à suivre manuellement |
| 0ffset | figé (2024-04) |
| Security Soup | flux absent ou cassé ; à suivre manuellement |
| hackers-arise | 403 aux robots (Cloudflare) ; à suivre manuellement |

## 19. Origine de la liste et contribution

**Comment les sources ont été trouvées.** Cinq passes : (1) recherche par pays et langue ; (2) rapports et référentiels d'acteurs ; (3) typologie de 20 familles de producteurs, chacune avec son biais, et fouille de la liste des membres de la Cyber Threat Alliance ; (4) JSON public Trusted Introducer (554 équipes) et communiqués M3AAWG ; (5) API publique FIRST (879 équipes). La fouille d'annuaires a rapporté plus que toutes les requêtes en langue locale réunies.

**Contribuer.** Une ligne = une source, avec Contenu (`IOC` / `RENS` / `IOC+RENS`), Accès (feed/repo/API/RSS/web/PDF/inscr./bot/géo), date d'activité et un commentaire d'une ligne indiquant ce qu'elle apporte que les autres n'ont pas. Une source morte, figée ou sans production originale va en §18 avec sa raison.

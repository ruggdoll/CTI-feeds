# CTI-feeds

Liste de sources de renseignement concernant la menace d'origine cyber.

> Dernière vérification des liens : 2026-09-02 (~470 sources ; tag `IOC` audité le 2026-09-02). Méthode au §19.
>
> Les sources ne sont pas restreintes à l'anglais. La langue est indiquée entre crochets — p. ex. `[ZH]`, `[RU]`, `[KO]` — lorsqu'elle n'est ni le français ni l'anglais.
>
> Aucune source n'est écartée en raison de son pays d'origine ou de son affiliation. Le recoupement des informations et la prise en compte du contexte propre à chaque source relèvent de l'analyste. Chaque section ouvre par le **biais** propre à la famille de producteurs : c'est la première chose à garder en tête au recoupement.

## Lire une ligne

| Colonne | Valeurs |
|---|---|
| **Contenu** | `IOC` = observables exploitables (hash, IP, domaines, URL, adresses, règles) · `RENS` = analyses, rapports, attribution, contexte · `IOC+RENS` = les deux. **Le tag `IOC` n'est attribué que sur preuve** : dépôt/feed dont le contenu a été vu, ou sonde ayant extrait des hash, IP ou indicateurs défangés du texte des publications (méthode au §19, résultats dans [`verification-IOC-2026-09-02.md`](verification-IOC-2026-09-02.md)). Une source réputée publier des IOC mais dont la sonde n'a rien extrait reste `RENS`, avec la mention « IOC non vérifiés » quand le site est en JavaScript, bloque les robots ou publie en PDF. |
| **Accès** | `feed` (TXT/CSV/JSON/STIX/MISP, URL stable) · `repo` (GitHub/GitLab) · `API` · `RSS` (flux vérifié) · `web` (pas de flux) · `PDF` · `inscr.` (compte requis) · `bot` (site vivant mais bloque les robots : ouvrir dans un navigateur) · `géo` (filtrage géographique probable) |
| **Activité** | date du dernier commit vérifiée pour les dépôts ; sinon « vivant » = répond au 2026-09-02 |

Pour l'ingestion automatique (MISP, OpenCTI), ne retenir que `feed`, `repo` et `API` ; les `RSS` vont dans un lecteur ou un connecteur RSS, avec extraction d'IOC à la demande.

## Sommaire

1. [Référentiels et annuaires](#1-référentiels-et-annuaires)
2. [Feeds communautaires, fondations et lutte anti-abus](#2-feeds-communautaires-fondations-et-lutte-anti-abus)
3. [CERT / CSIRT nationaux et organisations régionales](#3-cert--csirt-nationaux-et-organisations-régionales)
4. [Police, justice, sanctions et attribution officielle](#4-police-justice-sanctions-et-attribution-officielle)
5. [CERT sectoriels, ISAC et infrastructures critiques](#5-cert-sectoriels-isac-et-infrastructures-critiques)
6. [Infrastructure Internet : registres, RIR, NREN, cloud, opérateurs](#6-infrastructure-internet--registres-rir-nren-cloud-opérateurs)
7. [Éditeurs et laboratoires de recherche privés](#7-éditeurs-et-laboratoires-de-recherche-privés)
8. [Réponse à incident, conseil, assurance](#8-réponse-à-incident-conseil-assurance)
9. [Recherche académique et datasets](#9-recherche-académique-et-datasets)
10. [Cybercriminalité : trackers, sites de fuite, victimologie](#10-cybercriminalité--trackers-sites-de-fuite-victimologie)
11. [Chercheurs indépendants, communautés et agrégateurs](#11-chercheurs-indépendants-communautés-et-agrégateurs)
12. [Journalistes et médias spécialisés](#12-journalistes-et-médias-spécialisés)
13. [Ingérence numérique et abus de plateformes](#13-ingérence-numérique-et-abus-de-plateformes)
14. [Bases d'incidents, think tanks et rapports de référence](#14-bases-dincidents-think-tanks-et-rapports-de-référence)
15. [Sandboxes et dépôts d'échantillons](#15-sandboxes-et-dépôts-déchantillons)
16. [Règles de détection](#16-règles-de-détection)
17. [Angles morts](#17-angles-morts)
18. [Sources écartées](#18-sources-écartées)
19. [Méthodologie et vérification](#19-méthodologie-et-vérification)

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
| [lazarus.day](https://lazarus.day) | — | RENS | web | vivant | index des rapports sur les groupes nord-coréens |
| [RST Cloud — awesome-threat-actor-resources](https://github.com/rstcloud/awesome-threat-actor-resources) | — | RENS | repo | vivant | méta-liste de profils d'acteurs et datasets |
| [Trusted Introducer](https://www.trusted-introducer.org) · [export JSON](https://www.trusted-introducer.org/trusted-introducer/directory/downloads/json/teams/) | EU | RENS | JSON | vivant | annuaire de 554 équipes (contacts, PGP, constituency) ; le seul export machine européen |
| [FIRST](https://www.first.org) · [API](https://api.first.org/data/v1/teams?limit=100) | — | RENS | API | vivant | 879 équipes mondiales, paginé par 100 ; diff mensuel recommandé (§19) |
| [Onetracker](https://onetracker.org/ti) | — | RENS | web | vivant | annuaire d'échantillons, PCAP, feeds, blocklists |
| [hslatman — awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence) · [sroberts — awesome-iocs](https://github.com/sroberts/awesome-iocs) · [InQuest — awesome-yara](https://github.com/InQuest/awesome-yara) | — | RENS | repo | vivant | listes de référence |
| [Threatfeeds.io](https://threatfeeds.io) | — | RENS | web | ~2019 | annuaire de feeds, peu mis à jour |

## 2. Feeds communautaires, fondations et lutte anti-abus

*Biais : mesurent le volume et l'opportunisme (spam, scans, phishing de masse), pas le ciblé ; les listes de blocage produisent des faux positifs par conception. Les agrégateurs recyclent : vérifier la provenance avant d'empiler.*

### 2.1 Fondations et projets de référence

| Source | Pays | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|---|
| [abuse.ch](https://abuse.ch) — [URLhaus](https://urlhaus.abuse.ch), [MalwareBazaar](https://bazaar.abuse.ch), [ThreatFox](https://threatfox.abuse.ch), [Feodo Tracker](https://feodotracker.abuse.ch), [SSLBL](https://sslbl.abuse.ch) | CH | IOC | feed/API (CSV/JSON/MISP/Suricata) | vivant | hébergé par la Haute école spécialisée bernoise ; site bloque les robots, les feeds non |
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
| [stamparm — Ipsum](https://github.com/stamparm/Ipsum) · [Maltrail trails](https://github.com/stamparm/maltrail/tree/master/trails/static) | RS | IOC | repo | 2026-09-01 | Ipsum : IP scorées ; Maltrail : trails par famille (C2, DGA, scanners) |
| [Emerging Threats — compromised-ips](https://rules.emergingthreats.net/blockrules/compromised-ips.txt) | US | IOC | feed | vivant | |
| [Binary Defense banlist](https://binarydefense.com/banlist.txt) | US | IOC | feed | vivant | |
| [GreenSnow](https://blocklist.greensnow.co/greensnow.txt) | FR | IOC | feed | vivant | brute-force, scans |
| [BruteForceBlocker](https://danger.rulez.sk/projects/bruteforceblocker/blist.php) | SK | IOC | feed | vivant | SSH |
| [Phishing Army](https://phishing.army) | IT | IOC | feed | vivant | domaines de phishing |
| [OpenPhish](https://openphish.com) / [PhishTank](https://phishtank.org) | — | IOC | feed | vivant | versions publiques limitées |
| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) | ZA | IOC | repo | 2026-08-23 | domaines/IP/liens de phishing |
| [Inversion DNSBL Blocklists](https://github.com/elliotwutingfeng/Inversion-DNSBL-Blocklists) | SG | IOC | repo | 2026-09-01 | URL malveillantes issues de scans originaux (ses dépôts `ThreatFox-IOC-*` sont des miroirs) |
| [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) | DE | IOC | repo (hosts/ABP/RPZ) | 2026-09-01 | liste TIF pour DNS-RPZ |
| [The Block List Project](https://blocklistproject.github.io/Lists/) | — | IOC | repo | 2026-07-20 | |
| [FireHOL IP lists](https://iplists.firehol.org) · [repo](https://github.com/firehol/blocklist-ipsets) | — | IOC | repo | 2026-09-01 | agrégation scorée de ~400 listes ; plutôt warninglist / comparaison de couverture |
| [SURBL](https://www.surbl.org) / [URIBL](https://uribl.com) | US | IOC | DNSBL, licence | vivant | URI de spam et phishing |
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

## 3. CERT / CSIRT nationaux et organisations régionales

*Biais : mandat public, IOC souvent tardifs mais fiables ; l'attribution est parfois politique (voir §17 sur les contre-narratifs). Beaucoup publient dans des avis web plutôt qu'en feed.*

### France

| Source | Contenu | Accès | Commentaire |
|---|---|---|---|
| [CERT-FR / ANSSI](https://www.cert.ssi.gouv.fr/ioc) · [GitHub ANSSI-FR](https://github.com/ANSSI-FR) | IOC+RENS | feed (MISP) / repo | feed IOC officiel ; outils DFIR (DFIR-ORC, DFIR-OGRE) |
| [VIGINUM](https://github.com/VIGINUM-FR/Rapports-Techniques) | RENS | repo | ingérence numérique étrangère (dernière MAJ sept. 2025) |
| [Cybermalveillance.gouv.fr](https://www.cybermalveillance.gouv.fr/) | RENS | web, bot | alertes grand public, rapport annuel |
| [Phishing Initiative](https://phishing-initiative.eu/contrib/) · [Signal Spam](https://www.signal-spam.fr/) | IOC | web | signalement d'URL de phishing / spam |

### Organisations régionales et supranationales

| Source | Contenu | Accès | Commentaire |
|---|---|---|---|
| [ENISA — CSIRTs Network](https://github.com/enisaeu/CNW) · [publications](https://www.enisa.europa.eu/publications) (UE) | IOC+RENS | repo / PDF | avis agrégés des CSIRT de l'UE ; Threat Landscape annuel |
| [CERT-EU](https://cert.europa.eu/publications/threat-intelligence) · [`droid`](https://github.com/certeu/droid) (UE) | IOC+RENS | web / repo | institutions de l'UE ; gestion de règles Sigma |
| [Europol — newsroom](https://www.europol.europa.eu/media-press/newsroom) (UE) | RENS | web | démantèlements, infrastructures saisies |
| [NATO CCDCOE](https://ccdcoe.org/library/publications/) | RENS | PDF | recherche cyber-conflit |
| [Trusted Introducer / TF-CSIRT](https://www.trusted-introducer.org) (Europe) | RENS | JSON | voir §1 |
| [APCERT](https://www.apcert.org) (Asie-Pacifique) · [ASEAN Regional CERT](https://www.csa.gov.sg/news-events/press-releases/establishment-of-asean-regional-computer-emergency-response-team/) · [AfricaCERT](https://www.africacert.org) · [OEA — CSIRTAmericas](https://csirtamericas.org) `[ES/EN/PT]` · [OIC-CERT](https://oic-cert.org) | RENS | web | organisations régionales ; OIC-CERT parfois injoignable hors région |
| [FIRST](https://www.first.org) | RENS | API | voir §1 |
| [UNODC cybercrime](https://www.unodc.org/unodc/en/cybercrime/) · [ITU-D](https://www.itu.int/itu-d/sites/cybersecurity/) | RENS | web | rapports, pas d'observables |

### États membres de l'UE

| Pays | Source | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| Allemagne | [BSI / CERT-Bund](https://github.com/BSI-Bund) · [wid.cert-bund.de](https://wid.cert-bund.de) · [Lagebericht](https://www.bsi.bund.de/DE/Service-Navi/Publikationen/Lagebericht/lagebericht_node.html) | IOC+RENS | repo/web/PDF | honeypot MADCAT, CSAF ; rapport annuel `[DE]` |
| Autriche | [CERT.at](https://www.cert.at) | RENS | web, blog bot | opéré par nic.at `[DE/EN]` |
| Belgique | [CCB / CERT.be](https://cert.be) | RENS | web, bot | IOC non vérifiés |
| Bulgarie | [CERT Bulgaria](https://govcert.bg) | RENS | web | `[BG]` |
| Chypre | [CSIRT-CY](https://csirt.cy) | RENS | web | `[EL/EN]` |
| Croatie | [CERT.hr](https://www.cert.hr) | RENS | web | `[HR]` |
| Danemark | [CFCS](https://www.cfcs.dk) | RENS | web | redirige vers samsik.dk `[DA/EN]` |
| Espagne | [CCN-CERT](https://www.ccn-cert.cni.es) · [INCIBE-CERT](https://www.incibe.es/en/incibe-cert) | RENS | web, inscr. ; CCN bot | rapports APT ; IOC non vérifiés (CCN réservé, INCIBE : avis sans observables) `[ES]` |
| Estonie | [CERT-EE / RIA](https://github.com/cert-ee) | RENS | repo | outils (Cuckoo3, S4A), pas d'IOC |
| Finlande | [NCSC-FI / Traficom](https://www.kyberturvallisuuskeskus.fi) | RENS | web | `[FI/SV/EN]` |
| Grèce | [NCSA / EL CSIRT](https://cyber.gov.gr) | RENS | web | `[EL/EN]` |
| Hongrie | [NKI / NBSZ](https://nki.gov.hu) | RENS | web | `[HU]` |
| Irlande | [NCSC-IE](https://www.ncsc.gov.ie) · [IRISSCERT](https://iriss.ie/) | RENS | web / RSS | IRISSCERT : CERT non lucratif |
| Italie | [CERT-AGID](https://cert-agid.gov.it) | IOC | feed, inscr. | malware/phishing visant l'Italie, quotidien `[IT]` |
| Lettonie | [CERT.LV](https://www.cert.lv/en/data-feed) | IOC | feed, sur demande | data feed national (sinkhole, IP/domaines compromis) ; contenu réservé |
| Lituanie | [NKSC](https://www.nksc.lt) | RENS | web, bot | `[LT/EN]` |
| Luxembourg | [CIRCL](https://www.circl.lu) | IOC+RENS | feed | voir §2.1 |
| Malte | [CSIRTMalta](https://csirtmalta.gov.mt) | RENS | web, géo | |
| Pays-Bas | [NCSC-NL](https://github.com/NCSC-NL) | IOC | repo | IOC et scripts par campagne |
| Pologne | [CERT Polska](https://github.com/CERT-Polska) · [publikacje](https://cert.pl/publikacje/) · [NASK raporty](https://www.nask.pl/raporty) | IOC+RENS | repo / Atom / PDF | mwdb, drakvuf, Artemis ; hole.cert.pl (§2.2) `[PL/EN]` |
| Portugal | [CNCS / CERT.PT](https://www.cncs.gov.pt) | RENS | web | `[PT]` |
| Roumanie | [DNSC](https://www.dnsc.ro) | RENS | web, bot | `[RO/EN]` |
| Slovaquie | [SK-CERT](https://www.sk-cert.sk) | RENS | web | `[SK/EN]` |
| Slovénie | [SI-CERT](https://www.cert.si) | RENS | web | `[SL/EN]` |
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
| Bangladesh | [BGD e-GOV CIRT](https://www.cirt.gov.bd) | RENS | web, bot | très actif ; IOC non vérifiés |
| Bélarus | [CERT.BY](https://cert.by) | RENS | web | `[RU]` |
| Bolivie | [CGII / CSIRT-Bolivia](https://csirt.gob.bo) | RENS | web | `[ES]` |
| Brésil | [CERT.br](https://cert.br) | RENS | web | honeypots, spam, statistiques agrégées (pas d'IOC publiés) `[PT/EN]` |
| Canada | [CCCS](https://github.com/CybercentreCanada) · [avis](https://www.cyber.gc.ca/en/alerts-advisories) · [National Cyber Threat Assessment](https://www.cyber.gc.ca/en/guidance/national-cyber-threat-assessment-2025-2026) | IOC+RENS | repo/web | AssemblyLine, extracteurs de config ; évaluation biennale |
| Chili | [CSIRT de Gobierno](https://csirt.gob.cl) | RENS | web, bot | très régulier ; IOC non vérifiés `[ES]` |
| Chine | [CNCERT/CC](https://www.cert.org.cn/publish/english/index.html) · [CVERC](https://www.cverc.org.cn) | RENS | web | rapports et contre-attribution `[ZH]` |
| Colombie | [colCERT](https://www.colcert.gov.co) | RENS | web | `[ES]` |
| Corée du Sud | [KrCERT / KISA](https://www.krcert.or.kr) | RENS | web (JS) | IOC non vérifiés `[KO]` |
| Côte d'Ivoire | [CI-CERT](https://www.artci.ci) | RENS | web | |
| Égypte | [EG-CERT](https://egcert.eg) | RENS | web, géo | `[AR/EN]` |
| Émirats arabes unis | [aeCERT](https://aecert.ae) | RENS | web | `[AR/EN]` |
| Équateur | [EcuCERT](https://www.ecucert.gob.ec) | RENS | web | `[ES]` |
| États-Unis | [CISA](https://github.com/cisagov) · [KEV](https://github.com/cisagov/kev-data) · [avis](https://www.cisa.gov/news-events/cybersecurity-advisories) · [CERT/CC](https://github.com/CERTCC) · [NSA Cybersecurity](https://github.com/nsacyber) | IOC+RENS | repo/web | |
| Géorgie | [CERT.GOV.GE](https://cert.dga.gov.ge) | RENS | web | `[KA/EN]` |
| Ghana | [CSA / CERT-GH](https://www.csa.gov.gh) | RENS | web | |
| Hong Kong | [HKCERT](https://www.hkcert.org) | RENS | web | bulletins de vulnérabilités, pas d'IOC `[ZH/EN]` |
| Inde | [CERT-In](https://www.cert-in.org.in) · [CSK](https://www.csk.gov.in) · [NCIIPC](https://nciipc.gov.in) | RENS | web (JS) | IOC non vérifiés ; NCIIPC surtout accessible depuis l'Inde |
| Inde | [MH-CERT](https://github.com/MH-CERT) | IOC | repo | `Indicator-of-Compromise-IOC-`, activité faible |
| Indonésie | [BSSN](https://www.bssn.go.id) | RENS | web, bot | `[ID]` |
| Iran | [Maher / CERT.ir](https://cert.ir) | RENS | web, géo | `[FA]` ; voir §17 |
| Islande | [CERT-IS](https://www.cert.is) | RENS | web | `[IS/EN]` |
| Israël | [INCD](https://www.gov.il/en/departments/israel_national_cyber_directorate) | RENS | web, bot | `[HE/EN]` |
| Japon | [JPCERT/CC](https://github.com/JPCERTCC) · [blog « Eyes »](https://blogs.jpcert.or.jp/en/) · [JSAC](https://jsac.jpcert.or.jp/) | IOC+RENS | repo / Atom | phishurl-list, YARA, LogonTracer ; hash dans les billets `[JP/EN]` |
| Japon | [NCO](https://www.cyber.go.jp/) · [IPA 10大脅威](https://www.ipa.go.jp/security/10threats/) | RENS | web/PDF | NCO = ex-NISC `[JP]` |
| Japon | [フィッシング対策協議会](https://www.antiphishing.jp/) | RENS | Atom | alertes phishing quasi quotidiennes ; URL présentes dans les alertes mais non extraites par la sonde (IOC non vérifiés) `[JP]` |
| Jordanie | [NCSC-JO](https://ncsc.jo) | RENS | web | `[AR/EN]` |
| Kazakhstan | [KZ-CERT](https://cert.gov.kz) | RENS | web | `[KK/RU/EN]` |
| Kenya | [National KE-CIRT/CC](https://ke-cirt.go.ke) | RENS | web | |
| Macédoine du Nord | [MKD-CIRT](https://mkd-cirt.mk) | RENS | web | `[MK/EN]` |
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
| [IC3](https://www.ic3.gov/) · [ODNI](https://www.dni.gov/) | US | RENS | web, bot | rapports annuels |
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
| [MS-ISAC (CIS)](https://www.cisecurity.org/ms-isac) | US | collectivités | RENS | web | |
| [WaterISAC](https://www.waterisac.org/) | US | eau | RENS | RSS | |
| [RH-ISAC](https://rhisac.org/) | US | retail | RENS | RSS | |
| [Aviation ISAC](https://www.a-isac.com/) · [Auto-ISAC](https://automotiveisac.com/) | US | aviation, automobile | RENS | web | |
| [EE-ISAC](https://www.eeisac.eu/) · [ER-ISAC](https://er-isac.eu/) | EU | énergie, rail | RENS | web, bot | |
| [Cyber Threat Alliance](https://www.cyberthreatalliance.org/resources/) | US | multi | RENS | web | rapports conjoints ; ses communiqués listent les membres |
| [ECSO](https://www.ecso.org/) | EU | multi | RENS | RSS | |
| [Kaspersky ICS-CERT](https://ics-cert.kaspersky.com) | RU | OT | RENS | web | IOC en PDF, non vérifiés ; voir aussi §7.2 |

## 6. Infrastructure Internet : registres, RIR, NREN, cloud, opérateurs

*Biais : vision réseau que personne d'autre n'a ; conflit d'intérêt évident sur l'abus qu'ils hébergent ou enregistrent.*

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [ICANN DAAR](https://www.icann.org/octo-ssr/daar) | US | RENS | PDF | mesure mensuelle de l'abus par TLD |
| [NetBeacon Institute](https://netbeacon.org/) | US | RENS | RSS | ex-DNS Abuse Institute |
| [AFNIC — Observatoire](https://www.afnic.fr/observatoire-ressources/) | FR | RENS | RSS | abus du .fr |
| [SIDN Labs](https://www.sidnlabs.nl/en/news-and-blogs) | NL | RENS | web | recherche DNS/abus .nl |
| [Nominet](https://nominet.uk/news/) | UK | RENS | web | suspensions .uk |
| [SWITCH-CERT](https://www.switch.ch/en/cert) | CH | RENS | web | abus .ch, universités |
| [TWNIC](https://twnic.tw/blog/) | TW | RENS | web | `[ZH]` |
| [RNIDS](https://www.rnids.rs/) · [NIX.CZ](https://nix.cz/) | RS/CZ | RENS | web | registre .rs, IXP tchèque |
| [Nameshield](https://blog.nameshield.com/fr/) | FR | RENS | RSS | registrar : typosquatting |
| [RIPE Labs](https://labs.ripe.net/) | NL | RENS | RSS | hijacks BGP, mesures |
| [APNIC Blog](https://blog.apnic.net/) | AU | RENS | RSS | |
| [LACNIC CSIRT](https://www.lacnic.net/csirt) | UY | RENS | web | `[ES/EN]` |
| [CERN CERT](https://security.web.cern.ch/) · [EGI CSIRT](https://csirt.egi.eu/) · [SURFcert](https://www.surf.nl/en/services/security/surfcert) · [REN-ISAC](https://www.ren-isac.net/) | CH/EU/NL/US | RENS | web / RSS | NREN et grille |
| [Cloudflare — security](https://blog.cloudflare.com/tag/security/) · [Radar](https://radar.cloudflare.com) | US | RENS | RSS / bot | DDoS, botnets |
| [Akamai — security research](https://www.akamai.com/blog/security-research) | US | RENS | web, bot | IOC non vérifiés |
| [Fastly — security](https://www.fastly.com/blog/category/security) | US | RENS | RSS | |
| [AWS Security Blog](https://aws.amazon.com/blogs/security/) | US | RENS | RSS | honeypot MadPot, takedowns |
| [Telefónica Tech](https://telefonicatech.com/en/blog) | ES | RENS | web | |
| [CERT Orange Polska](https://cert.orange.pl) | PL | RENS | RSS | alertes ; la blocklist CyberTarcza n'est pas publiée `[PL]` |
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
| [Zscaler ThreatLabz](https://github.com/ThreatLabz/iocs) | IOC | repo | vivant | |
| [Sophos](https://github.com/sophoslabs/IoCs) | IOC | repo | vivant | blog bloque les robots ; absorbe Secureworks CTU |
| [Broadcom / Symantec Threat Hunter](https://www.security.com/threat-intelligence) · [protection bulletins](https://www.broadcom.com/support/security-center/protection-bulletin) | IOC+RENS | RSS / web | vivant | |
| [Trend Micro Research](https://www.trendmicro.com/en_us/research.html) | IOC+RENS | web (IOC en PDF) | vivant | dépôt GitHub figé 2024-11 |
| [Fortinet FortiGuard Labs](https://www.fortinet.com/blog/threat-research) | IOC+RENS | web | vivant | |
| [Proofpoint Threat Insight](https://www.proofpoint.com/us/blog/threat-insight) | IOC+RENS | web | vivant | |
| [Recorded Future / Insikt](https://www.recordedfuture.com/research) · [The Record](https://therecord.media/) | RENS | web | vivant | dépôt `Insikt-Group/Research` figé 2023 |
| [CrowdStrike](https://www.crowdstrike.com/en-us/blog/) · [rapports](https://www.crowdstrike.com/en-us/resources/reports/) | RENS | web/PDF | vivant | |
| [Elastic Security Labs](https://www.elastic.co/security-labs) · [labs-releases](https://github.com/elastic/labs-releases) | IOC+RENS | web / repo | 2026-09-01 | |
| [Netskope Threat Labs](https://www.netskope.com/blog) · [IOCs](https://github.com/netskopeoss/NetskopeThreatLabsIOCs) | IOC+RENS | RSS / repo | 2026-09-01 | abus de services cloud |
| [Huntress](https://www.huntress.com/blog) · [threat-intel](https://github.com/huntresslabs/threat-intel) | IOC+RENS | web / repo | 2026-08-19 | télémétrie MDR PME |
| [Wiz Research](https://www.wiz.io/blog/tag/research) · [IOCs](https://github.com/wiz-sec-public/wiz-research-iocs) | IOC+RENS | web / repo | 2026-08-06 | cloud |
| [Datadog Security Labs](https://securitylabs.datadoghq.com) · [malicious-software-packages-dataset](https://github.com/datadog/malicious-software-packages-dataset) | IOC+RENS | repo | 2026-08-31 | supply chain PyPI/npm, quotidien |
| [Infoblox](https://github.com/infobloxopen/threat-intelligence) | IOC+RENS | repo | vivant | DNS |
| [Cybereason](https://www.cybereason.com/blog) · [Rapid7](https://www.rapid7.com/blog/) · [Arctic Wolf](https://arcticwolf.com/resources/blog/) | IOC+RENS | RSS | vivant | IOC dans les billets (Cybereason : défangés) |
| [ReliaQuest](https://reliaquest.com/blog/) · [Varonis](https://www.varonis.com/blog/tag/threat-research) · [Uptycs](https://www.uptycs.com/blog) · [Morphisec](https://www.morphisec.com/blog/) | RENS | RSS | vivant | |
| [Malwarebytes Labs](https://www.malwarebytes.com/blog/category/threat-intel) · [eSentire TRU](https://www.esentire.com/resources/blog) · [Deep Instinct](https://www.deepinstinct.com/blog) · [Aqua Nautilus](https://www.aquasec.com/blog/) · [Sucuri](https://blog.sucuri.net/) | IOC+RENS | web / RSS | vivant | Sucuri : web/CMS (IP) |
| [Red Canary](https://redcanary.com/resources-center/category/blog/) | RENS | RSS | vivant | techniques, pas d'IOC |
| [LevelBlue SpiderLabs](https://www.levelblue.com/blogs/spiderlabs-blog) | IOC+RENS | RSS | vivant | ex-Trustwave |
| [Intel 471](https://www.intel471.com/blog) | IOC+RENS | RSS | vivant | underground ; 17 SHA-256 sur 30 billets (sonde 2026-09-02) |
| [Flashpoint](https://flashpoint.io/blog/) · [Cyware](https://www.cyware.com/resources/threat-briefings) | RENS | web | vivant | underground |
| [Trinity Cyber](https://www.trinitycyber.com/blog) | IOC+RENS | RSS | vivant | membre CTA ; hash dans les billets |
| [SonicWall Capture Labs](https://www.sonicwall.com/blog) · [WatchGuard Threat Lab](https://www.watchguard.com/wgrd-news/blog) · [ExtraHop](https://www.extrahop.com/blog) · [SecurityScorecard](https://securityscorecard.com/resources/research/) | RENS | web / RSS | vivant | membres CTA |
| [Aryaka](https://www.aryaka.com/blog/) | RENS | web | vivant | Transparent Tribe / APT36 |
| [Trellix ARC](https://www.trellix.com/blogs/research/) | RENS | web, bot | — | dépôt IOC figé 2021 |

**Europe (hors Russie)**

| Source | Pays | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|---|
| [ESET — WeLiveSecurity](https://www.welivesecurity.com) · [malware-ioc](https://github.com/eset/malware-ioc) | SK | IOC+RENS | web / repo | vivant | |
| [Gen Digital / Avast Threat Labs](https://www.gendigital.com/blog/insights) · [ioc](https://github.com/avast/ioc) | CZ | IOC+RENS | RSS / repo | 2026-06-01 | |
| [Bitdefender](https://github.com/bitdefender/malware-ioc) | RO | IOC | repo | vivant | |
| [WithSecure Labs](https://www.withsecure.com/en/resources-hub/w-labs/) · [iocs](https://github.com/WithSecureLabs/iocs) | FI | IOC+RENS | web / repo | 2026-08-27 | ex-F-Secure |
| [Sekoia.io](https://blog.sekoia.io) · [Community](https://github.com/SEKOIA-IO/Community) | FR | IOC+RENS | web / repo | 2026-08-24 | IOC + Sigma dans le dépôt |
| [HarfangLab](https://github.com/HarfangLab/iocs) | FR | IOC | repo | vivant | |
| [TEHTRIS](https://tehtris.com/en/blog/) | FR | IOC+RENS | web | vivant | honeypots mondiaux ; hash dans les billets |
| [Intrinsec](https://www.intrinsec.com/blog/) | FR | RENS | RSS | vivant | infra ransomware, bulletproof hosting ; IOC en PDF, non vérifiés |
| [OWN Security](https://www.own.security/ressources) · [Wavestone RiskInsight](https://www.riskinsight-wavestone.com/) · [Synetis](https://www.synetis.com/blog/) · [SysDream](https://sysdream.com/propos/blog/) | FR | RENS | web / RSS | vivant | |
| [Check Point Research](https://research.checkpoint.com) · [TI reports](https://research.checkpoint.com/category/threat-intelligence-reports/) | IL | IOC+RENS | web | vivant | absorbe Avanan |
| [Sygnia](https://www.sygnia.co/blog/) | IL | IOC+RENS | RSS | vivant | IOC ponctuels |
| [ClearSky](https://www.clearskysec.com/blog/) · [KELA](https://www.kelacyber.com/blog/) · [IRONSCALES](https://ironscales.com/blog) | IL | RENS | web / RSS | vivant | ClearSky : site JS, IOC non vérifiés |
| [G DATA](https://blog.gdatasoftware.com) | DE | IOC+RENS | web | vivant | hash dans les billets |
| [HiSolutions Research](https://research.hisolutions.com/) · [DCSO CyTec](https://blog.dcso.de) | DE | RENS | RSS / — | vivant | DCSO injoignable lors de la vérification |
| [Kaspersky — Securelist](https://securelist.com) | RU/CH | IOC+RENS | web | vivant | GReAT ; MD5 et indicateurs défangés en fin de rapport |
| [Certego](https://www.certego.net/blog/) · [Cleafy](https://www.cleafy.com/labs) | IT | IOC+RENS | RSS / web | vivant | Cleafy : IOC ponctuels `[IT/EN]` |
| [Yoroi Z-Lab](https://yoroi.company/research/) · [Yarix](https://www.yarix.com/en) · [HWG Sababa](https://www.hwgsababa.com/blog/) · [Tinexta Cyber](https://www.tinextacyber.com/) · [Telsy](https://www.telsy.com/en/blog/) | IT | RENS | web / bot | vivant | Yoroi : IOC non vérifiés (site JS) ; Telsy bloque les robots `[IT/EN]` |
| [Maltiverse](https://maltiverse.com) | ES | IOC | API, inscr. | vivant | plateforme IOC ouverte |
| [Lab52 / S2 Grupo](https://lab52.io) · [Mnemo](https://mnemo.com/blog-ciberseguridad/) · [Versia](https://www.versia.com/blog) · [Aiuken](https://www.aiuken.com/blog) · [S21sec](https://www.s21sec.com/blog/) | ES | RENS | web / RSS | vivant | Lab52 : IOC non vérifiés (site JS) `[ES/EN]` |
| [Fox-IT](https://blog.fox-it.com/) · [ThreatFabric](https://www.threatfabric.com/blogs) | NL | IOC+RENS | RSS | vivant | centaines de hash dans les billets |
| [NCC Group](https://www.nccgroup.com/research/) · [Northwave](https://northwave-cybersecurity.com/threat-intel-research) · [Tesorion](https://www.tesorion.nl/en) | UK/NL | RENS | web | vivant | NCC bloque les robots |
| [NVISO Labs](https://blog.nviso.eu/) | BE | IOC+RENS | RSS | vivant | hash dans le flux |
| [Truesec](https://www.truesec.com/hub/blog) · [Conscia](https://conscia.com/blog/) · [mnemonic](https://www.mnemonic.io/resources/blog/) | SE/DK/NO | RENS | web | vivant | mnemonic bloque les robots |
| [Nord Security](https://nordsecurity.com/blog) · [NRD Cyber Security](https://www.nrdcs.lt/) | LT | RENS | web | vivant | |
| [CERT Polska — voir §3](https://cert.pl) · [ComCERT](https://www.comcert.pl/aktualnosci/) · [RedTeam.pl](https://blog.redteam.pl/) | PL | RENS | RSS | vivant | `[PL]` |
| [Safetech](https://safetech.ro/blog/) · [Bit Sentinel](https://bit-sentinel.com/blog/) · [certSIGN](https://www.certsign.ro/ro/) | RO | RENS | RSS | vivant | `[RO/EN]` |
| [CrySyS Lab](https://blog.crysys.hu/) | HU | RENS | RSS | vivant | académique, APT Europe centrale |
| [Obrela](https://www.obrela.com/resources/blog) | GR | RENS | RSS | vivant | |
| [Oneconsult](https://oneconsult.com/en/blog/) · [Acronis TRU](https://www.acronis.com/en/tru/) | CH | IOC+RENS | RSS | vivant | hash dans les billets |
| [Open Systems](https://www.open-systems.com/blog/) · [Threatray](https://www.threatray.com) | CH | RENS | web | vivant | |
| [Brandefense](https://brandefense.io/blog/) · [SOCRadar](https://socradar.io/blog/) · [Barikat](https://www.barikat.com.tr/blog) | TR | RENS | web | vivant | `[TR/EN]` |
| [Orange Cyberdefense](https://www.orangecyberdefense.com/global/blog) | FR | RENS | web, bot | — | Security Navigator |

**Russie**

| Source | Contenu | Accès | Commentaire |
|---|---|---|---|
| [BI.ZONE](https://bi.zone) · [bizone-ti-lib](https://github.com/bi-zone/bizone-ti-lib) | RENS | web / repo (lib) | groupe Sber ; IOC non vérifiés `[EN/RU]` |
| [Positive Technologies](https://github.com/PositiveTechnologies) · [AttackDetection](https://github.com/ptresearch/AttackDetection) | RENS | repo (Suricata figé 2022), site bot | `[EN/RU]` |
| [Doctor Web](https://news.drweb.com) | IOC+RENS | web | indicateurs défangés dans les analyses `[RU/EN]` |
| [F6](https://www.f6.ru) · [Solar 4RAYS](https://solar4rays.ru) · [Solar analytics](https://rt-solar.ru/analytics/reports/) · [Security Vision](https://www.securityvision.ru/blog/) · [Infosecurity/Softline](https://www.infosec.ru/glavnye-temy/) | RENS | web, géo | F6 et Solar injoignables au robot : IOC non vérifiés `[RU]` |
| [Group-IB](https://www.group-ib.com/blog/) | IOC+RENS | web | siège Singapour ; hash et IP dans les billets `[EN]` |

**Chine**

| Source | Contenu | Accès | Commentaire |
|---|---|---|---|
| [QiAnXin / 奇安信](https://ti.qianxin.com) · [RedDrip7](https://github.com/RedDrip7) | IOC+RENS | web (bot) / repo | IOC via le dépôt `APT_Digital_Weapon` `[ZH]` |
| [360 高级威胁研究院 / 威胁情报中心](https://ti.360.net) | RENS | web | hebdo « 每周高级威胁情报解读 », nommage APT-C-xx ; remplace 360 Netlab (inactif) `[ZH]` |
| [Antiy / 安天](https://www.antiy.net) · [DBAPPSecurity / 安恒](https://ti.dbappsecurity.com.cn/blog/) | IOC+RENS | web / RSS | hash dans les rapports `[ZH]` |
| [NSFOCUS / 绿盟](https://nsfocusglobal.com/blog/) · [Knownsec 404](https://paper.seebug.org) · [Sangfor / 深信服](https://www.sangfor.com.cn/security-tech) · [Tencent 御见](https://tix.qq.com) · [ThreatBook / 微步](https://threatbook.io) | RENS | web, parfois géo | IOC non vérifiés (sites JS ou filtrés ; ThreatBook : lookups, pas de liste) `[ZH]` |
| [火绒 Huorong](https://www.huorong.cn/info/) · [瑞星 Rising](https://www.rising.com.cn/) | RENS | web | `[ZH]` |
| [CVERC](https://www.cverc.org.cn) | RENS | web | contre-attribution officielle `[ZH]` |

**Japon, Corée, Taïwan**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [ITOCHU C&I](https://blog-en.itochuci.co.jp) · [Macnica](https://security.macnica.co.jp/) · [nao-sec](https://nao-sec.org) · [IIJ-SECT](https://sect.iij.ad.jp/) | JP | IOC+RENS | RSS / web | hash dans les billets (ITOCHU : ~200) `[JP/EN]` |
| [LAC WATCH](https://www.lac.co.jp/lacwatch/) · [MBSD](https://www.mbsd.jp/research/) · [NRI Secure](https://www.nri-secure.co.jp/blog) · [NEC](https://jpn.nec.com/cybersecurity/blog/) · [Hitachi HIRT](https://www.hitachi.com/en/hirt/) · [SecureBrain](https://www.securebrain.co.jp/top/) · [Cyber Defense Institute](https://www.cyberdefense.jp/) | JP | RENS | web | `[JP]` |
| [AhnLab ASEC](https://asec.ahnlab.com/en/) · [Genians](https://www.genians.co.kr/en/blog/threat_intelligence) · [NSHC ThreatRecon](https://threatrecon.nshc.net) · [EST Security / ESRC](https://blog.alyac.co.kr) | KR | IOC+RENS | RSS / web | MD5 et indicateurs défangés (Genians ~50 par lot d'articles) ; fort sur les APT nord-coréennes `[KO/EN]` |
| [ENKI WhiteHat](https://www.enki.co.kr/en/media-center/blog) · [S2W](https://s2w.inc/en/resource) · [Penta Security](https://www.pentasecurity.com/blog/) · [Cloudbric](https://www.cloudbric.com/blogs/) · [SANDS Lab](https://sandslab.io/) · [IGLOO](https://www.igloo.co.kr/) · [SK shieldus](https://www.skshieldus.com/) | KR | RENS | web / RSS ; IGLOO, SK shieldus : bot | ENKI, S2W : sites JS, IOC non vérifiés `[KO]` |
| [TeamT5](https://teamt5.org/en/) | TW | IOC+RENS | web | APT nexus-Chine ; hash dans les billets `[ZH/EN]` |
| [CyCraft](https://www.cycraft.com/blog) · [ZUSO](https://www.zuso.ai/blog) · [ISSDU](https://www.issdu.com.tw/en) · [TXOne](https://www.txone.com/resources/blog/) | TW | RENS | web | PSIRT QNAP/Synology/Zyxel/ASUS pour les campagnes NAS/routeurs `[ZH/EN]` |

**Inde, Asie du Sud-Est, Océanie**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [CloudSEK](https://www.cloudsek.com/blog) · [Cyble](https://cyble.com/blog/) · [CYFIRMA](https://www.cyfirma.com/research/) · [Seqrite](https://www.seqrite.com/blog/) | IN | IOC+RENS | web / RSS | hash et IP dans les billets |
| [K7 Labs](https://labs.k7computing.com) · [Sequretek](https://www.sequretek.com/resources/threat-advisory) · [FalconFeeds](https://falconfeeds.io) | IN | RENS | web | K7 : site JS, Sequretek : bot — IOC non vérifiés |
| [Ensign InfoSecurity](https://www.ensigninfosecurity.com/resources) · [Group-IB](https://www.group-ib.com/blog/) | SG | RENS | web | |
| [Red Piranha](https://redpiranha.net/news-events) · [CyberCX](https://cybercx.com.au/blog/) | AU | RENS | web | |

**Moyen-Orient et Afrique**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [CTM360](https://www.ctm360.com) | BH | RENS | web | Golfe ; parle d'IOC sans les publier |
| [Help AG](https://www.helpag.com) · [DTS Solution](https://www.dts-solution.com) | AE | RENS | RSS présent, blog 404 | à vérifier en navigateur |
| [LMPS](https://www.lmps-group.com/fr/blog/) · [Raiseguard](https://raiseguard.com/blog) | MA/TN | RENS | web | `[FR]` |
| [Serianu](https://www.serianu.com/) | KE | RENS | PDF | rapport annuel Afrique |

**Amérique latine**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [CronUp](https://www.cronup.com/blog/) | CL | RENS | web | IOC non vérifiés (site JS) `[ES]` |
| [Metabase Q — Ocelot](https://www.metabaseq.com) · [Scitum](https://www.scitum.com.mx/) · [SILIKN](https://www.silikn.com/) | MX | RENS | web / RSS | `[ES/EN]` |
| [ISH Tecnologia](https://ish.com.br/blog/) · [Tempest](https://www.tempest.com.br/blog) · [Apura](https://apura.io/) | BR | RENS | RSS / web | `[PT]` |
| [Base4](https://base4sec.com/insights/) · [INSSIDE](https://www.insside.net/blog-ciberseguridad-insside/) | AR | RENS | web / RSS | `[ES]` |
| [B-Secure](https://www.b-secure.co/blog) · [Datasec](https://datasec-soft.com/blog/) · [Cyberseg](https://www.cyberseg.com/blog) · [SISAP](https://www.sisap.com/) · [GBM](https://www.gbm.net/) · [Canvia](https://www.canvia.com/blog/) | CO/UY/GT/CR/PE | RENS | RSS / web | surtout du marketing ; CronUp et Metabase Q restent les vraies sources CTI `[ES]` |

### 7.2 Spécialisés, par thème

**ICS / OT**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [Dragos](https://www.dragos.com/blog) | US | RENS | RSS | rapports de groupes, Year in Review ; IOC réservés à WorldView |
| [Claroty Team82](https://claroty.com/team82) | US/IL | RENS | Atom (disclosures) | vulnérabilités |
| [Nozomi Networks Labs](https://www.nozominetworks.com/labs) | US/CH | RENS | web | |
| [Forescout Vedere Labs](https://www.forescout.com/research-labs/) | US | RENS | web, bot | |
| [TXOne Networks](https://www.txone.com/resources/blog/) | TW | RENS | web | |
| [Kaspersky ICS-CERT](https://ics-cert.kaspersky.com) | RU | IOC+RENS | web | |

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
| [Lookout Threat Lab](https://www.lookout.com/threat-intelligence) | US | RENS | web | vivant | surveillanceware ; IOC non vérifiés (site JS) |
| [Apple — Threat notifications](https://support.apple.com/en-us/102174) | US | RENS | web | vivant | spyware mercenaire |

**Sécurité mail et phishing**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [Proofpoint — voir 7.1] | US | IOC+RENS | web | hash dans les billets |
| [Cloudmark](https://www.cloudmark.com/en/blog) | US | RENS | web | |
| [Cofense](https://cofense.com/blog/) · [Abnormal](https://abnormal.ai/blog) · [Barracuda](https://blog.barracuda.com/) · [INKY](https://www.inky.com/en/blog) · [KnowBe4](https://blog.knowbe4.com/) · [Validity](https://www.validity.com/blog/) · [Mailgun](https://www.mailgun.com/blog/) · [Data443 / Cyren](https://data443.com/cyren-threat-intelligence/) | US | RENS | web / RSS | aucun hash/IP dans les billets ; KnowBe4 absorbe Egress ; Data443 a repris Cyren |
| [Mimecast](https://www.mimecast.com/blog/) | UK | RENS | web | |
| [Hornetsecurity](https://www.hornetsecurity.com/en/blog/) · [Retarus](https://www.retarus.com/blog/en/) | DE | RENS | web / RSS | Hornetsecurity absorbe Vade |
| [Libraesva](https://www.libraesva.com/blog) | IT | RENS | web | |
| [Fortra (Agari, PhishLabs)](https://www.fortra.com/) | US | RENS | bot | rapports phishing de référence |
| [Netcraft](https://www.netcraft.com/resources/blog) | UK | RENS | web | |
| [Abusix](https://abusix.com/blog/) | DE | RENS | RSS | |

**Infrastructure, C2, pDNS, scans**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [Silent Push](https://www.silentpush.com/blog/) · [Validin](https://www.validin.com/blog/) · [Hunt.io](https://hunt.io/blog) · [Team Cymru](https://www.team-cymru.com/blog) | US | IOC+RENS | RSS / web ; feeds payants | IP et hash en clair dans les billets (Hunt.io : >100) |
| [DomainTools](https://www.domaintools.com/blog) | US | IOC+RENS | RSS | ~76 domaines défangés sur 30 billets (sonde 2026-09-02) |
| [Spur](https://spur.us/blog) | US | RENS | web | bloque les robots |
| [Censys](https://censys.com/resources/blog/) · [GreyNoise](https://www.greynoise.io/blog) | US | IOC+RENS | RSS / web / API | Censys : hash dans le flux ; GreyNoise : IP |
| [Bitsight](https://www.bitsight.com/blog) | US | RENS | RSS | |
| [drb-ra C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds) · [Xanderux C2watcher](https://github.com/Xanderux/C2watcher) · [ViriBack](https://tracker.viriback.com) · [CyberCrime Tracker](https://cybercrime-tracker.net) | — | IOC | repo / feed | trackers C2 ; `montysecurity/C2-Tracker` archivé avril 2026 |
| [Bambenek](https://osint.bambenekconsulting.com) · [EcrimeLabs](https://ecrimelabs.net) | US/DK | IOC | sur demande | |
| [Critical Path Security](https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds) | US | IOC | repo (Zeek Intel) | 2026-09-01 |

**Vulnérabilités et exploitation**

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [CISA KEV](https://github.com/cisagov/kev-data) · [VulnCheck](https://www.vulncheck.com/blog) · [Rapid7 AttackerKB / DB](https://www.rapid7.com/db/) · [ZDI](https://www.zerodayinitiative.com/blog) · [Exploit-DB](https://www.exploit-db.com/) · [Vulners](https://vulners.com/) · [Wiz Vulnerability DB](https://www.wiz.io/vulnerability-database) | US | IOC+RENS | repo / Atom / RSS / web | |
| [Google Project Zero — 0days in the wild](https://github.com/googleprojectzero/0days-in-the-wild) | US | RENS | repo | 2026-08-10 |
| [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) | — | IOC | repo | 2026-09-01 |
| [DEVCORE / Orange Tsai](https://blog.orange.tw/) | TW | RENS | Atom | recherche offensive |

**Crypto / Web3** — voir §2.3.

## 8. Réponse à incident, conseil, assurance

*Biais : échantillon limité à leurs clients et leurs sinistres ; excellents sur les TTP réels, rares sur les IOC.*

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [The DFIR Report](https://thedfirreport.com) · [Sigma](https://github.com/The-DFIR-Report/Sigma-Rules) | — | IOC+RENS | web / repo | rapports d'intrusion détaillés ; hash et IP en clair |
| [Kroll Cyber](https://www.kroll.com/en/insights/cyber) · [S-RM](https://www.s-rminform.com/cyber-intelligence-briefing) · [PwC TI](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence.html) | US/UK | RENS | web / RSS | |
| [GuidePoint GRIT](https://www.guidepointsecurity.com/blog/) | US | IOC+RENS | RSS | 11 SHA-256 + 66 domaines défangés sur 12 billets (sonde 2026-09-02) |
| [Coveware](https://coveware.com/ransomware-blog/) · [Halcyon](https://www.halcyon.ai/blog) | US | RENS | RSS / web | négociation et rapports ransomware |
| [Coalition](https://www.coalitioninc.com/blog) | US | RENS | web | assureur |
| [Cyber Threat Alliance — voir §5] · [Virus Bulletin](https://www.virusbulletin.com/virusbulletin/) · [Botconf](https://www.botconf.eu/) · [FIRST papers](https://www.first.org/resources/papers/) · [JSAC — voir §3] | — | RENS | web / RSS | actes de conférence |

## 9. Recherche académique et datasets

*Biais : rigueur, mais latence ; peu d'observables frais.*

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [Canadian Institute for Cybersecurity (UNB)](https://www.unb.ca/cic/datasets/) | CA | — | datasets | IDS, malware Android, DoH |
| [CAIDA](https://www.caida.org/catalog/datasets/) | US | — | datasets, partiellement sur demande | télescope réseau |
| [Citizen Lab](https://github.com/citizenlab) | CA | IOC+RENS | repo | voir §7.2 mobile |
| [Stratosphere — voir §2.1] · [UNSW Canberra](https://research.unsw.edu.au/projects/toniot-datasets) · [SecRepo](https://secrepo.com) · [theZoo](https://github.com/ytisf/theZoo) · [VirusShare](https://virusshare.com) | CZ/AU/— | — | datasets | |
| [DARPA OpTC](https://github.com/FiveDirections/OpTC-data) · [IMPACT Cyber Trust](https://www.impactcybertrust.org) · [Los Alamos](https://csr.lanl.gov/data/) | US | — | datasets | |
| [Malpedia — voir §1] · [Honeynet Project — voir §2.1] | | | | |
| [CrySyS Lab](https://blog.crysys.hu/) | HU | RENS | RSS | |
| [mdecrevoisier — EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | — | — | repo | EVTX mappés ATT&CK |
| [CTID Attack Flow](https://github.com/center-for-threat-informed-defense/attack-flow) | US | RENS | repo | 2026-08-13 |

## 10. Cybercriminalité : trackers, sites de fuite, victimologie

*Biais : **observables adverses**. Les revendications d'attaquants sont gonflées, recyclent de vieilles fuites, inventent des victimes. À collecter, jamais à promouvoir en indicateur sans recoupement.*

| Source | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|
| [Ransomware.live](https://www.ransomware.live/api) | RENS | API (50 req/j gratuit) | vivant | victimes et groupes ; victimologie, pas d'IOC réseau |
| [RansomLook](https://www.ransomlook.io/) | RENS | RSS / API | vivant | leak sites, forums, Telegram ; open source ; victimologie, pas d'IOC réseau |
| [ransomwatch](https://ransomwatch.telemetry.ltd/) · [repo](https://github.com/joshhighet/ransomwatch) | RENS | repo (JSON) | 2026-03-03 | historique depuis 2021 |
| [ecrime.ch](https://ecrime.ch/) · [DarkFeed](https://app.darkfeed.io/mainpage) · [Hackmanac](https://hackmanac.com/) · [ransom-db](https://www.ransom-db.com/) | RENS | web | vivant | victimologie |
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
| [Bert-JanP — Open-Source-Threat-Intel-Feeds](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds) | IOC | repo | vivant | |
| [spydisec](https://github.com/spydisec/spydithreatintel) · [EndlessFractal](https://github.com/EndlessFractal/Threat-Intel-Feed) · [rodanmaharjan](https://github.com/rodanmaharjan/ThreatIntelligence) | IOC | repo | vivant / 2025-09 | agrégats |
| [Intezer — community-intelligence](https://github.com/intezer/community-intelligence) · [Meta — voir §7.1] · [GithubInfosec](https://github.com/GithubInfosec/latest-malware-IoC) | IOC | repo | vivant / mi-2025 | |
| [malware-traffic — indicators](https://github.com/malware-traffic/indicators) · [PRODAFT](https://github.com/prodaft) · [DigitalSide](https://osint.digitalside.it) | IOC | repo / feed | vivant ; DigitalSide ralenti | |
| [TweetFeed](https://tweetfeed.live) · [0xDanielLopez](https://github.com/0xDanielLopez) | IOC | web / repo | vivant | IOC partagés sur X ; phishunt, phishing_kits |
| [curated-intel](https://github.com/curated-intel) · [mthcht](https://github.com/mthcht) · [blackorbird — APT_REPORT](https://github.com/blackorbird/APT_REPORT) · [despacito420 — The-Feed](https://github.com/despacito420/The-Feed) | IOC+RENS | repo | vivant | listes par campagne, ThreatIntel-Reports |
| [APTnotes](https://github.com/aptnotes/data) · [CyberMonitor](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections) | RENS | repo | figés 2024 | archives |
| [vx-underground](https://vx-underground.org) | IOC+RENS | web, bot | vivant | |
| [gm7.org — 信息安全知识库](https://www.gm7.org) · [tanjiti — sec_profile](https://github.com/tanjiti/sec_profile) · [安全内参 secrss](https://www.secrss.com/articles?tag=APT) · [安全客](https://www.anquanke.com/) | RENS | RSS / repo / web | vivant | agrégateurs chinois `[ZH]` |
| [Habr — infosecurity](https://habr.com/ru/hubs/infosecurity/articles/) · [Xakep](https://xakep.ru/) | RENS | RSS | vivant | `[RU]` |
| [piyolog](https://piyolog.hatenadiary.jp/) | RENS | RSS | vivant | chronologies d'incidents japonais `[JP]` |
| [Midnight Slayer — start.me](https://start.me/p/wMPxqX/cyber-threat-intelligence) | RENS | web, bot | vivant | |
| [dragnet](https://github.com/dragnet-dev) · [Mr Looquer](https://iocfeed.mrlooquer.com) · [xxspell](https://gitlab.com/xxspell/ctifeeds) | IOC | repo / feed | annoncé / 2023 / 2024 | à surveiller ; peu ou pas maintenus |

## 12. Journalistes et médias spécialisés

*Biais : sensationnalisme et absence d'IOC ; mais premiers sur les victimes, les infrastructures nommées et les fuites.*

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [Krebs on Security](https://krebsonsecurity.com/) · [Zero Day (K. Zetter)](https://www.zetter-zeroday.com/) · [CyberScoop](https://cyberscoop.com/) · [SecurityWeek](https://www.securityweek.com/) · [Risky Business News](https://news.risky.biz/) · [The Record](https://therecord.media/) · [BleepingComputer](https://www.bleepingcomputer.com/news/security/) | US/AU | RENS | RSS ; BleepingComputer bot | |
| [ZATAZ](https://www.zataz.com/) · [LeMagIT](https://www.lemagit.fr/actualites/cybersecurite) · [Numerama Cyberguerre](https://www.numerama.com/cyberguerre/) | FR | RENS | RSS / web / bot | LeMagIT : suivi ransomware très fin |
| [Hispasec — una al día](https://unaaldia.hispasec.com/) | ES | RENS | RSS | `[ES]` |
| [Red Hot Cyber](https://www.redhotcyber.com/) | IT | RENS | RSS | `[IT]` |
| [heise Security](https://www.heise.de/security) | DE | RENS | RSS | `[DE]` |
| [Security NEXT](https://www.security-next.com/) | JP | RENS | web | `[JP]` |
| [보안뉴스 Boan News](https://www.boannews.com/) | KR | RENS | RSS | `[KO]` |
| [Bellingcat](https://www.bellingcat.com/) | NL | RENS | web | OSINT |

## 13. Ingérence numérique et abus de plateformes

*Biais : les plateformes ne publient que ce qui les valorise.*

| Source | Contenu | Accès | Commentaire |
|---|---|---|---|
| [VIGINUM — voir §3] · [EU DisinfoLab](https://www.disinfo.eu/) · [DFRLab](https://dfrlab.org/) · [Graphika](https://www.graphika.com/reports) | RENS | RSS / web | FIMI |
| [Microsoft On the Issues (MTAC)](https://blogs.microsoft.com/on-the-issues/) | RENS | RSS | Digital Defense Report |
| [Meta — newsroom](https://about.fb.com/news/) | RENS | RSS (filtrer « adversarial threat ») | rapports trimestriels |
| [Google TAG / GTIG](https://blog.google/security/) | RENS | web | bulletins |
| [TikTok — covert influence operations](https://www.tiktok.com/safety/en/transparency/covert-influence-operations) | RENS | web | |
| [OpenAI — Disrupting malicious uses of AI](https://openai.com/global-affairs/disrupting-malicious-uses-of-ai/) · [Anthropic](https://www.anthropic.com/news/detecting-countering-misuse-aug-2025) | RENS | bot / web | abus des LLM par des acteurs étatiques |

## 14. Bases d'incidents, think tanks et rapports de référence

*Biais : politiques ou commerciaux ; utiles pour le contexte et les tendances, jamais pour les observables.*

| Source | Pays | Contenu | Accès | Commentaire |
|---|---|---|---|---|
| [EuRepoC](https://eurepoc.eu) | DE | RENS | RSS / exports | base codée d'incidents politiquement pertinents |
| [CFR Cyber Operations Tracker](https://www.cfr.org/cyber-operations/) · [CSIS Significant Cyber Incidents](https://www.csis.org/programs/strategic-technologies-program/significant-cyber-incidents) · [DCID](https://dcid.online/) · [CyberPeace Institute](https://cyberconflicts.protect.ngo/) | US/CH | RENS | web / RSS | |
| [RAND](https://www.rand.org/topics/cyber-warfare.html) · [Atlantic Council Cyber Statecraft](https://www.atlanticcouncil.org/programs/cyber-statecraft-initiative/) · [Carnegie](https://carnegieendowment.org/programs/technology-and-international-affairs) | US | RENS | RSS / web | |
| [Verizon DBIR](https://www.verizon.com/business/resources/reports/dbir/) · [IBM X-Force](https://www.ibm.com/reports/threat-intelligence) · [Picus Red Report](https://www.picussecurity.com/red-report) · [NETSCOUT](https://www.netscout.com/threatreport) · [CLUSIT](https://clusit.it/rapporto-clusit/) | — | RENS | PDF | rapports annuels |
| [NetManageIT — OpenCTI public](https://opencti.netmanageit.com) | — | IOC+RENS | web | hors ligne en 2026 |

## 15. Sandboxes et dépôts d'échantillons

*Biais : échantillons soumis par des tiers, donc bruités, parfois plantés.*

| Source | Contenu | Accès | Commentaire |
|---|---|---|---|
| [MalwareBazaar — voir §2.1] · [MalShare](https://malshare.com) · [VirusShare — voir §9] | IOC | API, inscr. | |
| [urlscan.io](https://urlscan.io/) · [Hybrid Analysis](https://hybrid-analysis.com/) · [Triage](https://tria.ge/) · [FileScan.io](https://www.filescan.io/) · [UnpacMe](https://www.unpac.me/) · [PolySwarm](https://polyswarm.io/) | IOC | web / API | comptes gratuits |
| [ANY.RUN](https://any.run/cybersecurity-blog/) · [Yomi](https://yomi.yoroi.company/) · [Threat.Zone](https://threat.zone/) · [OALabs](https://research.openanalysis.net/) | IOC+RENS | RSS / web | Threat.Zone : Turquie |
| [Joe Sandbox](https://www.joesandbox.com/) · [CAPE](https://capesandbox.com/) | IOC | bot | |

## 16. Règles de détection

| Source | Contenu | Accès | Activité | Commentaire |
|---|---|---|---|---|
| [SigmaHQ](https://github.com/SigmaHQ/sigma) · [elastic detection-rules](https://github.com/elastic/detection-rules) · [splunk security_content](https://github.com/splunk/security_content) · [chronicle detection-rules](https://github.com/chronicle/detection-rules) · [Sublime rules](https://github.com/Sublime-Security/sublime-rules) | IOC | repo | vivant | |
| [Neo23x0 signature-base](https://github.com/Neo23x0/signature-base) · [YARAHQ yara-forge](https://github.com/YARAHQ/yara-forge) · [Volexity](https://github.com/volexity/threat-intel) · [HarfangLab — voir §7.1] · [JPCERT yara — voir §3] | IOC | repo | vivant | |
| [RussianPanda — Yara-Rules](https://github.com/RussianPanda95/Yara-Rules) · [bartblaze](https://github.com/bartblaze/Yara-rules) · [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) | IOC | repo | 2026-08 / 2026-01 / 2025-11 | |
| [MISP warninglists](https://github.com/MISP/misp-warninglists) | IOC | repo | vivant | faux positifs ; y ajouter FireHOL level1 et la liste Tor |
| [RuleCheck.io Detections Digest](https://detections-digest.rulecheck.io) | RENS | newsletter | vivant | ctichef.com hors ligne |
| [Nuclei — voir §7.2] | | | | |

## 17. Angles morts

Constats après cinq passes de recherche (IOC, rapports, typologie, annuaires TI/M3AAWG/FIRST). Ces trous sont structurels, pas un défaut de recherche : la répartition des annuaires le montre.

| Zone / famille | Constat |
|---|---|
| **Golfe** | 18 membres FIRST (banques centrales, télécoms, autorités) : aucune publication technique ouverte ; Bahreïn et Koweït sur abonnement. |
| **Iran** | AFTA (`afta.gov.ir`), centres APA (`nsec.ir`, `cert.iut.ac.ir`), Padvish publient des IOC mais répondent 503 hors d'Iran ; 0 membre FIRST. |
| **Corée** | FSI, NCSC-KR, IGLOO, SK shieldus bloquent hors du pays — sources majeures sur les APT nord-coréennes. |
| **Asie du Sud / Sud-Est, Afrique subsaharienne** | une équipe FIRST par pays (le CERT national). |
| **Asie centrale / Caucase** | CERT.TJ seul flux ; TSARKA et CERT.AM injoignables. |
| **Adtech / anti-bot** (Confiant, HUMAN, DataDome, Imperva) | seule famille à voir le malvertising et les proxies résidentiels ; tous bloquent les robots. |
| **CERT bancaires et industriels** | présents dans TI/FIRST, ne publient pas ; observables réservés aux cercles fermés. |
| **États producteurs de contre-narratifs** (CVERC, NKTsKI, agences occidentales) | attribution miroir, IOC réels mêlés à des récits : recouper systématiquement. |
| **Telegram / Discord / Mastodon** | non explorables automatiquement ; couverts indirectement (§10). |

## 18. Sources écartées

Vérifiées et rejetées (dépôt figé > 18 mois, page morte, miroir, source absorbée). Ne pas réintroduire sans nouvelle vérification.

| Source | Raison |
|---|---|
| `mandiant/iocs`, `advanced-threat-research/IOCs` (Trellix), `Insikt-Group/Research`, `trendmicro/research`, `StrangerealIntel/*`, `swisscom/detections`, `Orange-Cyberdefense/russia-ukraine_IOCs`, `CryptoScamDB/blacklist`, `Yara-Rules/rules`, `InQuest/yara-rules-vt`, `KasperskyLab/klara`, `kbandla/APTnotes`, `0xToxin/Malware-IOCs`, `MalGamy/YARA_Rules`, `nshc-threatrecon/IoC-List`, `montysecurity/C2-Tracker` | figés ou archivés (2019–2024) |
| `executemalware/Malware-IOCs`, `ditekshen/detection`, `ThreatMon-Reports-IOC`, `pr0xylife/*` | activité déclinante (2024–2025) : surveiller |
| `elliotwutingfeng/ThreatFox-IOC-*`, `URLhaus-IOC`, `Cyberfury101/deepdarkCTI` | miroirs |
| Secureworks CTU, CyberArk Labs, Vade, Egress, Avanan, Zix, Cyren | absorbés (Sophos, Palo Alto, Hornetsecurity, KnowBe4, Check Point, OpenText, Data443) |
| CSIS Security Group (DK), Stanford Internet Observatory, Cyber Defense Institute blog, `SlowMist/SlowMist-Hacked`, USOM `url-list.txt` | introuvables, fermés ou remplacés (USOM → API Swagger de siberguvenlik.gov.tr) |

## 19. Méthodologie et vérification

**Comment les sources ont été trouvées.** Cinq passes : (1) recherche par pays et langue, vérification par lot ; (2) rapports et référentiels d'acteurs ; (3) typologie de 20 familles de producteurs, chacune avec son biais, et fouille de la liste des membres de la Cyber Threat Alliance ; (4) JSON public Trusted Introducer (554 équipes) et communiqués M3AAWG ; (5) API publique FIRST (879 équipes). La fouille d'annuaires a rapporté plus que toutes les requêtes en langue locale réunies.

**Comment le tag `IOC` est attribué.** Sur preuve uniquement : dépôt/feed dont le contenu a été vu, ou sonde de crawl (accueil + 25–40 pages internes, texte visible seulement) / sonde RSS ayant extrait ≥ 3 SHA-256, ≥ 10 IP publiques ou des indicateurs défangés. Le nombre de mentions du mot « IOC » ne compte pas : SOCRadar (111 mentions, 0 hash) ou CTM360 (42, 0) restent `RENS`. Résultats détaillés par source : [`verification-IOC-2026-09-02.md`](verification-IOC-2026-09-02.md).

**Comment les liens sont vérifiés.** Statut HTTP + auto-découverte RSS/Atom pour les sites ; pour GitHub, date réelle du dernier commit lue sur `https://github.com/<org>/<repo>/commits.atom` (sans quota API). Seuil de rejet : 18 mois sans commit. Vérification hebdomadaire pour les URL, mensuelle pour le diff des annuaires TI et FIRST.

**Contribuer.** Une ligne = une source, avec Contenu (`IOC` / `RENS` / `IOC+RENS`), Accès (feed/repo/API/RSS/web/PDF/inscr./bot/géo), date d'activité vérifiée et un commentaire d'une ligne indiquant ce qu'elle apporte que les autres n'ont pas. Une source qui ne passe pas la vérification va en §18 avec sa raison.

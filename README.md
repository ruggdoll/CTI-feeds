# CTI-feeds
Liste de sources de renseignement concernant la menace d'origine cyber

> Dernière vérification des liens : 2026-08-30

## Sommaire
- [Indices de compromissions](#indices-de-compromissions)
- [Menace mobile](#menace-mobile)
- [Sources gouvernementales et étatiques](#sources-gouvernementales-et-étatiques)
- [Rapports, analyses, informations](#rapports-analyses-informations)
- [Règles de detection](#règles-de-detection)

# Indices de compromissions
NB : Cette liste complète les feeds/connecteurs par défaut des projets OpenCTI et MISP
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[abuse.ch](https://abuse.ch) — [URLhaus](https://urlhaus.abuse.ch), [MalwareBazaar](https://bazaar.abuse.ch), [ThreatFox](https://threatfox.abuse.ch), [Feodo Tracker](https://feodotracker.abuse.ch), [SSLBL](https://sslbl.abuse.ch) | LA référence OSS : URLs, échantillons, IOCs, C2, certificats ; API + exports CSV / JSON / MISP / Suricata |
|[AlienVault OTX](https://otx.alienvault.com) | pulses communautaires, très gros volume ; API gratuite |
|[APNIC Community Honeynet Project](https://feeds.honeynet.asia) | honeypots Asie-Pacifique ; les fichiers `latest` sont en fin de listing |
|[Azure Sentinel Public feed](https://github.com/Azure/Azure-Sentinel) | dépôt massif du SIEM Microsoft ; IOCs et règles dispersés, il faut fouiller |
|[Bambenekconsulting.com](https://osint.bambenekconsulting.com) | feeds OSINT (DGA, C2) ; accès sur demande, montrer patte blanche au préalable |
|[Bert-JanP Github](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds) | feeds OSS librement réutilisables (IP, URL, CVE, hash), très actif |
|[Bitdefender Github](https://github.com/bitdefender/malware-ioc)| IOCs des whitepapers Bitdefender, tenu à jour |
|[blocklist.de](https://www.blocklist.de) | IPs signalées via fail2ban par des serveurs participants (SSH, mail, web) |
|[Botvrij.eu](https://www.botvrij.eu) | IOCs OSINT au format MISP / CSV |
|[CERT Mumbai](https://github.com/MH-CERT)| org GitHub, repo `Indicator-of-Compromise-IOC-` ; activité faible |
|[CERT Thailand Telco](https://github.com/ttc-cert)| blocklist recommandée + règles Sigma/YARA + events MISP ; rien de neuf depuis 2024 |
|[CINS Score / CI Army](https://cinsscore.com) | liste d'IPs à mauvaise réputation (CINS Active Threat Intelligence), gratuite |
|[Cisco Talos Github](https://github.com/Cisco-Talos/IOCs)| IOCs des publications Talos |
|[CyberCrime Tracker](https://cybercrime-tracker.net) | panels C2 de malware (Pony, Loki, etc.) |
|[cyberfury101 Gitlab](https://gitlab.com/Cyberfury101/deepdarkCTI) | copie de `deepdarkCTI`, inactive depuis 2021 ; préférer le dépôt fastfire |
|[DigitalSide Threat-Intel](https://osint.digitalside.it) ([mirror GitHub](https://github.com/davidonzo/Threat-Intel)) | IOCs OSINT (STIX / CSV / MISP) ; rythme ralenti depuis fin 2024 |
|[dragnet Github](https://github.com/dragnet-dev) | projet récent : le moteur d'agrégation `dragnet` est public, mais le repo de sorties `haul` (IOCs/Sigma/STIX) annoncé n'est pas encore publié |
|[drb-ra Github](https://github.com/drb-ra/C2IntelFeeds) | orienté C2, mise à jour quotidienne, très actif |
|[EcrimeLabs](https://ecrimelabs.net) | feeds fournis sur demande, montrer patte blanche au préalable |
|[ESET Github](https://github.com/eset/malware-ioc/tree/master)| IOCs des investigations ESET ; mises à jour épisodiques mais fiables |
|[fastfire Github](https://github.com/fastfire/deepdarkCTI) | LA référence deep et darkweb, très actif |
|[FGRibreau Github](https://github.com/FGRibreau/mailchecker) | détection d'emails jetables ; voir `list.txt` |
|[InfoSec Github](https://github.com/GithubInfosec/latest-malware-IoC)| IoC/IoA d'investigations InfoSec ; peu actif (dernière MAJ mi-2025) |
|[Malshare.com](https://malshare.com) | plateforme d'échantillons + IOCs ; inscription gratuite / clé API |
|[malware-traffic Github](https://github.com/malware-traffic/indicators)| IOCs de malware-traffic-analysis.net, classés par année |
|[Mandiant Github](https://github.com/mandiant/iocs)| archivé, IOCs de 2019 ; valeur historique |
|[Meta Github](https://github.com/facebook/threat-research)| IOCs et indicateurs de détection, actif |
|[Mitre ATT&CK Github](https://github.com/mitre-attack/attack-stix-data) | données STIX du framework ATT&CK |
|[montysecurity Github](https://github.com/montysecurity) | voir `C2-Tracker` (archivé avril 2026, snapshot encore utile) et les connecteurs OpenCTI |
|[Mr Looquer IOCs Feed](https://iocfeed.mrlooquer.com) | feed IPv4/IPv6 (JSON & CSV) ; semble à l'arrêt (dernières données fin 2023) |
|[Onetracker](https://onetracker.org/ti)| annuaire de ressources : échantillons, PCAP, images forensic, feeds, blocklists |
|[OpenPhish](https://openphish.com) / [PhishTank](https://phishtank.org) | URLs de phishing ; feeds communautaires gratuits (versions publiques limitées) |
|[Palo Alto Github](https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information)| IOCs liés aux articles Unit 42, actif ; remplace l'ancien repo `pan-unit42/iocs` |
|[pan-unit42 Github](https://github.com/pan-unit42) | org Unit 42 ; `pan-unit42/iocs` désormais archivé, utiliser le repo Article-Information ci-dessus |
|[Phishing Army Feed](https://phishing.army) | blocklist de domaines liés au phishing (versions basic et extended) |
|[Prodaft Github](https://github.com/prodaft)| voir `malware-ioc` (IOCs d'investigations) et CRADLE (plateforme CTI) |
|[PulseDive](https://pulsedive.com) | plateforme CTI, plusieurs feeds ; compte gratuit disponible |
|[Ransomware.live Feeds](https://www.ransomware.live/api) | API victimes/groupes ransomware ; le plan gratuit permet 50 req/j |
|[RedDrip7 Github](https://github.com/RedDrip7)| voir `APT_Digital_Weapon` : IOCs APT catégorisés par QiAnXin, actif |
|[rodanmaharjan Github](https://github.com/rodanmaharjan/ThreatIntelligence)| blocklist IOC pour MISP / pare-feu ; dernière MAJ sept. 2025 |
|[SANS ISC / DShield](https://isc.sans.edu) | IPs de scan et d'attaque, blocklists quotidiennes ([feeds](https://www.dshield.org/howto.html)) ; très fiable |
|[Shadowserver](https://www.shadowserver.org/what-we-do/network-reporting/) | ONG ; rapports quotidiens gratuits pour votre ASN / plage IP (victimes, scans, C2) + [dashboard public](https://dashboard.shadowserver.org) |
|[sophoslabs Github](https://github.com/sophoslabs/IoCs)| IOCs issus des publications Sophos, actif |
|[Spamhaus DROP / EDROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | plages IP détournées ou contrôlées par des cybercriminels ; TXT / JSON |
|[spydisec Github](https://github.com/spydisec/spydithreatintel)| agrégat OSINT + blocklists communautaires, mise à jour quotidienne, très complet |
|[sroberts Github](https://github.com/sroberts/awesome-iocs)| liste curée de sources IOC |
|[stamparm Ipsum Github](https://github.com/stamparm/Ipsum) | feed quotidien d'IPs malveillantes avec score de fiabilité graduel |
|[Stop Forum Spam](https://www.stopforumspam.com/downloads) | listes d'IP / domaines / emails de spam de forum |
|[Threatfeeds.io](https://threatfeeds.io) | annuaire de feeds gratuits/OSS ; peu mis à jour depuis ~2019 |
|[ViriBack C2 Tracker](https://tracker.viriback.com) | panels C2 actifs (stealers, RAT) ; export CSV |
|[Xanderux Github](https://github.com/Xanderux/C2watcher) | feed C2 quotidien, actif |
|[xxspell Gitlab](https://gitlab.com/xxspell/ctifeeds)| instantané de janvier 2024, non maintenu depuis |
|[Zscaler Github](https://github.com/ThreatLabz/iocs)| IOCs des rapports Zscaler ThreatLabz, actif et dense |

# Menace mobile
Sources dédiées aux compromissions de smartphones (spyware mercenaire, stalkerware).
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[Amnesty International — investigations](https://github.com/AmnestyTech/investigations) | IOCs (STIX) des enquêtes du Security Lab : Pegasus, Predator/Cytrox, campagnes Android… ; dernière MAJ fin 2024 |
|[AssoEchap — stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | stalkerware Android : noms de paquets, C2, règles YARA et Suricata/Snort ; maintenu par Échap + Amnesty Security Lab, actif |
|[Citizen Lab — malware-indicators](https://github.com/citizenlab/malware-indicators) | IOCs des enquêtes Citizen Lab sur le spyware mercenaire (Pegasus, Predator, Candiru…) |
|[MVT Project — mvt-indicators](https://github.com/mvt-project/mvt-indicators) | index et collection d'IOCs (STIX) compatibles avec l'outil forensic [MVT](https://github.com/mvt-project/mvt) (iOS / Android), actif |

# Sources gouvernementales et étatiques
CERT / CSIRT nationaux et agences (UE, OTAN, Five Eyes et alliés). Beaucoup de ces sources publient leurs IOCs dans des avis web plutôt que dans des feeds structurés.
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|🇦🇺 [ACSC / ASD](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories) (Australie) | alertes et avis avec IOCs ; pas de dépôt public notable |
|🇧🇪 [CCB / CERT.be](https://cert.be) (Belgique) | avis de sécurité avec IOCs |
|🇨🇦 [CCCS / Cyber Centre](https://github.com/CybercentreCanada) (Canada) | AssemblyLine (analyse de malware), extracteurs de config, outils SOC ; avis sur [cyber.gc.ca](https://www.cyber.gc.ca/en/alerts-advisories) |
|🇨🇭 [GovCERT.ch](https://github.com/govcert-ch/CTI) (Suisse) | dépôt `CTI` (IOCs et notes d'analyse), actif |
|🇨🇿 [NÚKIB](https://nukib.gov.cz/en/) (Tchéquie) | alertes, avertissements et rapports |
|🇩🇪 [BSI / CERT-Bund](https://github.com/BSI-Bund) (Allemagne) | honeypot MADCAT, Secvisogram (CSAF) ; avis de vulnérabilité sur [wid.cert-bund.de](https://wid.cert-bund.de) |
|🇪🇪 [CERT-EE / RIA](https://github.com/cert-ee) (Estonie) | Cuckoo3, S4A detector et autres outils |
|🇪🇺 [CERT-EU](https://cert.europa.eu/publications/threat-intelligence) (institutions UE) | Threat Intelligence & security advisories ; [`droid`](https://github.com/certeu/droid) pour la gestion de règles Sigma |
|🇪🇺 [ENISA — EU CSIRTs Network (CNW)](https://github.com/enisaeu/CNW) | agrège les avis des CSIRT nationaux de l'UE + CERT-EU — meilleur point d'entrée UE |
|🇫🇷 [CERT-FR / ANSSI](https://www.cert.ssi.gouv.fr/ioc) (France) | feed IOCs officiel (+ MISP natif) ; outils DFIR sur [github.com/ANSSI-FR](https://github.com/ANSSI-FR) (DFIR-ORC, DFIR-OGRE) |
|🇫🇷 [VIGINUM](https://github.com/VIGINUM-FR/Rapports-Techniques) (France) | rapports techniques sur l'ingérence numérique étrangère (dernière MAJ sept. 2025) |
|🇮🇹 [CERT-AGID](https://cert-agid.gov.it) (Italie) | feed IOC quotidien (malware / phishing visant l'Italie) ; inscription requise |
|🇯🇵 [JPCERT/CC](https://github.com/JPCERTCC) (Japon) | `phishurl-list`, `jpcert-yara`, `Contagious-Interview-IoCs`, `CobaltStrike-Config`, LogonTracer, EmoCheck — production publique remarquable |
|🇱🇻 [CERT.LV](https://www.cert.lv/en/data-feed) (Lettonie) | data feed national (sinkhole, IPs et domaines compromis) |
|🇱🇺 [CIRCL](https://www.circl.lu/doc/misp/feed-osint/) (Luxembourg) | feed MISP OSINT ; éditeur de MISP, AIL, Passive DNS/SSL ([github.com/CIRCL](https://github.com/CIRCL)) |
|🇳🇱 [NCSC-NL](https://github.com/NCSC-NL) (Pays-Bas) | dépôts d'IOCs et scripts de scan par campagne (Citrix, MOVEit, Zimbra…) |
|🇳🇿 [NCSC-NZ](https://www.ncsc.govt.nz) (Nouvelle-Zélande) | avis et alertes (CERT NZ y a été intégré en 2024) |
|🇵🇱 [CERT Polska / CERT.pl](https://github.com/CERT-Polska) (Pologne) | mwdb, drakvuf-sandbox, karton, Artemis ; liste d'avertissement de domaines malveillants [hole.cert.pl](https://hole.cert.pl) |
|🇸🇪 [CERT-SE](https://www.cert.se) (Suède) | alertes et analyses |
|🇺🇸 [CISA](https://github.com/cisagov) (États-Unis) | liste `.gov`, catalogue [KEV](https://github.com/cisagov/kev-data), avis [CSAF](https://github.com/cisagov/CSAF) ; alertes & Malware Analysis Reports sur [cisa.gov](https://www.cisa.gov/news-events/cybersecurity-advisories) |
|🇺🇸 [CERT/CC (CMU SEI)](https://github.com/CERTCC) (États-Unis) | coordination de divulgation (VINCE, SSVC, Vultron), outils d'analyse binaire (pharos) |
|🇺🇸 [NSA Cybersecurity](https://github.com/nsacyber) (États-Unis) | guides de durcissement et de détection, configurations |
|🇬🇧 [NCSC-UK](https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports) (Royaume-Uni) | rapports de menace avec IOCs ; packs de config et Logging Made Easy sur [github.com/ukncsc](https://github.com/ukncsc) |

# Rapports, analyses, informations
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[APTnotes](https://github.com/aptnotes/data) | archive historique de rapports APT publics ; figée fin 2024 |
|[despacito420 Github](https://github.com/despacito420/The-Feed)| liste curée d'articles SOC/DFIR/CTI ; activité faible (dernière MAJ janv. 2026) |
|[devsecops Github](https://github.com/devsecops/awesome-devsecops) | liste d'outils DevSecOps (dont CTI) ; figée depuis 2024 |
|[EndlessFractal Github](https://github.com/EndlessFractal/Threat-Intel-Feed)| agrégation et consolidation automatiques de feeds, actif |
|[ETDA / ThaiCERT APT Encyclopedia](https://apt.etda.or.th) | fiches détaillées de groupes et d'outils APT |
|[hslatman Github](https://github.com/hslatman/awesome-threat-intelligence)| LA liste de référence des ressources CTI |
|[infoblox Github](https://github.com/infobloxopen/threat-intelligence) | IOCs et rapports Infoblox (threat intel DNS), actif |
|[Malpedia](https://malpedia.caad.fkie.fraunhofer.de) | familles de malware, règles YARA, références (Fraunhofer FKIE) ; compte gratuit |
|[mdecrevoisier Github](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | 270+ échantillons EVTX mappés ATT&CK, pour mesurer la couverture SIEM |
|[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/)| rapports et analyses (MSTIC) |
|[Midnight Slayer](https://start.me/p/wMPxqX/cyber-threat-intelligence)| tableau de bord start.me très riche ; bloque les robots, ouvrir dans un navigateur |
|[MITRE ATT&CK — Groups & Software](https://attack.mitre.org/groups/) | complément « lisible » des données STIX : fiches groupes et logiciels |
|[mthcht Github](https://github.com/mthcht) | voir `awesome-lists` (SOC/CERT/CTI) et `ThreatIntel-Reports`, très actif |
|[NetManageIT instance publique OpenCTI](https://opencti.netmanageit.com) | instance OpenCTI publique en lecture seule ; actuellement hors ligne (2026) |
|[ORKL](https://orkl.eu) | bibliothèque de rapports CTI / APT indexés et cherchables + API |
|[The DFIR Report](https://thedfirreport.com) | rapports d'intrusion détaillés (chronologie, IOCs, TTPs, règles Sigma) |
|[TweetFeed](https://tweetfeed.live) | IOCs partagés par la communauté infosec (ex-Twitter) ; voir aussi 0xDanielLopez |
|[vx-underground](https://vx-underground.org) | collections APT, échantillons, papers ; bloque les robots, ouvrir dans un navigateur |
|[0xDanielLopez Github](https://github.com/0xDanielLopez)| auteur de TweetFeed ; aussi `phishunt-feed` et `phishing_kits` |

# Règles de detection
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[chronicle detection-rules](https://github.com/chronicle/detection-rules) | règles YARA-L pour Google Security Operations |
|[CTI Chef → RuleCheck.io Detections Digest](https://detections-digest.rulecheck.io) | le site ctichef.com est hors ligne depuis début 2026 ; seule subsiste la newsletter de suivi des règles de détection |
|[elastic detection-rules](https://github.com/elastic/detection-rules) | règles de détection Elastic Security, très actif |
|[HarfangLab Github](https://github.com/HarfangLab/iocs)| IOCs publiés par l'EDR français HarfangLab |
|[InQuest awesome-yara](https://github.com/InQuest/awesome-yara) | liste curée de règles, outils et ressources YARA |
|[MISP warninglists](https://github.com/MISP/misp-warninglists) | listes pour écarter les faux positifs (CDN, cloud, bogons, top domains…) |
|[Neo23x0 signature-base](https://github.com/Neo23x0/signature-base) | base YARA + IOCs de Florian Roth (moteur de THOR / Loki) |
|[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | le dépôt canonique des règles Sigma |
|[splunk security_content](https://github.com/splunk/security_content) | détections et analytics Splunk (research.splunk.com) |
|[Sublime-Security rules](https://github.com/Sublime-Security/sublime-rules) | détection d'attaques par email (phishing, BEC, malware) |
|[The DFIR Report — Sigma Rules](https://github.com/The-DFIR-Report/Sigma-Rules) | règles Sigma issues d'investigations réelles |
|[Volexity Github](https://github.com/volexity/threat-intel) | signatures (YARA) et IOCs des billets de blog Volexity |
|[YARAHQ yara-forge](https://github.com/YARAHQ/yara-forge) | packs YARA consolidés et normalisés, publiés en releases |

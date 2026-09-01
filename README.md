# CTI-feeds
Liste de sources de renseignement concernant la menace d'origine cyber

> Dernière vérification des liens : 2026-09-01 (2e passe : ajouts multi-régions + Web3 + ICS/OT)
>
> Les sources ne sont pas restreintes à l'anglais. La langue est indiquée entre crochets — p. ex. `[ZH]`, `[RU]`, `[KO]` — lorsqu'elle n'est ni le français ni l'anglais ; la traduction automatique du navigateur suffit dans la plupart des cas.
>
> Aucune source n'est écartée en raison de son pays d'origine ou de son affiliation. Le recoupement des informations et la prise en compte du contexte propre à chaque source relèvent de l'analyste.

## Sommaire
- [Indices de compromissions](#indices-de-compromissions)
- [Menace mobile](#menace-mobile)
- [Sources gouvernementales et étatiques](#sources-gouvernementales-et-étatiques)
- [Éditeurs et laboratoires de recherche privés](#éditeurs-et-laboratoires-de-recherche-privés)
- [Sources académiques et datasets de recherche](#sources-académiques-et-datasets-de-recherche)
- [Rapports, analyses, informations](#rapports-analyses-informations)
- [Règles de detection](#règles-de-detection)

# Indices de compromissions
NB : Cette liste complète les feeds/connecteurs par défaut des projets OpenCTI et MISP
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[abuse.ch](https://abuse.ch) — [URLhaus](https://urlhaus.abuse.ch), [MalwareBazaar](https://bazaar.abuse.ch), [ThreatFox](https://threatfox.abuse.ch), [Feodo Tracker](https://feodotracker.abuse.ch), [SSLBL](https://sslbl.abuse.ch) | URLs, échantillons, IOCs, C2, certificats ; API + exports CSV / JSON / MISP / Suricata (hébergé par la Haute école spécialisée bernoise) |
|[AlienVault OTX](https://otx.alienvault.com) | pulses communautaires, très gros volume ; API gratuite |
|[APNIC Community Honeynet Project](https://feeds.honeynet.asia) | honeypots Asie-Pacifique ; les fichiers `latest` sont en fin de listing |
|[APTtrail Github](https://github.com/trilwu/apttrail) ([site](https://trilwu.github.io/apttrail)) | ~170k IOCs attribués par groupe APT (identifiants `Gxxxx` ATT&CK) ; formats MISP / STIX / Suricata / listes par type et par groupe ; rythme de mise à jour irrégulier |
|[Avast / Gen Digital Github](https://github.com/avast/ioc) | IOCs (+ YARA) des billets Avast/AVG/Norton, rangés par famille de malware |
|[Azure Sentinel Public feed](https://github.com/Azure/Azure-Sentinel) | dépôt massif du SIEM Microsoft ; IOCs et règles dispersés, il faut fouiller |
|[Bambenekconsulting.com](https://osint.bambenekconsulting.com) | feeds OSINT (DGA, C2) ; accès sur demande |
|[Binary Defense — banlist](https://www.binarydefense.com) | liste d'IPs à mauvaise réputation ([banlist.txt](https://www.binarydefense.com/banlist.txt)) |
|[BruteForceBlocker](https://danger.rulez.sk/index.php/bruteforceblocker/) | IPs de brute-force SSH signalées par des serveurs participants (danger.rulez.sk) |
|[Bert-JanP Github](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds) | feeds OSS librement réutilisables (IP, URL, CVE, hash), très actif |
|[Bitdefender Github](https://github.com/bitdefender/malware-ioc)| IOCs des whitepapers Bitdefender, tenu à jour |
|[blocklist.de](https://www.blocklist.de) | IPs signalées via fail2ban par des serveurs participants (SSH, mail, web) |
|[Botvrij.eu](https://www.botvrij.eu) | IOCs OSINT au format MISP / CSV |
|[CINS Score / CI Army](https://cinsscore.com) | liste d'IPs à mauvaise réputation (CINS Active Threat Intelligence), gratuite |
|[Cisco Talos Github](https://github.com/Cisco-Talos/IOCs)| IOCs des publications Talos |
|[Critical Path Security Github](https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds) | feeds quotidiens d'IPs / domaines au format Zeek Intelligence Framework |
|[CyberCrime Tracker](https://cybercrime-tracker.net) | panels C2 de malware (Pony, Loki, etc.) |
|[cyberfury101 Gitlab](https://gitlab.com/Cyberfury101/deepdarkCTI) | copie de `deepdarkCTI`, inactive depuis 2021 ; préférer le dépôt fastfire |
|[Datadog Security Labs Github](https://github.com/DataDog/malicious-software-packages-dataset) | corpus de paquets PyPI / npm malveillants (archives chiffrées + JSON), MAJ quotidienne — supply chain |
|[DigitalSide Threat-Intel](https://osint.digitalside.it) ([mirror GitHub](https://github.com/davidonzo/Threat-Intel)) | IOCs OSINT (STIX / CSV / MISP) ; rythme ralenti depuis fin 2024 |
|[dragnet Github](https://github.com/dragnet-dev) | moteur d'agrégation `dragnet` public ; le repo de sorties `haul` (IOCs/Sigma/STIX) annoncé n'est pas encore publié |
|[drb-ra Github](https://github.com/drb-ra/C2IntelFeeds) | orienté C2, mise à jour quotidienne, très actif |
|[EcrimeLabs](https://ecrimelabs.net) | feeds fournis sur demande |
|[Elastic Security Labs Github](https://github.com/elastic/labs-releases) | IOCs, YARA et extracteurs des articles [Elastic Security Labs](https://www.elastic.co/security-labs) ; actif (distinct de `elastic/detection-rules`) |
|[Emerging Threats — compromised IPs](https://rules.emergingthreats.net/blockrules/compromised-ips.txt) | liste d'IPs compromises, classique |
|[ESET Github](https://github.com/eset/malware-ioc/tree/master)| IOCs des investigations ESET ; mises à jour épisodiques |
|[fastfire Github](https://github.com/fastfire/deepdarkCTI) | collection deep et darkweb, très actif |
|[FGRibreau Github](https://github.com/FGRibreau/mailchecker) | détection d'emails jetables ; voir `list.txt` |
|[GreenSnow](https://greensnow.co) | IPs de brute-force et de scan ([greensnow.txt](https://blocklist.greensnow.co/greensnow.txt)) |
|[HaGeZi DNS Blocklists Github](https://github.com/hagezi/dns-blocklists) | liste `tif` (Threat Intelligence Feeds) : malware / phishing / C2 agrégés au format hosts / RPZ / ABP |
|[Huntress Labs Github](https://github.com/huntresslabs/threat-intel) | IOCs et YARA de la télémétrie MDR (intrusions PME, abus RMM), actif |
|[InfoSec Github](https://github.com/GithubInfosec/latest-malware-IoC)| IoC/IoA d'investigations InfoSec ; peu actif (dernière MAJ mi-2025) |
|[Intezer — community-intelligence Github](https://github.com/intezer/community-intelligence) | IOCs curés par campagne (APT et cybercrime), formats CSV / Markdown / TXT ; actif |
|[Inversion DNSBL (elliotwutingfeng) Github](https://github.com/elliotwutingfeng/Inversion-DNSBL-Blocklists) | URLs malveillantes issues du scan de sources publiques ; formats hosts / ABP |
|[Maltrail — trails statiques](https://github.com/stamparm/maltrail/tree/master/trails/static) | listes d'IOCs (C2, DGA, scanners) rangées par famille de malware ; même auteur qu'Ipsum |
|[Malshare.com](https://malshare.com) | plateforme d'échantillons + IOCs ; inscription gratuite / clé API |
|[malware-traffic Github](https://github.com/malware-traffic/indicators)| IOCs de malware-traffic-analysis.net, classés par année |
|[Mandiant Github](https://github.com/mandiant/iocs)| archivé, IOCs de 2019 ; recherche vivante sur le [blog Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence) |
|[MetaMask — eth-phishing-detect Github](https://github.com/MetaMask/eth-phishing-detect) | blocklist de domaines de phishing Web3 utilisée par le wallet MetaMask, très active `[crypto]` |
|[Meta Github](https://github.com/facebook/threat-research)| IOCs et indicateurs de détection, actif |
|[Netskope Threat Labs Github](https://github.com/netskopeoss/NetskopeThreatLabsIOCs) | IOCs par billet ([blog](https://www.netskope.com/blog)) ; angle abus de services cloud légitimes, très actif |
|[Mitre ATT&CK Github](https://github.com/mitre-attack/attack-stix-data) | données STIX du framework ATT&CK |
|[montysecurity Github](https://github.com/montysecurity) | voir `C2-Tracker` (archivé avril 2026) et les connecteurs OpenCTI |
|[Mr Looquer IOCs Feed](https://iocfeed.mrlooquer.com) | feed IPv4/IPv6 (JSON & CSV) ; dernières données fin 2023 |
|[Onetracker](https://onetracker.org/ti)| annuaire de ressources : échantillons, PCAP, images forensic, feeds, blocklists |
|[OpenPhish](https://openphish.com) / [PhishTank](https://phishtank.org) | URLs de phishing ; feeds communautaires gratuits (versions publiques limitées) |
|[Palo Alto Github](https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information)| IOCs liés aux articles Unit 42, actif ; remplace l'ancien repo `pan-unit42/iocs` |
|[Palo Alto — Unit42 timely-threat-intel Github](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel) | IOCs des posts courts X/LinkedIn d'Unit 42 (distinct du repo Article-Information), très actif |
|[pan-unit42 Github](https://github.com/pan-unit42) | org Unit 42 ; `pan-unit42/iocs` archivé, utiliser le repo Article-Information ci-dessus |
|[Phishing Army Feed](https://phishing.army) | blocklist de domaines liés au phishing (versions basic et extended) |
|[Phishing.Database (mitchellkrogza) Github](https://github.com/mitchellkrogza/Phishing.Database) | agrégation de domaines / IPs / liens de phishing depuis des sources publiques |
|[polkadot-js — phishing Github](https://github.com/polkadot-js/phishing) | blocklist de sites / adresses de phishing de l'écosystème Polkadot (non-EVM) `[crypto]` |
|[Prodaft Github](https://github.com/prodaft)| voir `malware-ioc` (IOCs d'investigations) et CRADLE (plateforme CTI) |
|[PulseDive](https://pulsedive.com) | plateforme CTI, plusieurs feeds ; compte gratuit disponible |
|[Ransomware.live Feeds](https://www.ransomware.live/api) | API victimes/groupes ransomware ; le plan gratuit permet 50 req/j |
|[RedDrip7 Github](https://github.com/RedDrip7)| `APT_Digital_Weapon` : IOCs APT catégorisés par QiAnXin (奇安信, Chine), actif |
|[rodanmaharjan Github](https://github.com/rodanmaharjan/ThreatIntelligence)| blocklist IOC pour MISP / pare-feu ; dernière MAJ sept. 2025 |
|[SANS ISC / DShield](https://isc.sans.edu) | IPs de scan et d'attaque, blocklists quotidiennes ([feeds](https://www.dshield.org/howto.html)) |
|[Scam Sniffer — scam-database Github](https://github.com/scamsniffer/scam-database) | domaines de drainers + adresses (ETH) d'arnaques Web3, MAJ quotidienne `[crypto]` |
|[Sekoia.io — Community Github](https://github.com/SEKOIA-IO/Community) | IOCs et règles Sigma en complément du [blog Sekoia](https://blog.sekoia.io) (déjà listé plus bas) |
|[Shadowserver](https://www.shadowserver.org/what-we-do/network-reporting/) | ONG ; rapports quotidiens gratuits pour votre ASN / plage IP + [dashboard public](https://dashboard.shadowserver.org) |
|[sophoslabs Github](https://github.com/sophoslabs/IoCs)| IOCs issus des publications Sophos, actif |
|[Spamhaus DROP / EDROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | plages IP détournées ou contrôlées par des cybercriminels ; TXT / JSON |
|[spydisec Github](https://github.com/spydisec/spydithreatintel)| agrégat OSINT + blocklists communautaires, mise à jour quotidienne |
|[sroberts Github](https://github.com/sroberts/awesome-iocs)| liste curée de sources IOC |
|[stamparm Ipsum Github](https://github.com/stamparm/Ipsum) | feed quotidien d'IPs malveillantes avec score de fiabilité graduel |
|[Stop Forum Spam](https://www.stopforumspam.com/downloads) | listes d'IP / domaines / emails de spam de forum |
|[Threatfeeds.io](https://threatfeeds.io) | annuaire de feeds gratuits/OSS ; peu mis à jour depuis ~2019 |
|[ViriBack C2 Tracker](https://tracker.viriback.com) | panels C2 actifs (stealers, RAT) ; export CSV |
|[WithSecure Labs Github](https://github.com/WithSecureLabs/iocs) | IOCs par campagne ([W/Labs](https://www.withsecure.com/en/resources-hub/w-labs/)) ; bonne couverture Lazarus / Europe du Nord, actif |
|[Wiz Research Github](https://github.com/wiz-sec-public/wiz-research-iocs) | IOCs cloud-native (conteneurs, CI/CD, supply chain) ; [blog](https://www.wiz.io/blog/tag/research) |
|[Xanderux Github](https://github.com/Xanderux/C2watcher) | feed C2 quotidien, actif |
|[xxspell Gitlab](https://gitlab.com/xxspell/ctifeeds)| instantané de janvier 2024, non maintenu depuis |
|[Zscaler Github](https://github.com/ThreatLabz/iocs)| IOCs des rapports Zscaler ThreatLabz, actif et dense |

# Menace mobile
Sources dédiées aux compromissions de smartphones (spyware mercenaire, stalkerware, trojans bancaires Android).
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[Amnesty International — investigations](https://github.com/AmnestyTech/investigations) | IOCs (STIX) des enquêtes du Security Lab : Pegasus, Predator/Cytrox, campagnes Android… ; dernière MAJ fin 2024 |
|[AssoEchap — stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | stalkerware Android : noms de paquets, C2, règles YARA et Suricata/Snort ; maintenu par Échap + Amnesty Security Lab, actif |
|[Citizen Lab — malware-indicators](https://github.com/citizenlab/malware-indicators) | IOCs des enquêtes Citizen Lab (Université de Toronto) sur le spyware mercenaire (Pegasus, Predator, Candiru…) |
|[Cleafy Labs](https://www.cleafy.com/labs) (Italie) | trojans bancaires Android et fraude (SpyNote, Copybara…) ; pas de flux, IOCs en fin de billet `[EN]` |
|[Lookout Threat Lab](https://www.lookout.com/threat-intelligence) (États-Unis) | spyware / surveillanceware mobile ; complément de Citizen Lab / Amnesty |
|[MVT Project — mvt-indicators](https://github.com/mvt-project/mvt-indicators) | index d'IOCs (STIX) compatibles avec l'outil forensic [MVT](https://github.com/mvt-project/mvt) (iOS / Android), actif |
|[ThreatFabric](https://www.threatfabric.com/blogs) (Pays-Bas) | référence des trojans bancaires Android ; IOCs en fin de billet, flux RSS `[EN]` |
|[Zimperium zLabs — IOC Github](https://github.com/Zimperium/IOC) (États-Unis) | IOCs par campagne de malware Android (banking trojans, OTP stealers, FakeCall…), actif |

# Sources gouvernementales et étatiques
CERT / CSIRT nationaux et agences. Beaucoup publient leurs IOCs dans des avis web plutôt que dans des feeds structurés.

### France
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[CERT-FR / ANSSI](https://www.cert.ssi.gouv.fr/ioc) | feed IOCs officiel (+ MISP natif) ; outils DFIR sur [github.com/ANSSI-FR](https://github.com/ANSSI-FR) (DFIR-ORC, DFIR-OGRE) |
|[VIGINUM](https://github.com/VIGINUM-FR/Rapports-Techniques) | rapports techniques sur l'ingérence numérique étrangère (dernière MAJ sept. 2025) |

### Organisations régionales et supranationales
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[ENISA — EU CSIRTs Network (CNW)](https://github.com/enisaeu/CNW) (UE) | agrège les avis des CSIRT nationaux de l'UE + CERT-EU |
|[CERT-EU](https://cert.europa.eu/publications/threat-intelligence) (UE) | Threat Intelligence & security advisories des institutions de l'UE ; [`droid`](https://github.com/certeu/droid) pour la gestion de règles Sigma |
|[Trusted Introducer / TF-CSIRT](https://www.trusted-introducer.org) (Europe) | annuaire et accréditation des CSIRT européens |
|[APCERT](https://www.apcert.org) (Asie-Pacifique) | organisation régionale des CERT d'Asie-Pacifique ; rapports annuels et exercices |
|[ASEAN Regional CERT](https://www.csa.gov.sg/news-events/press-releases/establishment-of-asean-regional-computer-emergency-response-team/) (Asie du Sud-Est) | CERT régional de l'ASEAN, hébergé par la CSA (Singapour) ; opérationnel depuis 2024, pas encore de site autonome — page de la CSA |
|[AfricaCERT](https://www.africacert.org) (Afrique) | organisation régionale des CSIRT africains |
|[OEA — CSIRTAmericas](https://csirtamericas.org) (Amériques) | réseau des CSIRT nationaux des Amériques (Organisation des États américains) `[ES/EN/PT]` |
|[OIC-CERT](https://oic-cert.org) (Org. de la coopération islamique) | réseau des CERT des États membres de l'OCI (secrétariat en Malaisie) ; peut être injoignable hors région |
|[FIRST](https://www.first.org) (mondial) | forum mondial des équipes de réponse à incident ; [annuaire des équipes membres](https://www.first.org/members/teams/) |

### États membres de l'UE
|Pays|Source|Commentaire|
|----|------|-----------|
|Allemagne | [BSI / CERT-Bund](https://github.com/BSI-Bund) | honeypot MADCAT, Secvisogram (CSAF) ; avis de vulnérabilité sur [wid.cert-bund.de](https://wid.cert-bund.de) `[DE]` |
|Autriche | [CERT.at / GovCERT Austria](https://www.cert.at) | avis, blog technique et statistiques ; opéré par nic.at `[DE/EN]` |
|Belgique | [CCB / CERT.be](https://cert.be) | avis de sécurité avec IOCs |
|Bulgarie | [CERT Bulgaria](https://govcert.bg) | CERT gouvernemental ; avis et actualités `[BG]` |
|Chypre | [CSIRT-CY](https://csirt.cy) | CSIRT national ; alertes et avis `[EL/EN]` |
|Croatie | [CERT.hr](https://www.cert.hr) | CERT national (CARNET) ; avis et publications `[HR]` |
|Danemark | [CFCS](https://www.cfcs.dk) | centre de cybersécurité du renseignement (FE) ; cfcs.dk redirige vers samsik.dk depuis la réorganisation de 2025 `[DA/EN]` |
|Espagne | [CCN-CERT](https://www.ccn-cert.cni.es) | CERT du renseignement ; rapports APT et outils (souvent sur inscription) `[ES]` |
|Espagne | [INCIBE-CERT](https://www.incibe.es/en/incibe-cert) | avis, études et outils `[ES/EN]` |
|Estonie | [CERT-EE / RIA](https://github.com/cert-ee) | Cuckoo3, S4A detector et autres outils |
|Finlande | [NCSC-FI / Traficom](https://www.kyberturvallisuuskeskus.fi) | centre national ; alertes, rapports et notifications aux réseaux finlandais `[FI/SV/EN]` |
|Grèce | [NCSA / EL CSIRT](https://cyber.gov.gr) | autorité nationale de cybersécurité et son CSIRT `[EL/EN]` |
|Hongrie | [NKI / NBSZ](https://nki.gov.hu) | centre national de cybersécurité ; alertes et avis `[HU]` |
|Irlande | [NCSC-IE](https://www.ncsc.gov.ie) | avis et alertes |
|Italie | [CERT-AGID](https://cert-agid.gov.it) | feed IOC quotidien (malware / phishing visant l'Italie) ; inscription requise `[IT]` |
|Lettonie | [CERT.LV](https://www.cert.lv/en/data-feed) | data feed national (sinkhole, IPs et domaines compromis) |
|Lituanie | [NKSC](https://www.nksc.lt) | centre national de cybersécurité ; avis et rapports ; le site répond 403 aux robots, ouvrir dans un navigateur `[LT/EN]` |
|Luxembourg | [CIRCL](https://www.circl.lu/doc/misp/feed-osint/) | feed MISP OSINT ; éditeur de MISP, AIL, Passive DNS/SSL ([github.com/CIRCL](https://github.com/CIRCL)) |
|Malte | [CSIRTMalta](https://csirtmalta.gov.mt) | CSIRT national ; accès filtré hors de Malte (redirection vers une page d'attente lors de la vérification) |
|Pays-Bas | [NCSC-NL](https://github.com/NCSC-NL) | dépôts d'IOCs et scripts de scan par campagne (Citrix, MOVEit, Zimbra…) |
|Pologne | [CERT Polska / CERT.pl](https://github.com/CERT-Polska) | mwdb, drakvuf-sandbox, karton, Artemis ; blocklist de domaines [hole.cert.pl](https://hole.cert.pl) |
|Portugal | [CNCS / CERT.PT](https://www.cncs.gov.pt) | centre national ; avis et coordination d'incidents `[PT]` |
|Roumanie | [DNSC](https://www.dnsc.ro) | directorat national (ex-CERT-RO) ; alertes et guides ; le site répond 403 aux robots, ouvrir dans un navigateur `[RO/EN]` |
|Slovaquie | [SK-CERT](https://www.sk-cert.sk) | autorité nationale ; avis de vulnérabilité quotidiens `[SK/EN]` |
|Slovénie | [SI-CERT](https://www.cert.si) | CERT national (Arnes) ; avis et alertes `[SL/EN]` |
|Suède | [CERT-SE](https://www.cert.se) | alertes et analyses `[SV/EN]` |
|Tchéquie | [NÚKIB](https://nukib.gov.cz/en/) | alertes, avertissements et rapports |

### Autres pays
|Pays|Source|Commentaire|
|----|------|-----------|
|Albanie | [AKSK](https://aksk.gov.al) | autorité nationale de cybersécurité (ex-AKCESK) ; alertes et rapports `[SQ/EN]` |
|Arabie saoudite | [Saudi CERT](https://cert.gov.sa) | avis et alertes de sécurité `[AR/EN]` |
|Argentine | [CERT.ar](https://www.argentina.gob.ar/jefatura/innovacion-ciencia-y-tecnologia/centro-nacional-de-ciberseguridad/certar) | CERT national (Centro Nacional de Ciberseguridad) `[ES]` |
|Australie | [ACSC / ASD](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories) | alertes et avis avec IOCs |
|Azerbaïdjan | [CERT.AZ](https://cert.az) | CERT gouvernemental ; alertes `[AZ/EN]` |
|Bangladesh | [BGD e-GOV CIRT](https://www.cirt.gov.bd) | CIRT national très actif : alertes, rapports d'analyse et IOCs |
|Bélarus | [CERT.BY](https://cert.by) | CERT national (OAC) `[RU]` |
|Bolivie | [CGII / CSIRT-Bolivia](https://csirt.gob.bo) | centre de gestion d'incidents (AGETIC) ; alertes et avis `[ES]` |
|Brésil | [CERT.br](https://cert.br) | honeypots, données spam, statistiques nationales `[PT/EN]` |
|Canada | [CCCS / Cyber Centre](https://github.com/CybercentreCanada) | AssemblyLine, extracteurs de config, outils SOC ; avis sur [cyber.gc.ca](https://www.cyber.gc.ca/en/alerts-advisories) |
|Chili | [CSIRT de Gobierno](https://csirt.gob.cl) | alertes et IOCs publiés très régulièrement `[ES]` |
|Chine | [CNCERT/CC](https://www.cert.org.cn/publish/english/index.html) | CERT national ; rapports et statistiques `[ZH ; page EN limitée]` |
|Chine | [CVERC](https://www.cverc.org.cn) | centre national de réponse aux virus `[ZH]` |
|Colombie | [colCERT](https://www.colcert.gov.co) | CERT national `[ES]` |
|Corée du Sud | [KrCERT / KISA](https://www.krcert.or.kr) | avis, takedown phishing/C2, rapports `[KO]` |
|Côte d'Ivoire | [CI-CERT](https://www.artci.ci) | CERT national, rattaché au régulateur ARTCI |
|Égypte | [EG-CERT](https://egcert.eg) | CERT national (NTRA) ; connexion refusée depuis certains réseaux lors de la vérification `[AR/EN]` |
|Émirats arabes unis | [aeCERT](https://aecert.ae) | CERT national ; alertes et sensibilisation `[AR/EN]` |
|Équateur | [EcuCERT](https://www.ecucert.gob.ec) | CERT national (Arcotel) ; alertes `[ES]` |
|États-Unis | [CISA](https://github.com/cisagov) | liste `.gov`, catalogue [KEV](https://github.com/cisagov/kev-data), avis [CSAF](https://github.com/cisagov/CSAF) ; alertes sur [cisa.gov](https://www.cisa.gov/news-events/cybersecurity-advisories) |
|États-Unis | [CERT/CC (CMU SEI)](https://github.com/CERTCC) | coordination de divulgation (VINCE, SSVC, Vultron), outils d'analyse binaire |
|États-Unis | [DARPA — Transparent Computing / OpTC](https://github.com/FiveDirections/OpTC-data) | datasets de traces hôte/réseau annotées pour la recherche en détection APT (agence du DoD) |
|États-Unis | [IMPACT Cyber Trust](https://www.impactcybertrust.org) | place de marché de datasets de cybersécurité pour la recherche (financé par le DHS) |
|États-Unis | [Los Alamos National Laboratory](https://csr.lanl.gov/data/) | datasets host / auth / réseau, scénarios APT (laboratoire du DOE / NNSA) |
|États-Unis | [NSA Cybersecurity](https://github.com/nsacyber) | guides de durcissement et de détection, configurations |
|Géorgie | [CERT.GOV.GE](https://cert.dga.gov.ge) | CERT gouvernemental (Digital Governance Agency) `[KA/EN]` |
|Ghana | [CSA / CERT-GH](https://www.csa.gov.gh) | Cyber Security Authority et CERT national ; alertes et avis |
|Hong Kong | [HKCERT](https://www.hkcert.org) | alertes, blog de veille et rapports `[ZH/EN]` |
|Inde | [CERT-In](https://www.cert-in.org.in) | CERT national : avis, notes de vulnérabilité, alertes |
|Inde | [CERT Mumbai (MH-CERT)](https://github.com/MH-CERT) | repo `Indicator-of-Compromise-IOC-` ; activité faible |
|Inde | [Cyber Swachhता Kendra (CSK)](https://www.csk.gov.in) | centre de nettoyage de botnets opéré par CERT-In ; outils et avis |
|Inde | [NCIIPC](https://nciipc.gov.in) | protection des infrastructures critiques ; bulletins avec IOCs `[EN ; accès surtout depuis l'Inde]` |
|Indonésie | [BSSN](https://www.bssn.go.id) | agence nationale (dont l'Id-SIRTII/CC) ; le site répond 403 aux robots, ouvrir dans un navigateur `[ID]` |
|Iran | [Maher / CERT.ir](https://cert.ir) | CERT national `[FA]` |
|Islande | [CERT-IS](https://www.cert.is) | CERT national ; alertes `[IS/EN]` |
|Israël | [INCD](https://www.gov.il/en/departments/israel_national_cyber_directorate) | directorat national ; alertes et rapports ; le portail gov.il répond 403 aux robots, ouvrir dans un navigateur `[HE/EN]` |
|Japon | [JPCERT/CC](https://github.com/JPCERTCC) | `phishurl-list`, `jpcert-yara`, `Contagious-Interview-IoCs`, `CobaltStrike-Config`, LogonTracer, EmoCheck ; blog d'analyse [« Eyes »](https://blogs.jpcert.or.jp/en/) (IOCs par billet, flux Atom) |
|Jordanie | [NCSC-JO](https://ncsc.jo) | centre national de cybersécurité ; alertes `[AR/EN]` |
|Kazakhstan | [KZ-CERT](https://cert.gov.kz) | CERT national (State Technical Service) `[KK/RU/EN]` |
|Kenya | [National KE-CIRT/CC](https://ke-cirt.go.ke) | CERT national ; avis et rapports |
|Macédoine du Nord | [MKD-CIRT](https://mkd-cirt.mk) | CIRT national (AEK) ; avis `[MK/EN]` |
|Malaisie | [MyCERT](https://www.mycert.org.my) | CERT national (CyberSecurity Malaysia) : avis et alertes ; le site répond 403 aux robots, ouvrir dans un navigateur |
|Maroc | [DGSSI / maCERT](https://www.dgssi.gov.ma) | avis et bulletins de sécurité `[FR/AR]` |
|Maurice | [CERT-MU](https://cert-mu.govmu.org) | CERT national ; alertes et guides |
|Mexique | [CERT-MX](https://www.gob.mx/gncertmx) | CERT national (Guardia Nacional) `[ES]` |
|Moldavie | [CERT-GOV-MD](https://cert.gov.md) | CERT gouvernemental (STISC) ; alertes `[RO/EN]` |
|Monténégro | [CIRT.ME](https://cirt.gov.me) | CIRT national ; avis `[CNR/EN]` |
|Nigeria | [ngCERT](https://cert.gov.ng) | CERT national ; avis et alertes ; le site répond 403 aux robots, ouvrir dans un navigateur |
|Norvège | [NSM / NCSC-NO](https://nsm.no) | autorité nationale de sécurité ; alertes et rapports `[NO/EN]` |
|Nouvelle-Zélande | [NCSC-NZ](https://www.ncsc.govt.nz) | avis et alertes (CERT NZ y a été intégré en 2024) |
|Oman | [OCERT](https://www.cert.gov.om) | CERT national ; alertes `[AR/EN]` |
|Ouzbékistan | [UZCERT](https://uzcert.uz) | CERT national (Centre de cybersécurité) `[UZ/RU]` |
|Pakistan | [PKCERT](https://pkcert.gov.pk) | CERT national (opérationnel depuis 2024) ; avis et alertes |
|Panama | [CSIRT Panamá](https://cert.pa) | CSIRT national (AIG) ; alertes `[ES]` |
|Paraguay | [CERT-PY](https://www.cert.gov.py) | CERT national ; publie régulièrement avis et IOCs `[ES]` |
|Pérou | [PeCERT](https://pecert.gob.pe) | CERT gouvernemental `[ES]` |
|Philippines | [CERT-PH / NCERT](https://ncert.gov.ph) | CERT national (DICT) ; le site répond 403 aux robots, ouvrir dans un navigateur |
|Qatar | [NCSA / Q-CERT](https://www.ncsa.gov.qa) | agence nationale (intègre Q-CERT) ; alertes `[AR/EN]` |
|République dominicaine | [CNCS / CSIRT-RD](https://cncs.gob.do) | centre national de cybersécurité ; alertes `[ES]` |
|Royaume-Uni | [NCSC-UK](https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports) | rapports de menace avec IOCs ; packs de config sur [github.com/ukncsc](https://github.com/ukncsc) |
|Russie | [NKTsKI / GosSOPKA](https://safe-surf.ru) | CERT national (safe-surf.ru) ; portail russophone, accès limité `[RU]` |
|Serbie | [Nacionalni CERT](https://www.cert.rs) | CERT national (RATEL) ; avis `[SR/EN]` |
|Singapour | [SingCERT / CSA](https://www.csa.gov.sg/singcert) | alertes et avis ; la CSA héberge aussi l'ASEAN Regional CERT |
|Sri Lanka | [Sri Lanka CERT](https://www.cert.gov.lk) | CERT national ; alertes `[SI/TA/EN]` |
|Suisse | [GovCERT.ch](https://github.com/govcert-ch/CTI) | dépôt `CTI` (IOCs et notes d'analyse), actif |
|Tadjikistan | [CERT.TJ](https://cert.tj) | CERT national ; le seul d'Asie centrale avec un flux RSS `[RU/TJ]` |
|Taïwan | [TWCERT/CC](https://www.twcert.org.tw) | CERT national ; avis et rapports `[ZH/EN]` |
|Thaïlande | [TTC-CERT](https://github.com/ttc-cert) | CERT du secteur télécom : blocklist recommandée, règles Sigma/YARA, events MISP ; rien de neuf depuis 2024 |
|Thaïlande | [ThaiCERT / ETDA](https://www.thaicert.or.th) | avis et alertes (distinct de l'[APT Encyclopedia](https://apt.etda.or.th)) ; flux RSS `[TH/EN]` |
|Tunisie | [ANCS / tunCERT](https://www.ancs.tn) | agence nationale (ex-ANSI) et son CERT ; connexion refusée depuis certains réseaux lors de la vérification `[FR/AR]` |
|Turquie | [USOM](https://www.usom.gov.tr) | centre national ; [liste publique d'URLs/IPs malveillantes](https://www.usom.gov.tr/url-list.txt) `[TR]` |
|Ukraine | [CERT-UA](https://cert.gov.ua) | publication d'IOCs très prolifique (activité APT russe) ; articles détaillés + MISP `[UA/EN]` |
|Ukraine | [SSSCIP / ДССЗЗІ](https://cip.gov.ua/en) | service d'État de protection (tutelle de CERT-UA) ; rapports semestriels d'ensemble `[UA/EN]` |
|Uruguay | [CERTuy](https://www.cert.uy) | CERT national `[ES]` |
|Vietnam | [VNCERT/CC](https://vncert.vn) | CERT national (min. de l'Information et des Communications) `[VI]` |

# Éditeurs et laboratoires de recherche privés
Blogs et publications de recherche des éditeurs de sécurité (IOCs et TTPs dans les billets).
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[360 Netlab](https://blog.netlab.360.com) (Chine) | feeds C2 / DGA / botnet historiques ; peu actif depuis 2022 `[ZH/EN]` |
|[Acronis TRU](https://www.acronis.com/en/tru/) (Suisse) | analyses de malware et de ransomware ; flux RSS `[EN]` |
|[AhnLab ASEC](https://asec.ahnlab.com/en/) (Corée du Sud) | blog très prolifique (Kimsuky, Lazarus, malware ciblant l'Asie) `[KO ; blog EN]` |
|[Antiy Labs / 安天](https://www.antiy.net) (Chine) | rapports APT `[ZH ; certains rapports EN]` |
|[ANY.RUN](https://any.run/cybersecurity-blog/) | analyses de malware issues de la sandbox ; flux RSS `[EN]` |
|[Aqua Nautilus](https://www.aquasec.com/blog/) (Israël / États-Unis) | menaces cloud et conteneurs `[EN]` |
|[Arctic Wolf Labs](https://arcticwolf.com/resources/blog/) (États-Unis) | intrusions et ransomware, télémétrie IR ; flux RSS `[EN]` |
|[Aryaka — Threat Research](https://www.aryaka.com/blog/) (États-Unis) | rapports APT très détaillés, forte couverture Transparent Tribe / APT36 (C2 tradecraft) `[EN]` |
|[Base4 Security](https://base4sec.com/insights/) (Argentine) | recherche menaces Amérique latine `[ES]` |
|[BI.ZONE](https://bi.zone) (Russie) | recherche menaces (groupe Sber) ; lib [`bi-zone/bizone-ti-lib`](https://github.com/bi-zone/bizone-ti-lib) `[EN/RU]` |
|[Bitsight TRACE](https://www.bitsight.com/blog) (États-Unis) | botnets et sinkholes `[EN]` |
|[Brandefense](https://brandefense.io/blog/) (Turquie) | recherche menaces et rapports d'acteurs `[EN]` |
|[Broadcom / Symantec Threat Hunter Team](https://www.security.com/threat-intelligence) (États-Unis) | APT et ransomware ; flux RSS, [bulletins de protection](https://www.broadcom.com/support/security-center/protection-bulletin) `[EN]` |
|[Censys Research](https://censys.com/resources/blog/) (États-Unis) | infrastructure exposée et C2 ; flux RSS `[EN]` |
|[CERT Orange Polska](https://cert.orange.pl) (Pologne) | CERT de l'opérateur : alertes, analyses et blocklist CyberTarcza `[PL]` |
|[Check Point Research](https://research.checkpoint.com) (Israël) | recherche menaces très prolifique ; IOCs par billet `[EN]` |
|[Cisco Talos](https://blog.talosintelligence.com) (États-Unis) | blog de recherche ; les IOCs associés sont sur le repo GitHub (section Indices de compromissions) `[EN]` |
|[ClearSky Cyber Security](https://www.clearskysec.com/blog/) (Israël) | rapports APT, notamment Moyen-Orient `[EN]` |
|[CloudSEK](https://www.cloudsek.com/blog) (Inde) | recherche menaces, fuites, surface d'attaque `[EN]` |
|[Cofense](https://cofense.com/blog/) (États-Unis) | phishing et campagnes e-mail `[EN]` |
|[CronUp](https://www.cronup.com/blog/) (Chili) | threat intel centrée Amérique latine `[ES]` |
|[CrySyS Lab (BME)](https://blog.crysys.hu/) (Hongrie) | laboratoire universitaire (Duqu, sKyWIper) ; flux RSS `[EN]` |
|[CTM360](https://www.ctm360.com) (Bahreïn) | veille et rapports centrés Golfe / Moyen-Orient `[EN]` |
|[Cybereason](https://www.cybereason.com/blog) (États-Unis) | malware et ransomware ; flux RSS `[EN]` |
|[Cyble](https://cyble.com/blog/) (Inde / États-Unis) | recherche menaces très prolifique `[EN]` |
|[CYFIRMA](https://www.cyfirma.com/research/) (Inde / Singapour) | rapports d'attribution et de campagne `[EN]` |
|[DBAPPSecurity / 安恒信息 — 安恒威胁情报中心](https://ti.dbappsecurity.com.cn/blog/) (Chine) | blog TI ; labo 猎影 (Hunting Shadow), attribution APT `[ZH]` |
|[Deep Instinct](https://www.deepinstinct.com/blog) (Israël) | analyses de malware `[EN]` |
|[Doctor Web / Dr.Web](https://news.drweb.com) (Russie) | analyses de malware avec IOCs `[RU/EN]` |
|[DomainTools](https://www.domaintools.com/blog) (États-Unis) | investigation d'infrastructure DNS `[EN]` |
|[Dragos](https://www.dragos.com/blog) (États-Unis) | référence ICS/OT ; IOCs dans les rapports de groupes (Voltzite…), flux RSS `[EN]` |
|[DTS Solution](https://www.dts-solution.com) (Émirats arabes unis) | recherche menaces Golfe ; flux RSS présent, page blog à vérifier `[EN]` |
|[Emsisoft](https://www.emsisoft.com/en/blog/) (Nouvelle-Zélande) | ransomware et statistiques ; flux RSS `[EN]` |
|[ENKI WhiteHat — Threat Research](https://www.enki.co.kr/en/media-center/blog) (Corée du Sud) | analyses d'intrusions APT nord-coréennes (Kimsuky ciblant des éditeurs groupware KR), billets EN détaillés `[KO ; blog EN]` |
|[Ensign InfoSecurity](https://www.ensigninfosecurity.com/resources) (Singapour) | menaces Asie du Sud-Est `[EN]` |
|[eSentire TRU](https://www.esentire.com/resources/blog) (Canada) | Threat Response Unit : intrusions récurrentes `[EN]` |
|[ESET — WeLiveSecurity](https://www.welivesecurity.com) (Slovaquie) | blog de recherche ; les IOCs associés sont sur le repo GitHub (section Indices de compromissions) `[EN ; éditions FR/DE/ES]` |
|[EST Security / ESRC — 알약 블로그](https://blog.alyac.co.kr) (Corée du Sud) | analyses de malware et d'APT nord-coréennes (Kimsuky…) très fréquentes ; IOCs par billet `[KO]` |
|[F6](https://www.f6.ru) (ex-F.A.C.C.T., Russie) | cybercriminalité russophone `[RU]` |
|[FalconFeeds.io](https://falconfeeds.io) (Inde) | suivi temps réel : revendications de victimes ransomware, hacktivisme, fuites darkweb (opéré par Technisanct, Kochi) `[EN]` |
|[Flashpoint](https://flashpoint.io/blog/) (États-Unis) | underground criminel, ransomware `[EN]` |
|[Fortinet FortiGuard Labs](https://www.fortinet.com/blog/threat-research) (États-Unis) | malware et phishing ; IOCs en fin de billet `[EN]` |
|[G DATA CyberDefense](https://blog.gdatasoftware.com) (Allemagne) | analyses de malware `[EN/DE]` |
|[Genians — Genians Security Center](https://www.genians.co.kr/en/blog/threat_intelligence) (Corée du Sud) | blog prolifique sur les APT nord-coréennes (Kimsuky, APT37/ScarCruft, RokRAT) ; IOCs par billet, flux RSS `[KO ; blog EN]` |
|[Google Cloud Threat Intelligence (Mandiant)](https://cloud.google.com/blog/topics/threat-intelligence) (États-Unis) | APT et cybercrime ; le repo `mandiant/iocs` est archivé (2019), la recherche vivante est ici `[EN]` |
|[GreyNoise Labs](https://www.greynoise.io/blog) (États-Unis) | scans de masse et exploitation opportuniste `[EN]` |
|[Group-IB](https://www.group-ib.com/blog/) (Singapour) | e-crime, rapports détaillés avec IOCs `[EN]` |
|[Help AG](https://www.helpag.com) (Émirats arabes unis) | recherche menaces Golfe ; flux RSS présent, page blog à vérifier en navigateur `[EN]` |
|[Hunt.io](https://hunt.io/blog) (États-Unis) | suivi d'infrastructure C2 ; feeds sur compte `[EN]` |
|[IIJ — wizSafe Security Signal](https://wizsafe.iij.ad.jp) (Japon) | bilans mensuels de la menace observée (DDoS, malware, scan) et analyses ; flux RSS `[JP]` |
|[Intel 471](https://www.intel471.com/blog) (États-Unis) | underground criminel, IAB `[EN]` |
|[ISH Tecnologia](https://ish.com.br/blog/) (Brésil) | menaces visant le Brésil ; flux RSS `[PT]` |
|[ITOCHU Cyber & Intelligence](https://blog-en.itochuci.co.jp) (Japon) | analyses de malware et d'APT visant le Japon (Tropic Trooper, malspam JP…) ; flux RSS `[JP ; blog EN]` |
|[K7 Labs](https://labs.k7computing.com) (Inde) | analyses de malware (éditeur AV de Chennai) `[EN]` |
|[Kaspersky ICS-CERT](https://ics-cert.kaspersky.com) (Russie) | spécialisé OT / ICS `[EN]` |
|[Kaspersky — Securelist](https://securelist.com) (Russie) | équipe GReAT, IOCs par rapport `[EN]` |
|[KELA](https://www.kelacyber.com/blog/) (Israël) | cybercrime, courtiers d'accès initial `[EN]` |
|[Knownsec 404 Team / 知道创宇](https://paper.seebug.org) (Chine) | papers de recherche (plateforme Seebug) ; connexion refusée depuis certains réseaux lors de la vérification `[ZH]` |
|[Lab52 / S2 Grupo](https://lab52.io) (Espagne) | recherche APT et géopolitique cyber `[EN]` |
|[LAC — LAC WATCH](https://www.lac.co.jp/lacwatch/) (Japon) | rapports du JSOC et du Cyber Emergency Center sur les menaces visant le Japon `[JP]` |
|[LevelBlue SpiderLabs (ex-Trustwave)](https://www.levelblue.com/blogs/spiderlabs-blog) (États-Unis) | malware, phishing, e-mail ; flux RSS `[EN]` |
|[Macnica Security Research](https://security.macnica.co.jp/) (Japon) | rapports APT visant le Japon `[JP]` |
|[Malwarebytes Labs](https://www.malwarebytes.com/blog/category/threat-intel) (États-Unis) | malware grand public et arnaques `[EN]` |
|[Metabase Q — Ocelot](https://www.metabaseq.com) (Mexique) | recherche menaces centrée Amérique latine `[EN/ES]` |
|[Microsoft — Security Blog / MSTIC](https://www.microsoft.com/en-us/security/blog/) (États-Unis) | rapports et analyses `[EN]` |
|[Morphisec](https://www.morphisec.com/blog/) (Israël) | loaders et chaînes d'infection ; flux RSS `[EN]` |
|[nao-sec](https://nao-sec.org) (Japon) | collectif de recherche : analyses, outils (RTF weaponizer decoder…) `[JP/EN]` |
|[Netcraft](https://www.netcraft.com/resources/blog) (Royaume-Uni) | phishing et fraude à grande échelle `[EN]` |
|[Nozomi Networks Labs](https://www.nozominetworks.com/labs) (États-Unis / Suisse) | ICS/OT et IoT `[EN]` |
|[NSFOCUS / 绿盟](https://nsfocusglobal.com/blog/) (Chine) | rapports APT (labo 伏影 / Fuying) ; flux RSS sur le blog global `[EN (global) / ZH]` |
|[NSHC ThreatRecon](https://threatrecon.nshc.net) (Corée du Sud) | suivi des groupes « SectorXX » (APT nord-coréennes, chinoises…) ; [repo `IoC-List`](https://github.com/nshc-threatrecon/IoC-List) gelé fin 2021 `[EN/KO]` |
|[OpenAnalysis Labs (OALabs)](https://research.openanalysis.net/) (Canada) | reverse engineering, loaders ; flux RSS `[EN]` |
|[Positive Technologies — PT ESC](https://github.com/PositiveTechnologies) (Russie) | recherche menaces ; règles Suricata figées 2022 sur [`ptresearch/AttackDetection`](https://github.com/ptresearch/AttackDetection) `[EN/RU]` |
|[Proofpoint Threat Insight](https://www.proofpoint.com/us/blog/threat-insight) (États-Unis) | e-mail, acteurs TA5xx ; IOCs en tableaux `[EN]` |
|[QiAnXin TI Center / 奇安信](https://ti.qianxin.com) (Chine) | portail Threat Intelligence ; voir aussi [RedDrip7](https://github.com/RedDrip7) `[ZH]` |
|[Rapid7](https://www.rapid7.com/blog/) (États-Unis) | vulnérabilités et campagnes ; flux RSS `[EN]` |
|[Recorded Future / Insikt Group](https://www.recordedfuture.com/research) (États-Unis) | APT et cybercrime ; dépôt `Insikt-Group/Research` figé 2023 → n'utiliser que le blog `[EN]` |
|[Red Canary](https://redcanary.com/resources-center/category/blog/) (États-Unis) | détection, techniques les plus vues `[EN]` |
|[ReliaQuest](https://reliaquest.com/blog/) (États-Unis) | cybercrime et ransomware ; flux RSS `[EN]` |
|[S2W](https://s2w.inc/en/resource) (Corée du Sud) | recherche menaces (équipe Talon) : darkweb, groupes nord-coréens `[EN/KO]` |
|[Sangfor / 深信服 — 千里目安全技术中心](https://www.sangfor.com.cn/security-tech) (Chine) | rapports APT et analyses de campagnes (6 laboratoires) ; accès filtré hors de Chine `[ZH]` |
|[Scitum (Telmex)](https://www.scitum.com.mx/) (Mexique) | recherche menaces Amérique latine `[ES]` |
|[Secureworks CTU](https://www.secureworks.com) (États-Unis) | Counter Threat Unit ; Secureworks a été absorbé par Sophos (2025) `[EN]` |
|[Security Vision](https://www.securityvision.ru/blog/) (Russie) | analyses `[RU]` |
|[Sekoia.io](https://blog.sekoia.io) (France) | recherche menaces, TDR `[EN/FR]` |
|[SentinelLABS](https://www.sentinelone.com/labs/) (États-Unis) | recherche menaces, rapports APT `[EN]` |
|[Seqrite Labs / Quick Heal](https://www.seqrite.com/blog/) (Inde) | fort sur les APT d'Asie du Sud (SideCopy, Transparent Tribe…) `[EN]` |
|[Sequretek](https://www.sequretek.com/resources/threat-advisory) (Inde) | avis de menace `[EN]` |
|[Silent Push](https://www.silentpush.com/blog/) (États-Unis) | IOCs d'infrastructure très détaillés (pDNS, C2) ; flux RSS, feeds payants `[EN]` |
|[SOCRadar](https://socradar.io/blog/) (Turquie) | darkweb et ransomware ; volume élevé, IOCs variables `[EN]` |
|[Solar 4RAYS](https://solar4rays.ru) (Russie) | bulletins d'IOCs (groupe Rostelecom) `[RU]` |
|[Solar — analytics](https://rt-solar.ru/analytics/reports/) (Russie) | rapports (complète Solar 4RAYS) `[RU]` |
|[Sucuri](https://blog.sucuri.net/) (États-Unis) | malware web, skimmers, compromissions CMS/WordPress ; flux RSS `[EN]` |
|[Sygnia](https://www.sygnia.co/blog/) (Israël) | réponse à incident et APT ; flux RSS `[EN]` |
|[Team Cymru](https://www.team-cymru.com/blog) (États-Unis) | analyse d'infrastructure et de C2 `[EN]` |
|[TeamT5](https://teamt5.org/en/) (Taïwan) | recherche APT nexus-Chine `[EN/ZH]` |
|[Telefónica Tech](https://telefonicatech.com/en/blog) (Espagne) | télécom et menaces `[EN/ES]` |
|[Tempest Security](https://www.tempest.com.br/blog) (Brésil) | menaces visant le Brésil `[PT]` |
|[Tencent Security — 威胁情报中心 / 御见](https://tix.qq.com) (Chine) | portail de threat intelligence de Tencent : rapports APT et lookups ([s.tencent.com](https://s.tencent.com)) `[ZH]` |
|[ThreatBook / 微步在线](https://threatbook.io) (Chine) | éditeur TI ; lookups communautaires gratuits sur [x.threatbook.com](https://x.threatbook.com) `[EN/ZH]` |
|[Threatray](https://www.threatray.com) (Suisse) | similarité de code et suivi de campagnes `[EN]` |
|[Trend Micro Research](https://www.trendmicro.com/en_us/research.html) (Japon / États-Unis) | couverture large ; IOCs en PDF joints aux articles, dépôt `trendmicro/research` figé 2024 `[EN/JP]` |
|[Truesec](https://www.truesec.com/hub/blog) (Suède) | réponse à incident et ransomware (Nordiques) `[EN/SV]` |
|[Uptycs Threat Research](https://www.uptycs.com/blog) (États-Unis) | malware Linux et cloud ; flux RSS `[EN]` |
|[Validin](https://www.validin.com/blog/) (États-Unis) | investigation d'infrastructure et pDNS `[EN]` |
|[Varonis Threat Labs](https://www.varonis.com/blog/tag/threat-research) (États-Unis) | Windows et SaaS ; flux RSS `[EN]` |
|[Viettel Cyber Security](https://blog.viettelcybersecurity.com) (Vietnam) | analyses de menaces et de vulnérabilités `[VI/EN]` |
|[Yoroi — Z-Lab](https://yoroi.company/research/) (Italie) | analyses de campagnes et de malware `[IT/EN]` |

# Sources académiques et datasets de recherche
Laboratoires universitaires et jeux de données pour l'entraînement, l'évaluation et la recherche en détection.
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[Canadian Institute for Cybersecurity (UNB)](https://www.unb.ca/cic/datasets/) (Canada) | datasets IDS, malware Android (CICMalDroid), DoH, DDoS… très utilisés en recherche |
|[CAIDA](https://www.caida.org/catalog/datasets/) (UC San Diego, États-Unis) | télescope réseau, DDoS, données de scan (certains sur demande) ; financements NSF / DHS |
|[Citizen Lab](https://github.com/citizenlab) (Université de Toronto, Canada) | recherche spyware / censure ; voir aussi section Menace mobile |
|[SecRepo](https://secrepo.com) | index de « Samples of Security Related Data » |
|[Stratosphere Laboratory](https://www.stratosphereips.org) (CTU Prague, Tchéquie) | datasets malware / IoT (CTU-13, IoT-23) + feed de blocklists gratuit + IDS [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) |
|[The Honeynet Project](https://www.honeynet.org) | organisation de recherche (chapitres académiques) : outils, challenges forensic, données honeypot |
|[theZoo](https://github.com/ytisf/theZoo) | corpus de malware vivant pour la recherche |
|[UNSW Canberra Cyber](https://research.unsw.edu.au/projects/toniot-datasets) (Australie) | datasets UNSW-NB15, ToN_IoT et Bot-IoT pour la recherche IDS / IoT |
|[VirusShare](https://virusshare.com) | vaste corpus de malware ; accès chercheurs sur demande |

# Rapports, analyses, informations
Méta-listes, agrégateurs et bibliothèques de rapports.
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[APTnotes](https://github.com/aptnotes/data) | archive historique de rapports APT publics ; figée fin 2024 |
|[blackorbird Github](https://github.com/blackorbird/APT_REPORT) | collecte de rapports et d'indicateurs APT classés par groupe, très actif |
|[BushidoUK — Ransomware Tool Matrix Github](https://github.com/BushidoUK/Ransomware-Tool-Matrix) | matrice outils ↔ groupes de ransomware (exploitable en détection), actif |
|[curated-intel Github](https://github.com/curated-intel) | collectif Curated Intelligence : threat notes, listes par campagne (Ukraine, MOVEit…), CTI Fundamentals |
|[CyberMonitor Github](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections) | archive de campagnes APT / cybercrime classées par année ; figée depuis mi-2024 |
|[despacito420 Github](https://github.com/despacito420/The-Feed)| liste curée d'articles SOC/DFIR/CTI ; activité faible (dernière MAJ janv. 2026) |
|[devsecops Github](https://github.com/devsecops/awesome-devsecops) | liste d'outils DevSecOps (dont CTI) ; figée depuis 2024 |
|[EndlessFractal Github](https://github.com/EndlessFractal/Threat-Intel-Feed)| agrégation et consolidation automatiques de feeds, actif |
|[ETDA / ThaiCERT APT Encyclopedia](https://apt.etda.or.th) | fiches détaillées de groupes et d'outils APT |
|[gm7.org — 信息安全知识库](https://www.gm7.org) | agrégateur / archive de contenu sécurité chinois (actualités, vulnérabilités, campagnes APT, collectes de hash) ; flux RSS très dense `[ZH]` |
|[HackYourMom](https://hackyourmom.com/) (Ukraine) | communauté ; guides et listes, contenu grand public / hacktiviste, à recouper `[UA]` |
|[Have I Been Pwned](https://haveibeenpwned.com) | flux des fuites de données ([RSS](https://haveibeenpwned.com/feed/breaches/)) — hors IOC mais utile en veille |
|[hslatman Github](https://github.com/hslatman/awesome-threat-intelligence)| liste de référence des ressources CTI |
|[infoblox Github](https://github.com/infobloxopen/threat-intelligence) | IOCs et rapports Infoblox (threat intel DNS), actif |
|[Malpedia](https://malpedia.caad.fkie.fraunhofer.de) | familles de malware, règles YARA, références (Fraunhofer FKIE) ; compte gratuit |
|[mdecrevoisier Github](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | 270+ échantillons EVTX mappés ATT&CK, pour mesurer la couverture SIEM |
|[Midnight Slayer](https://start.me/p/wMPxqX/cyber-threat-intelligence)| tableau de bord start.me ; bloque les robots, ouvrir dans un navigateur |
|[MITRE ATT&CK — Groups & Software](https://attack.mitre.org/groups/) | complément « lisible » des données STIX : fiches groupes et logiciels |
|[mthcht Github](https://github.com/mthcht) | voir `awesome-lists` (SOC/CERT/CTI) et `ThreatIntel-Reports`, très actif |
|[NetManageIT instance publique OpenCTI](https://opencti.netmanageit.com) | instance OpenCTI publique en lecture seule ; actuellement hors ligne (2026) |
|[lazarus.day](https://lazarus.day) | index dédié des rapports publics sur les groupes nord-coréens (Lazarus, Kimsuky, APT37, Andariel…) |
|[ORKL](https://orkl.eu) | bibliothèque de rapports CTI / APT indexés et cherchables + API |
|[RST Cloud — awesome-threat-actor-resources](https://github.com/rstcloud/awesome-threat-actor-resources) | méta-liste de profils d'acteurs et de datasets APT publics |
|[Serianu](https://www.serianu.com/) (Kenya) | « Africa Cyber Security Report » annuels ; pas d'IOC atomiques `[EN]` |
|[SlowMist / 慢雾 — Knowledge-Base Github](https://github.com/SlowMist/Knowledge-Base) | analyses d'incidents Web3 ([base d'incidents](https://hacked.slowmist.io)) `[ZH/EN ; crypto]` |
|[tanjiti/sec_profile Github](https://github.com/tanjiti/sec_profile) | méta-index mensuel des publications de recherche sécurité chinoises (par source et par chercheur), très actif `[ZH]` |
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
|[RussianPanda — Yara-Rules Github](https://github.com/RussianPanda95/Yara-Rules) | règles YARA d'une chercheuse indépendante, forte cadence sur les stealers |
|[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | le dépôt canonique des règles Sigma |
|[splunk security_content](https://github.com/splunk/security_content) | détections et analytics Splunk (research.splunk.com) |
|[Sublime-Security rules](https://github.com/Sublime-Security/sublime-rules) | détection d'attaques par email (phishing, BEC, malware) |
|[The DFIR Report — Sigma Rules](https://github.com/The-DFIR-Report/Sigma-Rules) | règles Sigma issues d'investigations réelles |
|[bartblaze — Yara-rules Github](https://github.com/bartblaze/Yara-rules) | règles YARA de Bart Blaze |
|[ReversingLabs — YARA rules Github](https://github.com/reversinglabs/reversinglabs-yara-rules) | packs YARA de ReversingLabs |
|[Volexity Github](https://github.com/volexity/threat-intel) | signatures (YARA) et IOCs des billets de blog Volexity |
|[YARAHQ yara-forge](https://github.com/YARAHQ/yara-forge) | packs YARA consolidés et normalisés, publiés en releases |

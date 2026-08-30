# CTI-feeds
Liste de sources de renseignement concernant la menace d'origine cyber

> Dernière vérification des liens : 2026-08-30
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
|[Azure Sentinel Public feed](https://github.com/Azure/Azure-Sentinel) | dépôt massif du SIEM Microsoft ; IOCs et règles dispersés, il faut fouiller |
|[Bambenekconsulting.com](https://osint.bambenekconsulting.com) | feeds OSINT (DGA, C2) ; accès sur demande |
|[Bert-JanP Github](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds) | feeds OSS librement réutilisables (IP, URL, CVE, hash), très actif |
|[Bitdefender Github](https://github.com/bitdefender/malware-ioc)| IOCs des whitepapers Bitdefender, tenu à jour |
|[blocklist.de](https://www.blocklist.de) | IPs signalées via fail2ban par des serveurs participants (SSH, mail, web) |
|[Botvrij.eu](https://www.botvrij.eu) | IOCs OSINT au format MISP / CSV |
|[CINS Score / CI Army](https://cinsscore.com) | liste d'IPs à mauvaise réputation (CINS Active Threat Intelligence), gratuite |
|[Cisco Talos Github](https://github.com/Cisco-Talos/IOCs)| IOCs des publications Talos |
|[CyberCrime Tracker](https://cybercrime-tracker.net) | panels C2 de malware (Pony, Loki, etc.) |
|[cyberfury101 Gitlab](https://gitlab.com/Cyberfury101/deepdarkCTI) | copie de `deepdarkCTI`, inactive depuis 2021 ; préférer le dépôt fastfire |
|[DigitalSide Threat-Intel](https://osint.digitalside.it) ([mirror GitHub](https://github.com/davidonzo/Threat-Intel)) | IOCs OSINT (STIX / CSV / MISP) ; rythme ralenti depuis fin 2024 |
|[dragnet Github](https://github.com/dragnet-dev) | moteur d'agrégation `dragnet` public ; le repo de sorties `haul` (IOCs/Sigma/STIX) annoncé n'est pas encore publié |
|[drb-ra Github](https://github.com/drb-ra/C2IntelFeeds) | orienté C2, mise à jour quotidienne, très actif |
|[EcrimeLabs](https://ecrimelabs.net) | feeds fournis sur demande |
|[ESET Github](https://github.com/eset/malware-ioc/tree/master)| IOCs des investigations ESET ; mises à jour épisodiques |
|[fastfire Github](https://github.com/fastfire/deepdarkCTI) | collection deep et darkweb, très actif |
|[FGRibreau Github](https://github.com/FGRibreau/mailchecker) | détection d'emails jetables ; voir `list.txt` |
|[InfoSec Github](https://github.com/GithubInfosec/latest-malware-IoC)| IoC/IoA d'investigations InfoSec ; peu actif (dernière MAJ mi-2025) |
|[Malshare.com](https://malshare.com) | plateforme d'échantillons + IOCs ; inscription gratuite / clé API |
|[malware-traffic Github](https://github.com/malware-traffic/indicators)| IOCs de malware-traffic-analysis.net, classés par année |
|[Mandiant Github](https://github.com/mandiant/iocs)| archivé, IOCs de 2019 |
|[Meta Github](https://github.com/facebook/threat-research)| IOCs et indicateurs de détection, actif |
|[Mitre ATT&CK Github](https://github.com/mitre-attack/attack-stix-data) | données STIX du framework ATT&CK |
|[montysecurity Github](https://github.com/montysecurity) | voir `C2-Tracker` (archivé avril 2026) et les connecteurs OpenCTI |
|[Mr Looquer IOCs Feed](https://iocfeed.mrlooquer.com) | feed IPv4/IPv6 (JSON & CSV) ; dernières données fin 2023 |
|[Onetracker](https://onetracker.org/ti)| annuaire de ressources : échantillons, PCAP, images forensic, feeds, blocklists |
|[OpenPhish](https://openphish.com) / [PhishTank](https://phishtank.org) | URLs de phishing ; feeds communautaires gratuits (versions publiques limitées) |
|[Palo Alto Github](https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information)| IOCs liés aux articles Unit 42, actif ; remplace l'ancien repo `pan-unit42/iocs` |
|[pan-unit42 Github](https://github.com/pan-unit42) | org Unit 42 ; `pan-unit42/iocs` archivé, utiliser le repo Article-Information ci-dessus |
|[Phishing Army Feed](https://phishing.army) | blocklist de domaines liés au phishing (versions basic et extended) |
|[Prodaft Github](https://github.com/prodaft)| voir `malware-ioc` (IOCs d'investigations) et CRADLE (plateforme CTI) |
|[PulseDive](https://pulsedive.com) | plateforme CTI, plusieurs feeds ; compte gratuit disponible |
|[Ransomware.live Feeds](https://www.ransomware.live/api) | API victimes/groupes ransomware ; le plan gratuit permet 50 req/j |
|[RedDrip7 Github](https://github.com/RedDrip7)| `APT_Digital_Weapon` : IOCs APT catégorisés par QiAnXin (奇安信, Chine), actif |
|[rodanmaharjan Github](https://github.com/rodanmaharjan/ThreatIntelligence)| blocklist IOC pour MISP / pare-feu ; dernière MAJ sept. 2025 |
|[SANS ISC / DShield](https://isc.sans.edu) | IPs de scan et d'attaque, blocklists quotidiennes ([feeds](https://www.dshield.org/howto.html)) |
|[Shadowserver](https://www.shadowserver.org/what-we-do/network-reporting/) | ONG ; rapports quotidiens gratuits pour votre ASN / plage IP + [dashboard public](https://dashboard.shadowserver.org) |
|[sophoslabs Github](https://github.com/sophoslabs/IoCs)| IOCs issus des publications Sophos, actif |
|[Spamhaus DROP / EDROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | plages IP détournées ou contrôlées par des cybercriminels ; TXT / JSON |
|[spydisec Github](https://github.com/spydisec/spydithreatintel)| agrégat OSINT + blocklists communautaires, mise à jour quotidienne |
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
|[Citizen Lab — malware-indicators](https://github.com/citizenlab/malware-indicators) | IOCs des enquêtes Citizen Lab (Université de Toronto) sur le spyware mercenaire (Pegasus, Predator, Candiru…) |
|[MVT Project — mvt-indicators](https://github.com/mvt-project/mvt-indicators) | index d'IOCs (STIX) compatibles avec l'outil forensic [MVT](https://github.com/mvt-project/mvt) (iOS / Android), actif |

# Sources gouvernementales et étatiques
CERT / CSIRT nationaux et agences. Beaucoup publient leurs IOCs dans des avis web plutôt que dans des feeds structurés.

### France
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[CERT-FR / ANSSI](https://www.cert.ssi.gouv.fr/ioc) | feed IOCs officiel (+ MISP natif) ; outils DFIR sur [github.com/ANSSI-FR](https://github.com/ANSSI-FR) (DFIR-ORC, DFIR-OGRE) |
|[VIGINUM](https://github.com/VIGINUM-FR/Rapports-Techniques) | rapports techniques sur l'ingérence numérique étrangère (dernière MAJ sept. 2025) |

### Union européenne (institutions)
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[ENISA — EU CSIRTs Network (CNW)](https://github.com/enisaeu/CNW) | agrège les avis des CSIRT nationaux de l'UE + CERT-EU |
|[CERT-EU](https://cert.europa.eu/publications/threat-intelligence) | Threat Intelligence & security advisories ; [`droid`](https://github.com/certeu/droid) pour la gestion de règles Sigma |

### États membres de l'UE
|Pays|Source|Commentaire|
|----|------|-----------|
|Allemagne | [BSI / CERT-Bund](https://github.com/BSI-Bund) | honeypot MADCAT, Secvisogram (CSAF) ; avis de vulnérabilité sur [wid.cert-bund.de](https://wid.cert-bund.de) `[DE]` |
|Belgique | [CCB / CERT.be](https://cert.be) | avis de sécurité avec IOCs |
|Espagne | [CCN-CERT](https://www.ccn-cert.cni.es) | CERT du renseignement ; rapports APT et outils (souvent sur inscription) `[ES]` |
|Espagne | [INCIBE-CERT](https://www.incibe.es/en/incibe-cert) | avis, études et outils `[ES/EN]` |
|Estonie | [CERT-EE / RIA](https://github.com/cert-ee) | Cuckoo3, S4A detector et autres outils |
|Italie | [CERT-AGID](https://cert-agid.gov.it) | feed IOC quotidien (malware / phishing visant l'Italie) ; inscription requise `[IT]` |
|Lettonie | [CERT.LV](https://www.cert.lv/en/data-feed) | data feed national (sinkhole, IPs et domaines compromis) |
|Luxembourg | [CIRCL](https://www.circl.lu/doc/misp/feed-osint/) | feed MISP OSINT ; éditeur de MISP, AIL, Passive DNS/SSL ([github.com/CIRCL](https://github.com/CIRCL)) |
|Pays-Bas | [NCSC-NL](https://github.com/NCSC-NL) | dépôts d'IOCs et scripts de scan par campagne (Citrix, MOVEit, Zimbra…) |
|Pologne | [CERT Polska / CERT.pl](https://github.com/CERT-Polska) | mwdb, drakvuf-sandbox, karton, Artemis ; blocklist de domaines [hole.cert.pl](https://hole.cert.pl) |
|Suède | [CERT-SE](https://www.cert.se) | alertes et analyses `[SV/EN]` |
|Tchéquie | [NÚKIB](https://nukib.gov.cz/en/) | alertes, avertissements et rapports |

### Autres pays
|Pays|Source|Commentaire|
|----|------|-----------|
|Arabie saoudite | [Saudi CERT](https://cert.gov.sa) | avis et alertes de sécurité `[AR/EN]` |
|Australie | [ACSC / ASD](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories) | alertes et avis avec IOCs |
|Brésil | [CERT.br](https://cert.br) | honeypots, données spam, statistiques nationales `[PT/EN]` |
|Canada | [CCCS / Cyber Centre](https://github.com/CybercentreCanada) | AssemblyLine, extracteurs de config, outils SOC ; avis sur [cyber.gc.ca](https://www.cyber.gc.ca/en/alerts-advisories) |
|Chili | [CSIRT de Gobierno](https://csirt.gob.cl) | alertes et IOCs publiés très régulièrement `[ES]` |
|Chine | [CNCERT/CC](https://www.cert.org.cn/publish/english/index.html) | CERT national ; rapports et statistiques `[ZH ; page EN limitée]` |
|Chine | [CVERC](https://www.cverc.org.cn) | centre national de réponse aux virus `[ZH]` |
|Colombie | [colCERT](https://www.colcert.gov.co) | CERT national `[ES]` |
|Corée du Sud | [KrCERT / KISA](https://www.krcert.or.kr) | avis, takedown phishing/C2, rapports `[KO]` |
|Émirats arabes unis | [aeCERT](https://aecert.ae) | CERT national ; alertes et sensibilisation `[AR/EN]` |
|États-Unis | [CISA](https://github.com/cisagov) | liste `.gov`, catalogue [KEV](https://github.com/cisagov/kev-data), avis [CSAF](https://github.com/cisagov/CSAF) ; alertes sur [cisa.gov](https://www.cisa.gov/news-events/cybersecurity-advisories) |
|États-Unis | [CERT/CC (CMU SEI)](https://github.com/CERTCC) | coordination de divulgation (VINCE, SSVC, Vultron), outils d'analyse binaire |
|États-Unis | [DARPA — Transparent Computing / OpTC](https://github.com/FiveDirections/OpTC-data) | datasets de traces hôte/réseau annotées pour la recherche en détection APT (agence du DoD) |
|États-Unis | [IMPACT Cyber Trust](https://www.impactcybertrust.org) | place de marché de datasets de cybersécurité pour la recherche (financé par le DHS) |
|États-Unis | [Los Alamos National Laboratory](https://csr.lanl.gov/data/) | datasets host / auth / réseau, scénarios APT (laboratoire du DOE / NNSA) |
|États-Unis | [NSA Cybersecurity](https://github.com/nsacyber) | guides de durcissement et de détection, configurations |
|Inde | [CERT-In](https://www.cert-in.org.in) | CERT national : avis, notes de vulnérabilité, alertes |
|Inde | [CERT Mumbai (MH-CERT)](https://github.com/MH-CERT) | repo `Indicator-of-Compromise-IOC-` ; activité faible |
|Inde | [Cyber Swachhता Kendra (CSK)](https://www.csk.gov.in) | centre de nettoyage de botnets opéré par CERT-In ; outils et avis |
|Inde | [NCIIPC](https://nciipc.gov.in) | protection des infrastructures critiques ; bulletins avec IOCs `[EN ; accès surtout depuis l'Inde]` |
|Iran | [Maher / CERT.ir](https://cert.ir) | CERT national `[FA]` |
|Japon | [JPCERT/CC](https://github.com/JPCERTCC) | `phishurl-list`, `jpcert-yara`, `Contagious-Interview-IoCs`, `CobaltStrike-Config`, LogonTracer, EmoCheck |
|Kenya | [National KE-CIRT/CC](https://ke-cirt.go.ke) | CERT national ; avis et rapports |
|Maroc | [DGSSI / maCERT](https://www.dgssi.gov.ma) | avis et bulletins de sécurité `[FR/AR]` |
|Nouvelle-Zélande | [NCSC-NZ](https://www.ncsc.govt.nz) | avis et alertes (CERT NZ y a été intégré en 2024) |
|Oman | [OCERT](https://www.cert.gov.om) | CERT national ; alertes `[AR/EN]` |
|Royaume-Uni | [NCSC-UK](https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports) | rapports de menace avec IOCs ; packs de config sur [github.com/ukncsc](https://github.com/ukncsc) |
|Russie | [NKTsKI / GosSOPKA](https://safe-surf.ru) | CERT national (safe-surf.ru) ; portail russophone, accès limité `[RU]` |
|Suisse | [GovCERT.ch](https://github.com/govcert-ch/CTI) | dépôt `CTI` (IOCs et notes d'analyse), actif |
|Thaïlande | [TTC-CERT](https://github.com/ttc-cert) | CERT du secteur télécom : blocklist recommandée, règles Sigma/YARA, events MISP ; rien de neuf depuis 2024 |
|Turquie | [USOM](https://www.usom.gov.tr) | centre national ; [liste publique d'URLs/IPs malveillantes](https://www.usom.gov.tr/url-list.txt) `[TR]` |
|Ukraine | [CERT-UA](https://cert.gov.ua) | publication d'IOCs très prolifique (activité APT russe) ; articles détaillés + MISP `[UA/EN]` |
|Uruguay | [CERTuy](https://www.cert.uy) | CERT national `[ES]` |

### Réseaux régionaux
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[AfricaCERT](https://www.africacert.org) | organisation régionale des CSIRT africains |
|[OEA — CSIRTAmericas](https://csirtamericas.org) | réseau des CSIRT nationaux des Amériques (Organisation des États américains) `[ES/EN/PT]` |

# Éditeurs et laboratoires de recherche privés
Blogs et publications de recherche des éditeurs de sécurité (IOCs et TTPs dans les billets).
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[360 Netlab](https://blog.netlab.360.com) (Chine) | feeds C2 / DGA / botnet historiques ; peu actif depuis 2022 `[ZH/EN]` |
|[AhnLab ASEC](https://asec.ahnlab.com/en/) (Corée du Sud) | blog très prolifique (Kimsuky, Lazarus, malware ciblant l'Asie) `[KO ; blog EN]` |
|[Antiy Labs / 安天](https://www.antiy.net) (Chine) | rapports APT `[ZH ; certains rapports EN]` |
|[BI.ZONE](https://bi.zone) (Russie) | recherche menaces (groupe Sber) ; lib [`bi-zone/bizone-ti-lib`](https://github.com/bi-zone/bizone-ti-lib) `[EN/RU]` |
|[CloudSEK](https://www.cloudsek.com/blog) (Inde) | recherche menaces, fuites, surface d'attaque `[EN]` |
|[Cyble](https://cyble.com/blog/) (Inde / États-Unis) | recherche menaces très prolifique `[EN]` |
|[CronUp](https://www.cronup.com/blog/) (Chili) | threat intel centrée Amérique latine `[ES]` |
|[CYFIRMA](https://www.cyfirma.com/research/) (Inde / Singapour) | rapports d'attribution et de campagne `[EN]` |
|[Doctor Web / Dr.Web](https://news.drweb.com) (Russie) | analyses de malware avec IOCs `[RU/EN]` |
|[F6](https://www.f6.ru) (ex-F.A.C.C.T., Russie) | cybercriminalité russophone `[RU]` |
|[Group-IB](https://www.group-ib.com/blog/) (Singapour) | e-crime, rapports détaillés avec IOCs `[EN]` |
|[K7 Labs](https://labs.k7computing.com) (Inde) | analyses de malware (éditeur AV de Chennai) `[EN]` |
|[Kaspersky — Securelist](https://securelist.com) (Russie) | équipe GReAT, IOCs par rapport `[EN]` |
|[Kaspersky ICS-CERT](https://ics-cert.kaspersky.com) (Russie) | spécialisé OT / ICS `[EN]` |
|[Macnica Security Research](https://security.macnica.co.jp/) (Japon) | rapports APT visant le Japon `[JP]` |
|[Metabase Q — Ocelot](https://www.metabaseq.com) (Mexique) | recherche menaces centrée Amérique latine `[EN/ES]` |
|[Microsoft — Security Blog / MSTIC](https://www.microsoft.com/en-us/security/blog/) (États-Unis) | rapports et analyses `[EN]` |
|[nao-sec](https://nao-sec.org) (Japon) | collectif de recherche : analyses, outils (RTF weaponizer decoder…) `[JP/EN]` |
|[NSFOCUS / 绿盟](https://nsfocusglobal.com/blog/) (Chine) | rapports APT `[EN (global) / ZH]` |
|[Positive Technologies — PT ESC](https://github.com/PositiveTechnologies) (Russie) | recherche menaces ; règles Suricata figées 2022 sur [`ptresearch/AttackDetection`](https://github.com/ptresearch/AttackDetection) `[EN/RU]` |
|[QiAnXin TI Center / 奇安信](https://ti.qianxin.com) (Chine) | portail Threat Intelligence ; voir aussi [RedDrip7](https://github.com/RedDrip7) `[ZH]` |
|[Sekoia.io](https://blog.sekoia.io) (France) | recherche menaces, TDR `[EN/FR]` |
|[Seqrite Labs / Quick Heal](https://www.seqrite.com/blog/) (Inde) | fort sur les APT d'Asie du Sud (SideCopy, Transparent Tribe…) `[EN]` |
|[Sequretek](https://www.sequretek.com/resources/threat-advisory) (Inde) | avis de menace `[EN]` |
|[Solar 4RAYS](https://solar4rays.ru) (Russie) | bulletins d'IOCs (groupe Rostelecom) `[RU]` |
|[TeamT5](https://teamt5.org/en/) (Taïwan) | recherche APT nexus-Chine `[EN/ZH]` |
|[ThreatBook / 微步在线](https://threatbook.io) (Chine) | éditeur TI ; lookups communautaires gratuits sur [x.threatbook.com](https://x.threatbook.com) `[EN/ZH]` |
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
|[VirusShare](https://virusshare.com) | vaste corpus de malware ; accès chercheurs sur demande |

# Rapports, analyses, informations
Méta-listes, agrégateurs et bibliothèques de rapports.
|Source                                                                            |Commentaire         |
|----------------------------------------------------------------------------------|--------------------|
|[APTnotes](https://github.com/aptnotes/data) | archive historique de rapports APT publics ; figée fin 2024 |
|[despacito420 Github](https://github.com/despacito420/The-Feed)| liste curée d'articles SOC/DFIR/CTI ; activité faible (dernière MAJ janv. 2026) |
|[devsecops Github](https://github.com/devsecops/awesome-devsecops) | liste d'outils DevSecOps (dont CTI) ; figée depuis 2024 |
|[EndlessFractal Github](https://github.com/EndlessFractal/Threat-Intel-Feed)| agrégation et consolidation automatiques de feeds, actif |
|[ETDA / ThaiCERT APT Encyclopedia](https://apt.etda.or.th) | fiches détaillées de groupes et d'outils APT |
|[hslatman Github](https://github.com/hslatman/awesome-threat-intelligence)| liste de référence des ressources CTI |
|[infoblox Github](https://github.com/infobloxopen/threat-intelligence) | IOCs et rapports Infoblox (threat intel DNS), actif |
|[Malpedia](https://malpedia.caad.fkie.fraunhofer.de) | familles de malware, règles YARA, références (Fraunhofer FKIE) ; compte gratuit |
|[mdecrevoisier Github](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | 270+ échantillons EVTX mappés ATT&CK, pour mesurer la couverture SIEM |
|[Midnight Slayer](https://start.me/p/wMPxqX/cyber-threat-intelligence)| tableau de bord start.me ; bloque les robots, ouvrir dans un navigateur |
|[MITRE ATT&CK — Groups & Software](https://attack.mitre.org/groups/) | complément « lisible » des données STIX : fiches groupes et logiciels |
|[mthcht Github](https://github.com/mthcht) | voir `awesome-lists` (SOC/CERT/CTI) et `ThreatIntel-Reports`, très actif |
|[NetManageIT instance publique OpenCTI](https://opencti.netmanageit.com) | instance OpenCTI publique en lecture seule ; actuellement hors ligne (2026) |
|[ORKL](https://orkl.eu) | bibliothèque de rapports CTI / APT indexés et cherchables + API |
|[RST Cloud — awesome-threat-actor-resources](https://github.com/rstcloud/awesome-threat-actor-resources) | méta-liste de profils d'acteurs et de datasets APT publics |
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

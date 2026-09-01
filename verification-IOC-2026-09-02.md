# Vérification empirique du tag `IOC` — 2026-09-02

## Règle appliquée

Une source reçoit le tag `IOC` **uniquement** si l'une de ces preuves a été obtenue :

1. **Dépôt ou feed d'IOC** (GitHub, TXT/CSV/JSON/MISP) dont le contenu a été vu — preuve directe ;
2. **Sonde de crawl** : page d'accueil + jusqu'à 25–40 pages internes (avis/blog), texte visible uniquement (scripts, styles et attributs HTML retirés pour éviter les hash d'assets) ; seuil : ≥ 3 SHA-256 distincts, ou ≥ 10 IP publiques distinctes, ou des indicateurs défangés (`[.]`, `hxxp`), ou ≥ 5 mentions « IOC / Indicators of Compromise » accompagnées d'au moins un hash/IP ;
3. **Sonde RSS** : flux complet ou 6–8 derniers articles, mêmes critères.

Tout le reste est `RENS`, même quand la source est réputée publier des IOC (ASEC avant sonde ciblée, Intrinsec, SOCRadar…). La mention « IOC non vérifiés » dans le commentaire signale les cas où la sonde n'a pas pu conclure (site JavaScript, blocage des robots, IOC en PDF ou en image) : un contrôle humain peut faire remonter la source en `IOC`.

## Résultats — CERT nationaux

| Source | Preuve | Verdict |
|---|---|---|
| CERT-FR | page `/ioc` documente le feed MISP TLP:CLEAR | IOC+RENS |
| ENISA CNW | 103 SHA-256 dans `advisories/` | IOC+RENS |
| CERT-EU | 10 SHA-256 dans les Cyber Briefs | IOC+RENS |
| CERT-AGID | 156 mentions IOC + feed sur inscription | IOC+RENS |
| CERT.LV | page « data feed » (contenu réservé) | IOC (feed sur demande) |
| NCSC-NL | 168 SHA-256 dans les dépôts | IOC |
| CERT Polska | 20 SHA-256, 12 IP dans les posts ; hole.cert.pl | IOC+RENS |
| CCCS | 103 IP dans les alertes | IOC+RENS |
| NCSC-UK | 12 SHA-256 dans les threat reports | IOC+RENS |
| GovCERT.ch | 79 SHA-256 dans le dépôt CTI | IOC+RENS |
| CERT-UA | sections « Індикатори компрометації » avec URL défangées (article 39882 et suivants) ; MISP sur demande | IOC+RENS |
| CERT-PY | 91 IP dans les notifications `malware_url` | IOC+RENS |
| CISA | 101 SHA-256 dans les advisories | IOC+RENS |
| JPCERT/CC | dépôts + 162 SHA-256 sur le blog | IOC+RENS |
| NCSC-NZ | 6 IP dans les alertes (Zimbra) | IOC+RENS (ponctuel) |
| TTC-CERT (TH) | dépôt blocklist + events MISP, figé 2024 | IOC |
| USOM | `url-list.txt` redirige vers l'API Swagger de siberguvenlik.gov.tr : **liste publique morte** | RENS — **corriger l'entrée** |
| CERT.at, INCIBE, NCSC-FI, CERT.br, HKCERT, CERT-In, CSK, KrCERT, SK-CERT, NÚKIB, CSIRT Bolivia, OCERT, NCSC-JO, Q-CERT, DGSSI, NCSC-IE, CERT-SE, SI-CERT, CERT.TJ, KZ-CERT, Sri Lanka CERT, TWCERT, フィッシング対策協議会 | aucun hash/IP dans le texte visible ; KrCERT, TWCERT, CERT-In, 360 : sites JS (1 page) | RENS (« IOC non vérifiés » pour les sites JS) |
| CCB, CCN-CERT, ACSC, BGD CIRT, CSIRT Chile, Saudi CERT, aeCERT, KE-CIRT, CNCS | injoignables au robot | RENS, « non vérifié » |

## Résultats — éditeurs et blogs (sonde crawl, 25 pages)

| Verdict | Sources (preuve principale) |
|---|---|
| **IOC+RENS** | Symantec (54 sha), Fortinet (39), Proofpoint (17), Trend Micro (19 IP, 24 kw), Talos (19), Unit 42 (118), Check Point (40), Google TI (21), MSTIC (12), SentinelLABS (4), Securelist (115 MD5, 229 défangés sur 6 articles), ThreatFabric (75), Cleafy (2 sha, 8 kw — ponctuel), WithSecure (15), Gen/Avast (28), Netskope (12 sha via RSS + dépôt), Huntress (11), Wiz (109 IP), Rapid7 (17 IP), Arctic Wolf (6), Malwarebytes (23), eSentire (5), Deep Instinct (3), Sucuri (23 IP), LevelBlue (16), Trinity Cyber (46), Silent Push (34 IP, 73 kw), Validin (10 IP), Hunt.io (107 sha, 54 IP), Team Cymru (12 sha, 16 IP), GreyNoise (9 IP, 17 kw), Viettel (4 sha, 8 IP, 40 kw), Certego (4), Fox-IT (325), G DATA (39), Acronis TRU (42), TEHTRIS (74), TeamT5 (3 sha, 83 kw), Genians (51 MD5, 68 défangés), ESRC/alyac (3 IP, 5 kw — ponctuel), NSHC (24), IIJ-SECT (22), Macnica (8), ITOCHU (197), CloudSEK (8 sha, 16 IP), Cyble (10), CYFIRMA (5), Seqrite (8), DBAPPSecurity (35), Dr.Web (81 défangés), Group-IB (67), DFIR Report (24 sha, 44 IP), JPCERT blog (162), nao-sec (19), WeLiveSecurity (11), Aqua (6 sha, 15 défangés), Sygnia (2 sha, 4 kw — ponctuel), Censys (59 sha via RSS), NVISO (10 via RSS), Oneconsult (5 via RSS), Cybereason (4 défangés, 22 kw), ASEC (5 MD5, 3 kw sur 8 articles), Antiy (5 MD5, 2 IP), Zimperium (dépôt IOC), Sekoia (dépôt Community), QiAnXin (dépôt RedDrip7), Elastic (dépôt labs-releases), Bitdefender / ESET / Sophos / Zscaler / Talos / Meta / Infoblox / HarfangLab / Volexity (dépôts) |
| **RENS** (aucune preuve) | Intrinsec (35 kw, 0 hash — IOC en PDF), Zimperium blog seul, Lookout, Dragos, Claroty, Nozomi, ReliaQuest, Morphisec, Red Canary, Uptycs, SonicWall, WatchGuard, SecurityScorecard, DomainTools, Bitsight, Netcraft, Cofense, Abnormal, Barracuda, INKY, KnowBe4, Validity, Mailgun, Cloudmark, IRONSCALES, Kaspersky ICS-CERT (IOC en PDF), SektorCERT, AWS, CERT Orange PL, Yoroi, Lab52, NCC Group, Northwave, Tesorion, ClearSky, KELA, HiSolutions, Threatray, Access Now, CyCraft, TXOne, ENKI, S2W, LAC, MBSD, NRI Secure, Hitachi HIRT, K7, CronUp, Metabase Q, ISH, CTM360 (42 kw, 0 hash), NSFOCUS, 360, ThreatBook (37 kw, 0 hash), BI.ZONE, Aryaka, Brandefense, SOCRadar (111 kw, 0 hash), Intel 471, Flashpoint, Varonis (1 sha, 5 IP — insuffisant), ExtraHop, Positive Technologies (règles figées 2022), wizSafe, F6, Solar (injoignables) |

## Enseignement

Le nombre de mentions « IOC » ne prédit pas la présence d'observables : SOCRadar (111 mentions, 0 hash), CTM360 (42, 0), ThreatBook (37, 0), Intrinsec (35, 0) parlent d'IOC sans les publier dans le texte — ils sont dans des PDF, des plateformes payantes ou des images. À l'inverse, Fox-IT, ITOCHU, Unit 42 ou Hunt.io livrent des centaines de hash en clair. C'est cette seconde catégorie qui mérite le tag.

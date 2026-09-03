# OpenCTI — Portal Kombat (rapport 1)

- **Report** : `report--cc400dae-3f6d-5e82-85b5-b1e2949ae41f`
- **Source du bundle** : `VIGINUM-FR/Rapports-Techniques/202402 - Portal Kombat/…_full.json`
- **Poussé le** : 2026-09-03 · **auteur** : VIGINUM · **TLP:CLEAR** (rattaché a posteriori — le bundle ne l'a pas propagé au Report)
- **Contenu** : 1 Report (~1617 objets) · Campaign **Portal Kombat** + Campaign **RRN**
  (alias *Doppelgänger*) · Intrusion-Set « Creation and use of a web infrastructure
  targeting local audiences » · **534 channels** (portails du réseau) · 21 techniques
  **DISARM** · 3 narratives · 1 event (invasion de l'Ukraine) · identités :
  Krymtechnologii, InfoRos, TigerWeb, Denis SHEVCHENKO, Yevgeny SHEVCHENKO,
  Mikhail GAMANDIY-EGOROV · 13 IPv4 · 2 domaines · 1 infrastructure · 1 AS
- **Description** : celle de VIGINUM (bundle), conservée.
- **Écarts** : marquage TLP:CLEAR absent à l'import, rattaché manuellement. Couvre le
  **1er** des 3 rapports Portal Kombat (12/02/2024). Les rapports 2 (14/02/2024) et
  3 (29/04/2024) sont en groupe B — voir `articles/`.

## Rapports 2 et 3 (groupe B, ajoutés le 2026-09-03)

- **Report PK2** `report--9ac37c89-2e4f-5003-9bca-c4412066d41b` (14/02/2024) —
  rattaché au Campaign « Portal Kombat ». +identités : TigerWeb (org),
  Evgueni CHEVTCHENKO, Denis CHEVTCHENKO, Krymtechnologii, Inforos,
  Mikhail GAMANDIY-EGOROV. Relations : CHEVTCHENKO→TigerWeb→Campaign,
  TigerWeb↔Inforos, RRN→Campaign (amplification).
- **Report PK3** `report--3ec31e41-4c27-5f0e-b828-de622bf50c99` (29/04/2024) —
  **224 domaines** du réseau (annexe) + infrastructure/IPv4 `178.21.15.85` (AS49352).
- MISP : event 2292 « VIGINUM — Portal Kombat (IOC contextuels) », 224 domaines + 1 IP, `to_ids=False`.
- Note : les 3 rapports Portal Kombat partagent le **même Campaign** dans OpenCTI
  (déduplication STIX par nom). PK1 vient du bundle STIX VIGINUM, PK2/PK3 de l'extraction PDF.

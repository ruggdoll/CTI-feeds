# OpenCTI — Storm-1516

- **Report** : `report--accf38a0-69b1-5b0e-8203-5fd25e110f28` (890 objets liés) ·
  Intrusion-Set `intrusion-set--5f35c893-8adb-54c0-bfdf-c27fbcf27adb`
- **Source** : bundle construit à la main depuis le rapport (pas d'annexe STIX VIGINUM) —
  `viginum/build_storm1516.py`
- **Poussé le** : 2026-09-03 · **auteur** : VIGINUM · **TLP:CLEAR**
- **Contenu** (252 objets) :
  - Intrusion-Set **Storm-1516** (alias *Neva Flood*)
  - 17 identités : DOUGAN (*badvolf*), KOROVINE, KHOROCHENKY, SAVINE, ANISSIMOV,
    VOVK/TERADA, BOWES, BOÏKOV ; CEG, Evrazia, FCI, BJA, Projet Lakhta,
    GRU Unit 29155, RIA FAN, Nova Resistência
  - Infrastructure **CopyCop** (alias *MAGAstan*, *False Façade*) + **300 domaines** (annexe 6.2, extraits par pdftotext)
  - 74 techniques **DISARM** (annexe 6.4, T-codes) reliées à l'Intrusion-Set
  - Intrusion-Sets liés : RRN/*Doppelgänger*, Portal Kombat, Mriya (`related-to`)
  - 124 relations (`attributed-to`, `related-to`, `part-of`, `uses`, `communicates-with`)
- **IOC** : annexes 6.2 (300 domaines CopyCop) + 6.3.1 (22 médias de blanchiment) +
  6.3.2 (16 sites + 32 comptes X/Telegram) — **totalité importée** (texte PDF, pas image).
  Également versés dans **MISP** : event 2291 « VIGINUM — Storm-1516 (IOC contextuels) »,
  369 attributs `to_ids=False`, tag `opencti-bridge="skip"`.
- **Écarts / limites** :
  - **77 opérations** (annexe 6.1) : non modélisées individuellement — listées dans `articles/`.
  - Modélisé en `intrusion-set` (et non `campaign` + `threat-actor` comme le bundle RRN de VIGINUM)
    car un « mode opératoire informationnel » recouvre un ensemble de comportements/ressources.

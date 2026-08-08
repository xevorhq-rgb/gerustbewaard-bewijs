# GerustBewaard — publieke bewijs-spiegel

**Wat dit is:** de openbare, controleerbare bewijslaag van het GerustBewaard-woningarchief:
hash-ketens (V1 bevroren + V2 actief) en OpenTimestamps-zegels waarmee iedereen kan
nagaan dat het archief sinds elke zegel-datum niet stiekem is veranderd.

**Wat dit uitdrukkelijk NIET is: een archief-backup.** `git clone` van deze repository
herstelt het woningarchief niet. De broninventaris en de echte data blijven prive
opgeslagen; deze spiegel publiceert uitsluitend ondoorzichtige hashes en bewijzen.

## Zelf controleren (een commando)
```
python3 tools/verify.py
```

## Wat de publieke controle wel en niet bewijst
- WEL: dat de gepubliceerde bestanden intern kloppen (manifest), dat elk V1-bewijs
  exact het bestand is dat destijds is verzegeld (`.ots`), en dat de V2-keten van
  payload-hash naar payload-hash ononderbroken doorloopt vanaf GENESIS_V2.
- NIET: de inhoud achter die payload-hashes. De keten controleert verbintenissen
  (commitments); de onderliggende archief-inhoud zelf is niet openbaar.
- `ARCHIVE-COMMITMENT.txt` verankert het volledige prive-manifest (elke byte van het
  archief) als een verbintenis, zonder iets over de inhoud prijs te geven.

## Eerlijke Bitcoin-status (stand 2026-07-27, 23 zegels)
De zegels bevatten Bitcoin-attestaties, maar zijn hier nog niet onafhankelijk tegen een
eigen Bitcoin-node geverifieerd. De verifier toont dat eerlijk: BITCOIN wordt pas
VERIFIED (en de eindstatus pas GREEN) na een succesvolle `ots verify`; tot die tijd is
de eindstatus AMBER. Fouten geven RED.

## Bevroren volledige geschiedenis
De volledige historische Git-geschiedenis van het archief is bevroren in een bundle
met sha256:
`5cfe4d6a20a1787974d0e7245c08351712a89c768c04c760c1ec7f55a7ed7e7c`
Wie een kopie van die bundle ontvangt, kan met deze hash bewijzen dat hij de echte is.

## Inhoud
- `BEWIJS.log` + `bewijs/` — V1-keten en dagzegels (`.txt` + `.ots`)
- `bewijs_v2/GENESIS_V2.txt` (+ `.ots`) — het verankerde startpunt van keten V2
- `bewijs_v2/keten-export.tsv` — de V2-schakels (run, tijd, hashes; zonder payload)
- `ARCHIVE-COMMITMENT.txt` — verbintenis aan het volledige prive-manifest
- `ots-verwacht.tsv` — de in elk `.ots` gestempelde sha256
- `MANIFEST.sha256` — sha256+bytes van alle bestanden in deze export
- `tools/verify.py` — de controle hierboven

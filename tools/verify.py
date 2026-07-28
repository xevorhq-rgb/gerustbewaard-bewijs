#!/usr/bin/env python3
"""Publieke verifier van de GerustBewaard bewijs-spiegel:
    python3 tools/verify.py
Rapporteert apart: INTEGRITEIT (manifest + V1 vs .ots), V2-KETEN (publieke schakels),
BITCOIN (eerlijke OTS-status) en een EINDSTATUS. GREEN kan alleen wanneer de
Bitcoin-verankering onafhankelijk is geverifieerd (`ots verify` exit 0); tot die tijd
is de eindstatus hoogstens AMBER. Fouten geven RED (exit 1).
Let op: de keten bewijst de schakels tussen de gepubliceerde payload-hashes; de
verborgen payload-inhoud zelf valt buiten deze publieke controle."""
import os, sys, hashlib, shutil, subprocess

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()
def sha_text(s): return hashlib.sha256(s.encode()).hexdigest()

fouten = []

# --- INTEGRITEIT: manifest + V1 vs .ots ---
n_m = 0
for regel in open(os.path.join(R, "MANIFEST.sha256")):
    if regel.startswith("#"): continue
    loc, sha, size, pad = regel.rstrip("\n").split("\t")
    n_m += 1
    vol = os.path.join(R, pad)
    if not os.path.exists(vol): fouten.append("ontbreekt: " + pad); continue
    if sha_file(vol) != sha or str(os.path.getsize(vol)) != size:
        fouten.append("hash/grootte-afwijking: " + pad)
ots = shutil.which("ots")
verwacht = {}
for regel in list(open(os.path.join(R, "ots-verwacht.tsv")))[1:]:
    pad, sha = regel.rstrip("\n").split("\t"); verwacht[pad] = sha
for pad, sha in sorted(verwacht.items()):
    txt = os.path.join(R, pad)
    if ots:
        info = subprocess.run([ots, "info", txt + ".ots"], capture_output=True, text=True).stdout
        kand = [l for l in info.splitlines() if "File sha256" in l]
        if kand: sha = kand[0].split()[-1]
    if sha_file(txt) != sha:
        fouten.append("V1 wijkt af van .ots: " + pad)
int_fouten = len(fouten)
print(f"INTEGRITEIT: {'PASS' if not int_fouten else 'FAIL'} "
      f"(manifest {n_m} bestanden; V1-vs-.ots {len(verwacht)} zegels; bron: {'ots-CLI' if ots else 'ots-verwacht.tsv'})")

# --- V2-KETEN (publieke schakels; formule: keten = sha256(prev|run_id|ts|payload)) ---
rows = [r.rstrip("\n").split("\t") for r in list(open(os.path.join(R, "bewijs_v2", "keten-export.tsv")))[1:]]
prev = None; kfout = 0
for i, (rid, ts, prevk, ph, keten) in enumerate(rows):
    if i == 0:
        if rid != "GENESIS_V2" or prevk != "" or keten != ph:
            kfout += 1; fouten.append("V2 genesis-schakel klopt niet")
        gen = open(os.path.join(R, "bewijs_v2", "GENESIS_V2.txt")).read().splitlines()
        if sha_text(gen[0]) != ph or gen[1] != keten:
            kfout += 1; fouten.append("GENESIS_V2.txt komt niet overeen met de keten")
    else:
        if prevk != prev or sha_text("|".join([prevk, rid, ts, ph])) != keten:
            kfout += 1; fouten.append(f"V2 schakel {i+1} ({rid}) klopt niet")
    prev = keten
print(f"V2-KETEN: {'PASS' if not kfout else 'FAIL'} ({len(rows)} schakels herrekend vanaf GENESIS_V2; "
      "payload-inhoud zelf is niet openbaar en valt buiten deze controle)")

# --- BITCOIN (eerlijk) ---
btc = "NIET BEPAALD (ots-CLI ontbreekt)"; btc_klasse = "ONBEKEND"
if ots:
    telling = {"VERIFIED": 0, "ATTESTED_UNVERIFIED": 0, "PENDING": 0, "ERROR": 0}
    for pad in sorted(verwacht):
        f = os.path.join(R, pad + ".ots")
        info = subprocess.run([ots, "info", f], capture_output=True, text=True)
        ver = subprocess.run([ots, "verify", f], capture_output=True, text=True)
        uit = ver.stdout + ver.stderr
        if "does not match" in uit.lower(): telling["ERROR"] += 1
        elif ver.returncode == 0: telling["VERIFIED"] += 1
        elif "bitcoin block" in info.stdout.lower() and "could not connect" in uit.lower():
            telling["ATTESTED_UNVERIFIED"] += 1
        elif "bitcoin block" not in info.stdout.lower(): telling["PENDING"] += 1
        else: telling["ERROR"] += 1
    if telling["ERROR"]: btc_klasse = "ERROR"; fouten.append("OTS ERROR aanwezig")
    elif telling["VERIFIED"] == len(verwacht): btc_klasse = "VERIFIED"
    elif telling["ATTESTED_UNVERIFIED"]: btc_klasse = "ATTESTED_UNVERIFIED"
    else: btc_klasse = "PENDING"
    btc = " ".join(f"{k.lower()}={v}" for k, v in telling.items())
print(f"BITCOIN: {btc_klasse} ({btc})")

# --- EINDSTATUS ---
if fouten:
    eind = "RED"
elif btc_klasse == "VERIFIED":
    eind = "GREEN"
else:
    eind = "AMBER"
print(f"EINDSTATUS: {eind}" + ("" if not fouten else " — " + "; ".join(fouten[:5])))
sys.exit(1 if eind == "RED" else 0)

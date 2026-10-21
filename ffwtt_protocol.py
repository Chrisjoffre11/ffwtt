#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ffwtt_protocol.py — Codec du protocole FFWorld Triple Triad (client v3.3.3).

Etabli par retro-ingenierie du client + capture d'une session reelle.

TRAME :
    [ longueur : uint16 LITTLE-ENDIAN ][ opcode : uint16 BIG-ENDIAN ][ champs ]
    (la longueur couvre opcode + champs)

CHAMPS (dans la charge utile) :
    0x01  chaine : 0x01 [longueur uint16 LE XOR 0x55DE] [caracteres]
                   caractere[i] = clair[i] XOR (0x4F + i)
    0x03  entier : 0x03 [uint32 LE]
    (d'autres types existent — a completer selon besoin)

Ce module fournit l'encodage ET le decodage, pour lire des captures comme pour
ecrire un serveur.
"""
import struct

XOR_START = 0x4F      # cle de depart du chiffre de chaine (s'incremente par caractere)
LEN_XOR   = 0x55DE    # masque applique a la longueur (uint16)

# ---------- chiffrement de chaine ----------
def encode_string(s: str) -> bytes:
    raw = s.encode("latin1")
    enc = bytes((c ^ ((XOR_START + i) & 0xFF)) for i, c in enumerate(raw))
    ln  = (len(raw) & 0xFFFF) ^ LEN_XOR
    return b"\x01" + struct.pack("<H", ln) + enc

def decode_string(buf: bytes, off: int):
    """Lit un champ chaine a partir de buf[off] (qui doit valoir 0x01).
    Retourne (texte, nouvel_offset)."""
    assert buf[off] == 0x01, "pas un champ chaine"
    ln = struct.unpack("<H", buf[off+1:off+3])[0] ^ LEN_XOR
    start = off + 3
    enc = buf[start:start+ln]
    txt = "".join(chr(b ^ ((XOR_START + i) & 0xFF)) for i, b in enumerate(enc))
    return txt, start + ln

# ---------- champs ----------
def decode_fields(payload: bytes):
    """Decoupe la charge utile (apres l'opcode) en champs lisibles.
    Retourne une liste de tuples ('str'|'int'|'raw', valeur)."""
    out = []; i = 0; n = len(payload)
    # eventuel octet de contexte en tete (canal / categorie)
    if n and payload[0] not in (0x01, 0x03):
        out.append(("ctx", payload[0])); i = 1
    while i < n:
        t = payload[i]
        if t == 0x01 and i + 3 <= n:
            try:
                txt, i = decode_string(payload, i); out.append(("str", txt)); continue
            except Exception:
                pass
        if t == 0x03 and i + 5 <= n:
            val = struct.unpack("<I", payload[i+1:i+5])[0]; out.append(("int", val)); i += 5; continue
        if t == 0x06 and i + 2 <= n:
            out.append(("byte", payload[i+1])); i += 2; continue
        if t == 0x04 and i + 3 <= n:
            out.append(("int16", struct.unpack("<H", payload[i+1:i+3])[0])); i += 3; continue
        out.append(("raw", payload[i:].hex())); break
    return out


# ---------- version du client (op5) ----------
# Le client envoie op5 « u(version) » des qu'il recoit op4 ; le serveur repond op6 « b(1) » (« Session initialisee »)
# ou « b(0) » (« Vous ne possedez pas la bonne version de FFWTT », cas 6 du client, 0x63A162). Capture :
# op5 = 00 03 11346001, op6 = 00 06 01. FFWTT.exe v3.3.3.6065 envoie 23082001 (immediat a 0x63A00B) et connait 4885
# cartes.
VERSION_CLIENT = 23082001
CARTES_CLIENT = 4885

def cartes_du_client(version: int) -> int:
    """Plus grand identifiant de carte que connait le client qui a annonce cette version."""
    return CARTES_CLIENT


# ---------- aides de construction de champs ----------
def field_str(s: str) -> bytes:   return encode_string(s)
def field_int(v: int) -> bytes:   return b"\x03" + struct.pack("<I", v & 0xFFFFFFFF)
def field_byte(v: int) -> bytes:  return b"\x06" + bytes([v & 0xFF])
def field_v(v: int) -> bytes:     return b"\x05" + bytes([v & 0xFF])  # champ "valeur" 1 octet (jeu)
def field_int16(v: int) -> bytes: return b"\x04" + struct.pack("<H", v & 0xFFFF)

# ---------- trame ----------
def build_frame(opcode: int, payload: bytes = b"") -> bytes:
    body = struct.pack(">H", opcode) + payload      # opcode BIG-ENDIAN
    return struct.pack("<H", len(body)) + body      # longueur LITTLE-ENDIAN

def parse_frames(buf: bytearray):
    """Extrait toutes les trames completes de buf (le modifie). Rend une liste
    de (opcode, payload)."""
    res = []
    while len(buf) >= 2:
        ln = struct.unpack("<H", buf[:2])[0]
        if len(buf) < 2 + ln: break
        body = bytes(buf[2:2+ln]); del buf[:2+ln]
        if len(body) >= 2:
            op = struct.unpack(">H", body[:2])[0]
            res.append((op, body[2:]))
    return res

def build_string_msg(opcode: int, *strings, ctx: int = None) -> bytes:
    """Aide : construit une trame opcode + chaines (avec octet de contexte optionnel)."""
    payload = b"" if ctx is None else bytes([ctx])
    for s in strings:
        payload += encode_string(s)
    return build_frame(opcode, payload)


if __name__ == "__main__":
    # Demonstration : decodage de trames au format du fil (nom du serveur, identifiants et adresse fictifs)
    print("=== Verification du codec sur des trames du fil ===\n")
    samples = [
        ("op4 accueil (S->C)", 4,   bytes.fromhex("0001d455023f3f0136262333222a")),
        ("op100 LOGIN (C->S)", 100, bytes.fromhex("0001d855053f2437262601d8553c3532203620")),
    ]
    for label, op, payload in samples:
        print(f"{label} : opcode={op}")
        for kind, val in decode_fields(payload):
            print(f"    {kind}: {val!r}")
        print()

    # Aller-retour encode/decode
    m = build_string_msg(100, "Joueur", "secret", ctx=0)
    print("re-encode op100(Joueur,secret) =", m.hex())
    op, pl = parse_frames(bytearray(m))[0]
    print("re-decode ->", op, decode_fields(pl))

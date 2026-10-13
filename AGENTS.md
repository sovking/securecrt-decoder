# AGENTS.md - Developer & Agent Guide for SecureCRT Password Decoder

Questo file descrive l'architettura, le convenzioni, le specifiche crittografiche e le linee guida operative per gli agenti AI e i contributori umani che lavorano su questa codebase.

> **Puntatori e Documentazione Correlata:**
> - Per lo stato di avanzamento, le attività pianificate e la roadmap: consultare [TODO.md](file:///home/gabriele/mySoftware/secureCRT-password-decoder/TODO.md).
> - Per la guida all'uso per l'utente finale e l'installazione: consultare [README.md](file:///home/gabriele/mySoftware/secureCRT-password-decoder/README.md).

---

## 1. Panoramica del Progetto

`securecrt-decoder` è un'applicazione CLI autonoma in Go (pure-Go, zero dipendenze CGO) per l'analisi dei file `.ini` di sessione di SecureCRT, l'estrazione dei metadati di connessione e la decodifica delle password salvate (versioni v1, v2 `02` e v2 `03`) o l'individuazione della chiave privata SSH.

---

## 2. Struttura del Progetto

La codebase segue il layout standard idiomatico dei progetti Go:

```text
.
├── .github/
│   └── workflows/
│       ├── ci.yml               # CI: Test, lint e verifica di build su push e PR
│       └── release.yml          # CD: Rilascio automatico via GoReleaser al push di tag git (v*)
├── cmd/
│   └── securecrt-decoder/
│       └── main.go              # Entrypoint CLI: parsing flag, gestione input, formattazione output
├── pkg/
│   ├── crypto/
│   │   ├── crypto.go            # Interfaccia comune Decoder e dispatcher automatico (Auto-detect)
│   │   ├── v1.go                # Decoder v1 (Blowfish-CBC a due passaggi)
│   │   ├── v2.go                # Decoder v2 (AES-256-CBC per varianti "02" e "03")
│   │   ├── kdf.go               # Key Derivation Function (KDF) per v2 variante "03"
│   │   └── crypto_test.go       # Test unitari con vettori noti
│   ├── parser/
│   │   ├── session.go           # Struct Session e tipi di protocollo supportati
│   │   ├── ini.go               # Parser dei file .ini di SecureCRT (gestione tipi S:"...", D:"...")
│   │   └── ini_test.go          # Test unitari di parsing
│   └── scanner/
│       ├── scanner.go           # Scansione del filesystem (file singolo o directory ricorsiva)
│       └── scanner_test.go      # Test unitari dello scanner
├── testdata/                    # File .ini di esempio e casi di test per regressione
├── .gitignore                   # File e directory ignorati da Git
├── .goreleaser.yaml             # Configurazione GoReleaser per gli 8 target di compilazione (Linux, FreeBSD, Windows, macOS)
├── AGENTS.md                    # Questo file di guida
├── LICENSE                      # Licenza MIT
└── README.md                    # Documentazione per l'utente finale
```

---

## 3. Specifiche Crittografiche

### A. SecureCRT v1 (Doppio Blowfish CBC)
- **Campi sorgente nel file `.ini`**: `S:"Password"=...` (stringa esadecimale).
- **Parametri**:
  - IV: 8 byte `0x00`.
  - Chiave 1 ($K_1$): `24 a6 3d de 5b d3 b3 82 9c 7e 06 f4 08 16 aa 07` (16 byte).
  - Chiave 2 ($K_2$): `5f b0 45 a2 94 17 d9 16 c6 c6 a2 ff 06 41 82 b7` (16 byte).
- **Procedura**:
  1. Decodifica la stringa hex in byte. La lunghezza deve essere multipla di 8 byte e $> 8$.
  2. Decifra con Blowfish-CBC ($K_1$, IV nullo).
  3. Rimuovi i primi 4 byte e gli ultimi 4 byte (`intermediate = pt1[4 : len(pt1)-4]`).
  4. Decifra `intermediate` con Blowfish-CBC ($K_2$, IV nullo).
  5. Il testo risultante è codificato in UTF-16LE. Trova il doppio byte nullo `0x00 0x00` di terminazione e converti in stringa UTF-8.

### B. SecureCRT v2 Variante `02` (AES-256-CBC base)
- **Campi sorgente nel file `.ini`**: `S:"Password V2"=02:...` oppure stringa esadecimale grezza.
- **Parametri**:
  - Ciphertext: byte esadecimali (escluso l'eventuale prefisso `02:`). Deve essere multiplo di 16 byte.
  - Chiave AES-256: `SHA-256(passphrase)` (se non fornita, la passphrase è una stringa vuota: `SHA-256("")`).
  - IV: 16 byte `0x00`.
- **Procedura**:
  1. Decifra con AES-256-CBC (senza padding standard PKCS#7; il blocco è gestito internamente).
  2. Leggi i primi 4 byte come intero unsigned a 32-bit little-endian: lunghezza $L$ della password in chiaro.
  3. Estrai la password: byte da `4` a `4 + L`.
  4. Estrai il checksum atteso: successivi 32 byte (da `4 + L` a `4 + L + 32`).
  5. Calcola `SHA-256(password)` e confronta con il checksum estratto. Se non coincidono, la decifratura è fallita (passphrase errata o dati corrotti).

### C. SecureCRT v2 Variante `03` (AES-256-CBC con Salt e KDF)
- **Campi sorgente nel file `.ini`**: `S:"Password V2"=03:...` (o stringa esadecimale con payload $> 32$ byte).
- **Parametri**:
  - Primi 16 byte: Salt casuale.
  - Byte successivi: Ciphertext AES effettivo.
  - KDF: Funzione iterativa basata su SHA-512 che produce 48 byte totali (primi 32 byte = Chiave AES-256, successivi 16 byte = IV AES).
- **Verifica**: Stessa struttura di payload della variante `02` (lunghezza a 32-bit + password UTF-8 + checksum SHA-256 a 32 byte).

---

## 4. Specifiche del Parsing dei File `.ini` di SecureCRT

I file `.ini` di SecureCRT utilizzano convenzioni di tipo con prefissi:
* `S:"Hostname"=192.168.1.10`
* `S:"Protocol Name"=SSH2`
* `D:"[SSH2] Port"=00000016` (notare: valore esadecimale a 8 cifre in formato dword; `0x00000016` = 22 in decimale) oppure numeri decimali diretti.
* `S:"Username"=cisco_admin`
* `S:"Password"=...` (versione v1)
* `S:"Password V2"=...` (versione v2)
* `S:"Identity Filename V2"=C:\Users\User\.ssh\id_rsa` (chiave SSH, usata se la password è vuota o assente)

Il parser deve ignorare righe vuote o commenti, estrarre correttamente i valori rimuovendo le virgolette e ripulire gli spazi.

---

## 5. Convenzioni di Sviluppo e Linee Guida

1. **Pure Go (Zero CGO)**:
   - Compilare sempre con `CGO_ENABLED=0`. Nessuna libreria nativa C o dipendenza dinamica è ammessa.
   - Dipendenze ammesse: esclusivamente la libreria standard di Go e pacchetti ufficiali `golang.org/x/...` (come `golang.org/x/crypto/blowfish`).
2. **Trattamento Sicuro delle Credenziali**:
   - Non salvare mai password in chiaro in file di log o file temporanei.
   - Fornire opzioni di output formattato (tabella da terminale, JSON per automazione, CSV per esportazione).
3. **Robustezza ed Error Handling**:
   - In modalità scansione directory, un singolo file `.ini` corrotto non deve interrompere l'analisi degli altri file.
   - Errori o password non decifrabili (es. v2 con passphrase mancante) devono essere segnalati chiaramente come `[DECRYPTION FAILED - PASSPHRASE REQUIRED]` senza mandare in crash il programma.
4. **Testing**:
   - Ogni componente critico (`pkg/crypto`, `pkg/parser`, `pkg/scanner`) deve avere test unitari automatizzati eseguibili con `go test -v ./...`.

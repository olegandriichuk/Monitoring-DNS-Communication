# Projekt do předmětu Síťové aplikace a správa sítí

**Author:** Oleg Andriichuk  
**Login:** xandri07  
**Date Created:** 11.11.2024  

## Popis Projektu

- **Zpracování argumentů příkazového řádku**: Program přijímá parametry pro zadání síťového rozhraní nebo PCAP souboru, volbu verbose režimu, a specifikaci výstupních souborů pro doménová jména a IP překlady.
- **Bezpečné ukončení**: Program zachytává signály jako `SIGINT`, `SIGTERM`, a `SIGQUIT` a v případě zachycení zobrazí zprávu o ukončení a bezpečně ukončí běh.
- **Parsování DNS paketů**: Program podporuje parsování DNS záznamů typu `A`, `AAAA`, `NS`, `MX`, `SOA`, `CNAME`, a `SRV`. Nepodporované záznamy jsou označeny jako `UNKNOWN TYPE OF RECORD` a nepodporované dotazy jako `UNKNOWN TYPE OF QUESTION`.
- **Ukládání do souboru**: Doménová jména a jejich překlady mohou být ukládána do výstupních souborů pomocí funkcí `saveDomainsToFile` a `saveDomainTranslationsToFile`.


## Příklady použití

Následující příklady ukazují, jakým způsobem lze program `dns-monitor` spustit s různými parametry.

### Příklad 1: Monitorování DNS dotazů na rozhraní

Pro monitorování DNS dotazů na konkrétním síťovém rozhraní (například `eth0`) v neverbózním režimu spusťte následující příkaz:

```bash
./dns-monitor -i eth0
```

### Příklad spuštění 2: Monitorování s verbose režimem

Přidáním volby `-v` přepne program do verbose režimu, ve kterém zobrazí podrobné informace o DNS dotazech a odpovědích, včetně časových značek, IP adres a podrobných údajů o sekcích dotazů a odpovědí.

```bash
./dns-monitor -i eth0 -v
```
### Příklad 3: Monitorování s logováním domén a překladů
Tento příkaz spustí program na rozhraní eth0, uloží doménová jména do souboru domains.txt a překlady domén na IP adresy do souboru translations.txt.

```bash 
./dns-monitor -i eth0 -d domains.txt -t translations.txt
```

### Příklad 4:  Monitorování DNS z PCAP souboru
Program může být spuštěn ve způsobu čtení z PCAP souboru. Výsledky budou uloženy do domains.txt pro doménová jména a translations.txt pro překlady domén na IP adresy.

```bash 
./dns-monitor -p ok.pcap -d domains.txt -t translations.txt
```

## List of All Files

```

makefile
README.md
manual.pdf

main.c
dnsStructures.h

processPacket.c
processPacket.h

filesOperations.c
filesOperations.h

parseFunctions.c
parseFunctions.h

printFunctions.c
printFunctions.h
```


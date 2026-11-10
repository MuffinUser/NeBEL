# Repository-Analyse: Sicherheit, Wartbarkeit und Nutzbarkeit

Stand: 29. September 2026

Repository: `nebel`

Prüfungsart: statische Quellcodeanalyse einschließlich Tests, Spezifikationen, Benutzerführung und CI-Konfiguration

## 1. Gesamtbewertung

Das Repository besitzt eine überschaubare, nachvollziehbare Architektur und eine umfangreiche Testbasis. Die Trennung zwischen Schlüsselableitung, Verschlüsselung, Tag-Format, strukturierten Dateiformaten, Git-Anbindung und CLI erleichtert die Weiterentwicklung. Golden Tests, Manipulationstests und Ende-zu-Ende-Tests für Schlüsselrotation zeigen, dass wichtige Sicherheits- und Betriebsanforderungen berücksichtigt wurden.

Gleichzeitig bestehen konkrete Fehlerpfade, die zentrale Erwartungen an ein Verschlüsselungswerkzeug verletzen:

- Ausgewählte Geheimnisse können trotz erfolgreicher Verarbeitung ganz oder teilweise unverschlüsselt im Git-Index landen.
- Ein erneutes `nebel init` kann lokale Änderungen verwerfen.
- Der Datentyp eines verschlüsselten Feldes ist nicht durch dessen kryptografische Authentisierung geschützt.
- Abgeleitetes Schlüsselmaterial wird als Argument eines Unterprozesses übergeben.
- Fehler während einer Rotation können einen unvollständigen Zustand hinterlassen.

**Einsatzbewertung:** Für neue oder wichtige Geheimnisse ist ein produktiver Einsatz ohne Behebung und gezielte Laufzeitprüfung dieser Befunde nicht zu empfehlen. Insbesondere die Feldverschlüsselung in YAML/JSON weist mehrere voneinander unabhängige Fehlerpfade auf. Ganzdateiverschlüsselung vermeidet diese speziellen Formatfehler, bleibt aber von Problemen bei Initialisierung, Filterzuordnung, Schlüsselübergabe und Präfixerkennung betroffen.

Diese Bewertung bedeutet weder, dass der verwendete Verschlüsselungsalgorithmus gebrochen ist, noch, dass bestehende Installationen zwangsläufig Geheimnisse offengelegt haben. Ob eine konkrete Installation betroffen ist, hängt von Dateiinhalten, Regeln, ausgeführten Befehlen und lokalen Zugriffsrechten ab. Ein sauberes `git status` allein weist keine Verschlüsselung nach.

## 2. Umfang, Evidenz und Grenzen

Betrachtet wurden insbesondere:

- `cmd/nebel/`: Initialisierung, Passworteingabe, Dateiauswahl, Filter und Rotation;
- `internal/`: Konfiguration, Formathandler, Filtertransformationen, Kryptografie, lokale Schlüssel und Git-Hilfsfunktionen;
- Unit-, Golden- und Ende-zu-Ende-Tests;
- `README.md`, `REQUIREMENTS.md`, `USER_INTERACTIONS.md`, `specs/` und der vorhandene Sicherheitsbericht;
- `.github/workflows/release.yml`.

Die Analyse war lesend. Erst die anschließende ausdrückliche Bitte um eine Markdown-Zusammenfassung autorisierte die Erstellung dieser Berichtsdatei. Anwendungscode und bestehende Dokumente wurden nicht verändert.

### Bedeutung der Aussagen

- **Beleg:** direkt aus dem Quellcode oder einem Repository-Artefakt ersichtlich.
- **Folgerung:** daraus abgeleitetes Verhalten und mögliche Auswirkung unter den angegebenen Voraussetzungen.
- **Offen:** mit den verfügbaren Nachweisen nicht geklärt.
- **Konfidenz:** Sicherheit der jeweiligen Analyse, unabhängig von der Schwere des möglichen Schadens.

Die wesentlichen Codepfade wurden zusätzlich in getrennten Analyseperspektiven auf Sicherheit, CLI-Betrieb und Formatverarbeitung betrachtet. Das ersetzt keine Laufzeitreproduktion.

### Nicht durchgeführte Prüfungen

Der Versuch, die Go-Toolchain aufzurufen, scheiterte mit `go: command not found`. Deshalb wurden weder `go test ./...` noch `go vet ./...` ausgeführt. Die nachfolgenden Eingabebeispiele sind aus dem Code abgeleitete Reproduktionsfälle, keine protokollierten erfolgreichen Exploit-Tests.

Es erfolgten keine aktuelle Schwachstellendatenbankprüfung der Abhängigkeiten, keine Prüfung veröffentlichter Release-Artefakte und keine Kontrolle historischer CI-Ergebnisse. Ebenso wurden keine realen Benutzer-Repositories auf bereits eingecheckte Geheimnisse untersucht. Die Analyse stellt keine vollständige Sicherheitszertifizierung dar.

Dateiverweise und Zeilennummern beziehen sich auf den untersuchten Stand und können sich durch spätere Änderungen verschieben.

## 3. Priorisierte Übersicht echter Probleme

| ID | Priorität | Bereich | Kernaussage | Konfidenz |
|---|---|---|---|---|
| P01 | Hoch | Betrieb / Datenintegrität | Erneutes `init` kann lokale und gestagte Änderungen verwerfen. | Hoch |
| P02 | Hoch | YAML / Vertraulichkeit | ` #` innerhalb eines Strings kann einen Klartextrest im Index hinterlassen. | Hoch, statisch |
| P03 | Hoch | Feldauswahl / Vertraulichkeit | Punkt-Schlüssel können auf einen anderen, verschachtelten Wert abgebildet werden. | Hoch |
| P04 | Hoch | JSON / Vertraulichkeit | Doppelte Schlüssel werden nur beim ersten Auftreten verschlüsselt. | Hoch |
| P05 | Hoch | Authentisierung / Integrität | Der Feldtyp kann ohne Authentisierungsfehler verändert werden. | Hoch |
| P06 | Hoch bei entsprechender Prozesssichtbarkeit | Lokale Sicherheit | Der abgeleitete Schlüssel erscheint in Unterprozessargumenten. | Hoch für den Codepfad |
| P07 | Hoch bei betroffenen Pfaden | Git-Integration | Attributmuster und tatsächliche Regelauswertung können auseinanderfallen. | Hoch |
| P08 | Mittel | Tag-Erkennung | Klartext mit `ENC[` am Anfang wird als bereits verschlüsselt behandelt. | Hoch |
| P09 | Mittel | Rotation | Fehler nach dem Konfigurationswechsel hinterlassen einen Zwischenzustand. | Hoch |
| P10 | Mittel | YAML / Datenintegrität | Zeilenumbrüche in Strings werden beim Rendern nicht ausreichend escaped. | Hoch, statisch |
| P11 | Mittel, abhängig vom Dokument | YAML / Schutzumfang | Mehrdokument-YAML wird nur im ersten Dokument verarbeitet. | Hoch für den Umfang |
| P12 | Mittel | Automatisierung | Teilweise fehlgeschlagene Entschlüsselung kann Exitcode 0 liefern. | Hoch |

Die Prioritäten drücken die Bedeutung bei erfüllten Voraussetzungen aus, nicht die Häufigkeit im Alltag. Insbesondere Prozesssichtbarkeit, problematische Dateinamen und ungewöhnliche Dokumentstrukturen sind installations- beziehungsweise eingabeabhängig.

## 4. Sicherheits- und Funktionsbefunde im Detail

### P01 — Erneutes Initialisieren kann lokale Arbeit verwerfen

**Beleg:** `joinRepo` und `initVersion` rufen `gitutil.CheckoutAll` auf. Diese Funktion löscht zunächst alle ermittelten verwalteten Dateien mit `os.Remove`. Anschließend stellt sie jede Datei mit `git checkout HEAD -- <path>` wieder her. Eine Prüfung auf lokale Änderungen, eine Sicherung des Arbeitsbaums oder eine Sicherung des Index ist in diesem Pfad nicht vorhanden.

**Folgerung:** Nicht gestagte Änderungen können ohne Sicherung verloren gehen. Auch gestagte Inhalte werden durch den Stand aus HEAD ersetzt; ihre mögliche Wiederherstellbarkeit aus Git-Objekten ist kein zugesicherter Schutz. Der Fall betrifft sowohl ein wiederholtes `nebel init` als auch das Nachladen einer Schlüsselversion. Scheitert die vorgelagerte Löschschleife, können bereits gelöschte Dateien zudem ohne Wiederherstellung zurückbleiben.

**Quellen:** [init.go](../cmd/nebel/init.go), Zeilen 203–217 und 330–347; [gitutil.go](../internal/gitutil/gitutil.go), Zeilen 226–259.

**Verifikationsbedarf:** Wiederholtes Initialisieren mit getrennt vorbereiteten unstaged, staged und neu gestagten verwalteten Dateien; Vergleich von Arbeitsbaum und Index vor und nach dem Befehl. Der vorhandene Test für isolierte Smudge-Fehler belegt keinen Schutz veränderter Dateien.

### P02 — YAML-Kommentarerkennung kann Geheimnisreste offenlegen

**Beleg:** `scalarText` kürzt den Token-Ursprungstext beim ersten Vorkommen von ` #`. Die Funktion berücksichtigt nicht, ob dieses Zeichenpaar innerhalb eines zitierten Strings steht. `yamlSpan` verwendet die Länge des so gekürzten Textes als zu ersetzenden Bereich. Seine anschließende Prüfung vergleicht lediglich diesen bereits verkürzten Bereich.

**Abgeleiteter Reproduktionsfall:** Bei `password: "abc # geheim"` kann nur der Anfang `"abc` ersetzt werden. Der Rest ` # geheim"` bleibt außerhalb des ersetzten Bereichs stehen und wird im resultierenden YAML als Kommentar interpretiert.

**Folgerung:** Der gesamte logische Wert kann zwar im verschlüsselten Tag enthalten sein, gleichzeitig bleibt sein Suffix im Klartext im Git-Blob erhalten. Dies ist ein Vertraulichkeitsfehler, nicht lediglich eine Formatierungsabweichung.

**Quellen:** [yaml.go](../internal/format/yaml.go), Zeilen 152–189; [filterop.go](../internal/filterop/filterop.go), Zeilen 162–186.

**Offen:** Laufzeitbestätigung mit der konkret eingebundenen YAML-Parser-Version steht aus.

### P03 — Mehrdeutige Feldpfade können das falsche Feld verschlüsseln

**Beleg:** `Leaves` bildet Feldnamen über `joinPath` auf Punktnotation ab. Eine Escape-Regel für Punkte in Schlüsseln existiert nicht. `ParsePath` interpretiert Punkte dagegen immer als Trennung verschachtelter Schlüssel.

**Abgeleiteter Reproduktionsfall:**

```json
{"a.b":"secret","a":{"b":"decoy"}}
```

Der Picker kann beide Werte unter demselben Pfad `a.b` anbieten. Wird der erste Eintrag ausgewählt, löst die spätere Validierung diesen Pfad auf den verschachtelten Wert `decoy` auf. Die Auswahl kann deshalb erfolgreich sein, während `secret` unverändert bleibt.

**Folgerung:** Eine ausdrücklich ausgewählte Schutzabsicht wird auf ein anderes Feld angewandt. Ohne ein vorhandenes gleichnamiges verschachteltes Feld kann stattdessen eine Fehlermeldung entstehen; der gefährliche Fall benötigt die beschriebene Kollision.

**Quellen:** [format.go](../internal/format/format.go), Zeilen 110–116; [path.go](../internal/format/path.go), Zeilen 41–80; [json.go](../internal/format/json.go), Funktion `Leaves`; [yaml.go](../internal/format/yaml.go), Zeilen 279–311; [add.go](../cmd/nebel/add.go), Zeilen 174–186.

### P04 — Doppelte JSON-Schlüssel hinterlassen eine Klartextkopie

**Beleg:** `descendObject` kehrt beim ersten zum Pfad passenden Schlüssel zurück. `cleanValues` ersetzt für jeden konfigurierten Pfad genau den ermittelten Bereich. Eine Prüfung auf weitere gleichnamige Schlüssel im selben Objekt fehlt.

**Abgeleiteter Reproduktionsfall:**

```json
{"password":"eins","password":"zwei"}
```

Bei konfiguriertem Pfad `password` bleibt das zweite Vorkommen unverschlüsselt.

**Folgerung:** Bereits die sichtbare zweite Klartextkopie ist ein Datenleck, unabhängig davon, welchen Wert eine nachgelagerte Anwendung verwendet. Welche Kopie für die Anwendung wirksam ist, hängt von deren JSON-Verarbeitung ab und wurde hier nicht untersucht.

**Quellen:** [json.go](../internal/format/json.go), Zeilen 69–84; [filterop.go](../internal/filterop/filterop.go), Zeilen 162–186.

### P05 — Der native Datentyp gehört nicht zum authentisierten Inhalt

**Beleg:** Der Typ wird als `type:` im Tag gespeichert. Verschlüsselt wird der Feldwert; die zugehörigen Authentisierungsdaten enthalten nur Modus, Dateipfad und Feldpfad. Nach erfolgreicher Entschlüsselung übergibt `smudgeValues` den separat geparsten Typ an `Render`. Für Zahlen und Boolesche Werte geben die Renderer den Klartext ohne String-Quoting aus.

**Folgerung:** Ein Angreifer, der den gespeicherten Tag ändern kann, benötigt keinen Schlüssel, um `type:str` beispielsweise in `type:bool` zu ändern. Ein verschlüsselter String `false` kann dadurch als Boolean statt als String ausgegeben werden, ohne dass die Authentisierungsprüfung anschlägt. Bei passend aufgebautem Klartext kann die unquotierte Ausgabe zusätzliche JSON-Struktur bilden. Diese weitergehende Wirkung benötigt geeigneten Inhalt; ein allgemeines Einschleusen beliebiger Inhalte ist damit nicht nachgewiesen.

**Quellen:** [tag.go](../internal/tag/tag.go), Zeilen 120–122; [siv.go](../internal/siv/siv.go), Zeilen 53–59; [filterop.go](../internal/filterop/filterop.go), Zeilen 175 und 214–234; [json.go](../internal/format/json.go), Zeilen 157–169; [yaml.go](../internal/format/yaml.go), Zeilen 252–258.

**Testgrenze:** Der vorhandene Manipulationstest verändert Ciphertext-Daten. Er belegt keine Authentisierung der Typmetadaten.

### P06 — Schlüsselmaterial wird als Prozessargument übergeben

**Beleg:** `localkey.Set` Base64-kodiert den vollständigen abgeleiteten Schlüssel. `gitutil.ConfigSet` startet anschließend `git config --local <name> <value>` mit diesem Schlüssel als `value`.

**Folgerung:** Während der Laufzeit des Unterprozesses steht unmittelbar verwendbares Entschlüsselungsmaterial in dessen Argumentliste. Der Schutz gegen Passwortargumente an der eigenen CLI verhindert diesen zweiten Offenlegungspfad nicht. Base64 ist lediglich eine Kodierung.

**Voraussetzung und Grenze:** Ein lokaler Beobachter muss die betreffenden Prozessargumente lesen können. Ob andere Benutzer diese Sichtbarkeit haben, hängt von Betriebssystem und Sicherheitskonfiguration ab. Eine konkrete fremde Lesbarkeit wurde nicht gemessen.

**Quellen:** [localkey.go](../internal/localkey/localkey.go), Zeilen 64–66; [gitutil.go](../internal/gitutil/gitutil.go), Zeilen 44–49; [password.go](../cmd/nebel/password.go), Argumentprüfung.

### P07 — Die Filterzuordnung garantiert keine passende Schutzregel

Es gibt mehrere eigenständige Ursachen für dieses Problem:

1. **Unterschiedliche Glob-Semantik:** Der Code dokumentiert ausdrücklich, dass `*.env` in der eigenen Regelauswertung nur auf Root-Dateien passt, während ein solches `.gitattributes`-Muster auch Dateien in Unterverzeichnissen erfasst. `add file` schreibt das Muster unverändert in beide Systeme. Für `config/prod.env` kann Git deshalb den Filter aufrufen, während `MatchRule` keinen Treffer liefert und `Clean` Klartext zurückgibt. Die Filterzuordnung ist in diesem Fall sichtbar, aber nicht wirksam.
2. **Fehlendes Quoting:** `addGitattributesPattern` schreibt Dateinamen beziehungsweise Muster unmittelbar in eine Attributzeile. Leerzeichen im Namen können dazu führen, dass die gewünschte Datei keine wirksame Filterzuordnung erhält, obwohl der Befehl Erfolg meldet.
3. **Ignorierte Glob-Fehler:** `Validate` prüft keine Glob-Syntax. `MatchRule` verwirft den Fehlerwert von `doublestar.Match`. Eine fehlerhafte handeditierte Regel kann daher ohne expliziten Fehler als nicht passend behandelt werden.

**Folgerung:** Benutzer können aus einer erfolgreichen Registrierung oder aus `filter: nebel` mehr Schutz ableiten, als der Filter tatsächlich leistet. Die Beispiele benötigen jeweils die beschriebene Muster- oder Pfadkonstellation; sie bedeuten nicht, dass jedes Muster wirkungslos ist.

**Quellen:** [config.go](../internal/config/config.go), Zeilen 38–43 und 115–148; [add.go](../cmd/nebel/add.go), Zeilen 219–239; [filterop.go](../internal/filterop/filterop.go), Zeilen 57–61.

### P08 — Ein Präfix ersetzt die Prüfung auf Verschlüsselung

**Beleg:** `tag.IsEncrypted` prüft ausschließlich, ob der Inhalt mit `ENC[` beginnt. Sowohl Ganzdatei- als auch Feldverschlüsselung überspringen so klassifizierte Werte, ohne zuvor einen vollständigen Tag zu parsen.

**Folgerung:** Ein Klartextwert wie `ENC[mein-geheimnis` wird unverändert durch Clean gereicht. Ein späterer Parse-Fehler beim Smudge verhindert nicht, dass der Klartext zuvor in den Index aufgenommen wurde. Der Fall dürfte seltener auftreten als gewöhnliche Stringwerte, verletzt aber die zugesagte Schutzwirkung für diese Eingabeklasse.

**Quellen:** [tag.go](../internal/tag/tag.go), Zeilen 97–104; [filterop.go](../internal/filterop/filterop.go), Zeilen 67–75 und 168–170.

### P09 — Rotation ist über mehrere Zustandsänderungen nicht atomar

**Beleg:** `runRotate` registriert den neuen Schlüssel und schreibt die neue Konfiguration, bevor das Staging der Konfiguration und die Neuverschlüsselung sämtlicher verwalteter Inhalte abgeschlossen sind. Fehler in den folgenden Schritten führen zum Rücksprung, ohne den vorherigen Zustand wiederherzustellen. Ein automatisch erzeugtes Passwort wird erst in der abschließenden Erfolgsausgabe angezeigt.

**Folgerung:** Ein Git-/Schreibfehler oder eine Unterbrechung kann eine neue aktuelle Schlüsselversion mit noch nicht vollständig migrierten Inhalten hinterlassen. Wird ein solcher Zwischenstand später unbemerkt committed, kann ein anderer Clone trotz Kenntnis des neuen Passworts noch alte Schlüssel benötigen. Nach einem frühen Fehler kann außerdem das erzeugte Passwort unbekannt bleiben, obwohl der abgeleitete Schlüssel bereits lokal gespeichert ist.

Dies ist kein Nachweis eines unvermeidlichen dauerhaften Datenverlusts: Alte Schlüssel bleiben lokal erhalten und ein Zustand kann gegebenenfalls repariert werden. Die fehlende abgeschlossene Transaktion und Wiederanlaufbeschreibung sind dennoch konkrete Betriebsrisiken.

**Quellen:** [rotate.go](../cmd/nebel/rotate.go), Zeilen 127–161; [gitutil.go](../internal/gitutil/gitutil.go), Zeilen 112–139.

### P10 — YAML-Strings mit Zeilenumbrüchen können ihren Wert ändern

**Beleg:** Der YAML-Renderer escaped Backslashes und Anführungszeichen, aber keine Zeilenumbrüche oder sonstigen Steuerzeichen. Ein entschlüsselter String mit LF wird deshalb mit einem tatsächlichen Zeilenumbruch innerhalb doppelter Anführungszeichen ausgegeben.

**Folgerung:** Ein ursprünglich als Escape dargestellter Zeilenumbruch kann durch die YAML-Verarbeitung eines physischen Zeilenumbruchs anders interpretiert werden. Für gewöhnliche fortgesetzte zitierte Skalare kann aus dem Zeilenumbruch ein Leerzeichen werden. Damit kann ein Verschlüsseln-/Entschlüsseln-Zyklus den logischen Wert verändern, etwa bei mehrzeiligen Zugangsdaten.

**Quelle:** [yaml.go](../internal/format/yaml.go), Zeilen 252–258.

**Offen:** Konkrete Roundtrips mit dem eingebundenen Parser und den nachgelagerten Zielanwendungen wurden nicht ausgeführt. Dieser Befund benötigt gezielte Tests für LF, CR, Tabs und weitere Steuerzeichen.

### P11 — Mehrdokument-YAML wird nur teilweise berücksichtigt

**Beleg:** Sowohl `Locate` als auch `Leaves` beziehen sich ausschließlich auf `file.Docs[0]`. Weitere YAML-Dokumente werden weder ausgewählt noch auf gleichnamige zu schützende Pfade geprüft.

**Folgerung:** Enthält eine YAML-Datei mehrere Dokumente mit `password`, wird beim passenden Pfad im ersten Dokument nur dieses verarbeitet. Ein weiterer Wert im zweiten Dokument bleibt Klartext. Fehlt das Feld bereits im ersten Dokument, scheitert die Verarbeitung dagegen mit einem Fehler.

**Einordnung:** Falls Mehrdokument-YAML bewusst außerhalb des unterstützten Formats liegt, ist die fehlende Zurückweisung beziehungsweise Warnung die entscheidende Schutzlücke. Ob ein konfigurierter Pfad fachlich für alle Dokumente gelten soll, ist aus dem untersuchten Vertrag nicht abschließend geklärt.

**Quelle:** [yaml.go](../internal/format/yaml.go), Zeilen 43–47 und 279–311.

### P12 — Teilweises Scheitern wird nicht im Exitcode abgebildet

**Beleg:** `reportCheckoutResult` gibt fehlgeschlagene oder noch nicht entschlüsselte Dateien aus und kehrt anschließend mit `nil` zurück.

**Folgerung:** Ein Skript kann anhand des Exitcodes allein nicht erkennen, dass die Initialisierung keine vollständig verwendbaren Dateien hinterlassen hat. Nachfolgende Schritte können mit Ciphertext oder unvollständiger Entschlüsselung weiterlaufen. Die Warnungen sind für einen aufmerksamen interaktiven Benutzer sichtbar, für Exitcode-basierte Automatisierung jedoch unzureichend.

**Quelle:** [init.go](../cmd/nebel/init.go), Zeilen 234–299.

## 5. Weitere Nutzbarkeits- und Wartbarkeitsbefunde

### Fehlende spezifizierte Statusprüfung

`specs/09-cli-status.md` und `USER_INTERACTIONS.md` beschreiben `nebel status` mit Zustandsdiagnose und einem nicht erfolgreichen Exitcode bei ungeschützten Inhalten. Im Dispatcher existiert kein entsprechender Befehl.

Das ist eine tatsächliche Funktionslücke gegenüber diesen Dokumenten. Die aktuelle Befehlstabelle der README führt `status` hingegen nicht auf; die Aussage sollte deshalb nicht zu einer falschen Behauptung über die README erweitert werden. Ein als implementiert vorausgesetztes CI-Sicherheitsnetz ist derzeit nicht vorhanden.

Quellen: [Spec 09](../specs/09-cli-status.md), Zeilen 7–37; [USER_INTERACTIONS.md](../USER_INTERACTIONS.md), ab Zeile 144; [main.go](../cmd/nebel/main.go), Zeilen 21–44.

### Widersprüchliche Beschreibung der Rotation

Die CLI-Hilfe sagt, Rotation berühre bereits verschlüsselte Inhalte nicht. Die Implementierung führt dagegen ausdrücklich eine Neuverschlüsselung durch. Das erschwert die Einschätzung von Nebenwirkungen und erzeugt Wartungsrisiken, wenn Dokumentation als Implementierungsvorgabe verwendet wird.

Quellen: [main.go](../cmd/nebel/main.go), Zeilen 63–65; [rotate.go](../cmd/nebel/rotate.go), Zeilen 138–153.

### Konfigurationskommentare gehen beim Speichern verloren

`Config.Save` serialisiert die gesamte Struktur neu. Der Quellkommentar benennt selbst, dass vorhandene Kommentare nicht erhalten werden. Normale Add- und Rotationsvorgänge können damit manuell hinterlegte Erläuterungen entfernen. Dies ist ein belegter Verlust von Dokumentationsinhalt, aber keine unmittelbare kryptografische Schwachstelle.

Quelle: [config.go](../internal/config/config.go), Zeilen 167–181.

### Überschneidende Regeln sind schwer zu überblicken

Die erste passende Regel gewinnt; die Add-Befehle prüfen Konflikte überwiegend anhand identischer Muster. Eine breite Regel kann daher eine später hinzugefügte spezifische Regel verdecken. Eine frühere Ganzdateiregel kann beispielsweise eine spätere Feldregel wirkungslos machen, ohne deshalb Klartext zu erzeugen. Je nach Reihenfolge und Inhalt von Feldregeln kann der tatsächlich geschützte Feldumfang aber von der zuletzt geäußerten Benutzerabsicht abweichen.

Quellen: [config.go](../internal/config/config.go), Zeilen 138–148; [add.go](../cmd/nebel/add.go), Funktion `applyFieldRule`.

### Git-Dateilisten werden als zeilenorientierter Text verarbeitet

`ManagedFiles` verwendet `git ls-files` ohne NUL-Trennung und interpretiert die Ausgabe von `git check-attr` durch einfache Stringzerlegung. Der Quellkommentar nennt selbst Einschränkungen für besondere Dateinamen. Dies begrenzt die verlässliche Verarbeitung ungewöhnlicher Namen; die Übergabe sämtlicher Pfade in einem Argumentvektor kann zusätzlich bei sehr großen Repositories an Betriebssystemgrenzen stoßen.

Quelle: [gitutil.go](../internal/gitutil/gitutil.go), Zeilen 262–296.

## 6. Positive Eigenschaften und reine Verbesserungspotenziale

### Positiv belegte Eigenschaften

- Die Kryptografie wird an die Tink-Implementierung von AES-SIV delegiert; das Repository implementiert nicht selbst den Blockchiffre-Modus.
- Die Schlüsselableitung verwendet Argon2id und eine getrennte HKDF-Kontextkennung.
- Die Authentisierungsdaten binden Ciphertext an Modus, Dateipfad und Feldpfad. Ihre längenpräfixierte Kodierung vermeidet Mehrdeutigkeiten zwischen diesen Komponenten.
- Die Passworteingabe unterstützt verdeckte Terminaleingabe sowie stdin und verweigert Passwortargumente an der eigenen CLI.
- Tests prüfen unter anderem Determinismus, falsche Schlüssel, Ciphertext-Manipulation, CRLF-Verhalten und Rotationsabläufe über mehrere Clones.
- Die CI-Konfiguration sieht `go vet`, Tests und Smoke-Tests auf Linux, macOS und Windows vor. Externe Actions sind auf konkrete Commit-SHAs festgelegt.

Diese Eigenschaften sind positive Architektur- und Testnachweise. Sie heben die zuvor beschriebenen Integrationsfehler nicht auf und belegen keine aktuelle erfolgreiche CI-Ausführung.

Quellen: [kdf.go](../internal/kdf/kdf.go), [siv.go](../internal/siv/siv.go), [password.go](../cmd/nebel/password.go), [value_test.go](../internal/filterop/value_test.go), [rotate_e2e_test.go](../cmd/nebel/rotate_e2e_test.go), [release.yml](../.github/workflows/release.yml).

### Optimierungspotenzial ohne nachgewiesenen unmittelbaren Defekt

- **Lokale Schlüsselablage härten:** Klartextschlüssel in `.git/config` sind eine explizite lokale Vertrauensgrenze. Restriktive Zugriffsrechte oder ein Betriebssystem-Schlüsselspeicher könnten sie verstärken. Dass eine konkrete Installation tatsächlich für fremde Benutzer lesbar ist, wurde nicht belegt. Dieser Punkt ist vom bestätigten argv-Pfad P06 zu trennen.
- **Ressourcenverbrauch begrenzen:** Filter und Passworteingabe lesen stdin vollständig in den Speicher. Größenlimits oder eine klarere Ressourcenstrategie könnten die Robustheit gegen sehr große Eingaben verbessern. Ein praktisch relevanter Angriffsweg wurde dafür nicht nachgewiesen.
- **Gezielte Diagnose ausbauen:** Eine Statusprüfung könnte Filterzuordnung, Regeltreffer und tatsächlich gespeicherte Inhalte gemeinsam sichtbar machen. Das würde Bedienfehler früher erkennbar machen.
- **Dokumentation konsolidieren:** Implementierter Umfang, geplante Funktionen, Formatgrenzen und bewusste Kompromisse sollten eindeutig voneinander unterscheidbar sein.

Deterministische Verschlüsselung, lokal entschlüsselte Arbeitsdateien und die fortbestehende Lesbarkeit alter Historie mit alten Schlüsseln sind zunächst Design- beziehungsweise Betriebsgrenzen. Sie sind nicht allein aufgrund ihrer Existenz als Programmfehler zu werten. Insbesondere macht eine Schlüsselrotation bereits bekannte alte Geheimnisse nicht rückwirkend unbekannt; darauf weist die Rotationsausgabe selbst hin.

## 7. Bewertung der Testbasis und vorhandener Audit-Aussagen

Die Testbasis ist für ein kleines Repository umfangreich und berücksichtigt mehrere reale Integrationsprobleme. Ihre Aussagekraft endet jedoch bei den tatsächlich geprüften Eigenschaften. Ein erfolgreicher Test gegen Ciphertext-Bitflips beweist beispielsweise nicht, dass separat gespeicherte Metadaten authentisiert sind. Ebenso belegt ein erfolgreicher Checkout in einem unveränderten Clone keinen Schutz lokaler Arbeit bei erneutem Initialisieren.

Für die hier identifizierten Risiken sind insbesondere folgende Nachweise offen:

- Erhalt von Arbeitsbaum und Index bei wiederholtem `init`;
- vollständige Geheimnisabdeckung bei Punkt-Schlüsseln, doppelten JSON-Schlüsseln und Mehrdokument-YAML;
- korrekte YAML-Bereiche bei ` #` innerhalb zitierter Strings;
- logische Roundtrips von Strings mit Steuerzeichen;
- Zurückweisung manipulierter Typmetadaten;
- Übereinstimmung von Attributmustern, Regeltreffern und tatsächlichen Index-Inhalten;
- nachvollziehbare Zustände nach gezielt ausgelösten Rotationsfehlern;
- sinnvolle Exitcodes bei nur teilweise erfolgreicher Entschlüsselung.

Der vorhandene Bericht [11-security-audit.md](11-security-audit.md) endet mit einer positiven Gesamtbewertung. Diese ist kein ausreichender Gegenbeleg zu den hier nachvollzogenen Fehlerpfaden. Die aktuelle Analyse übernimmt weder pauschale Sicherheitsfreigaben noch jede Risikoeinstufung dieses älteren Berichts. Für eine Freigabe sind konkrete Verhaltensnachweise am betroffenen Code erforderlich.

## 8. Bedeutung für eine bestehende Nutzung

Aus der statischen Analyse allein lässt sich keine tatsächliche Kompromittierung einer bestehenden Installation feststellen. Um diese Unsicherheit zu reduzieren, wäre eine lesende Untersuchung der realen Regeln und der ungefilterten Git-Blobs einschließlich relevanter Historie erforderlich. Dabei müsste geprüft werden, ob die beschriebenen Eingabeklassen oder Filterabweichungen tatsächlich vorkommen.

Eine Prüfung nur der lokal entschlüsselten Arbeitsdateien reicht dafür nicht aus. Umgekehrt beweist ein sauberer Git-Arbeitsbaum nicht, dass gespeicherte Geheimnisse verschlüsselt sind.

Bis zur Behebung der wesentlichen Befunde ist das Tool für Experimente mit unwichtigen Beispieldaten geeignet, sollte aber nicht als belastbar geprüfte Schutzmaßnahme für neue produktive Geheimnisse behandelt werden. Dieser Bericht dokumentiert die Analyse und ihre Grenzen; er ist weder ein Nachweis bereits eingetretener Schäden noch eine umgesetzte Fehlerbehebung.

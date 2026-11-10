# Erneute Repository-Analyse: Sicherheit, Wartbarkeit und Nutzbarkeit

Berichtsdatum: 30. September 2026

Geprüfter Stand: Commit `8599e77` — `Merge pull request #11 from MuffinUser/worktree-audit-medium-findings`

Dieser Bericht dokumentiert die zuletzt durchgeführte erneute Analyse nach den Korrekturen an den früheren Befunden P01–P13. Er wurde anschließend verschriftlicht; seine Erstellung ist kein weiterer Testlauf. Der Repository-Stand entspricht weiterhin dem geprüften Commit.

## 1. Gesamtbewertung

Der aktualisierte Stand ist deutlich verbessert. Mehrere zuvor nachgewiesene Klartext- und Formatfehler wurden behoben oder durch eine explizite Zurückweisung problematischer Eingaben abgesichert. Die neuen Regressionstests prüfen zahlreiche zuvor fehlende Randfälle.

Trotzdem bestehen relevante Restprobleme:

- Dateinamen mit Leerzeichen erhalten weiterhin keine wirksame Git-Filterzuordnung.
- Die Schutzprüfung vor erneutem `init` übersieht einen bestimmten Zustand mit Änderungen im Index.
- Rotation ist weiterhin nicht transaktional und zeigt ein automatisch erzeugtes Passwort erst nach den fehleranfälligen Folgeschritten an.
- Die neue Schlüsseldatei wird ohne atomaren Austausch oder Synchronisierung geschrieben.
- Die Erkennung bereits verschlüsselter Inhalte ist weiterhin zu großzügig.
- Manche akzeptierten und verschlüsselten Werte können beim späteren Smudge nicht wieder ausgegeben werden.

**Einsatzbewertung:** Die frühere Kritik trifft nicht mehr unverändert auf sämtliche damaligen Befunde zu. Eine uneingeschränkte Empfehlung für produktive Geheimnisse ist wegen der verbleibenden Klartext- und Datenverlustrisiken aber weiterhin nicht gerechtfertigt.

Diese Aussage ist keine Feststellung einer tatsächlichen Kompromittierung. Ob vorhandene Benutzer-Repositories betroffen sind, wurde nicht untersucht.

## 2. Prüfungsumfang und Nachweise

Die erneute Prüfung umfasste die geänderten Implementierungen, zugehörige Tests und Dokumentation sowie die Abhilfestände der früheren Befunde. Betrachtet wurden insbesondere Formatverarbeitung, Tag-Authentisierung, Schlüsselablage, Git-Filterzuordnung, Initialisierung und Rotation.

### Frische Prüfungen am untersuchten Stand

Unter Go 1.27.1 auf Linux/amd64 wurden ausgeführt:

```bash
go vet ./...
go test ./... -count=1 -timeout 120s
```

Das aufgerufene Ausgangsprogramm war `/usr/lib/go-1.24/bin/go`; mit `GOTOOLCHAIN=auto` wurde die bereits nachgeladene Go-1.27.1-Toolchain verwendet. Der Testlauf verwendete `-count=1`, um den Testcache auszuschließen.

| Prüfung | Ergebnis |
|---|---|
| `go vet ./...` | Exitcode 0, keine Meldungen |
| Vollständige vorhandene Testsuite | Exitcode 0, alle neun Pakete erfolgreich |
| Zusätzlicher gezielter Lauf für `internal/format`, `internal/filterop`, `internal/tag` | Tests und Vet erfolgreich |
| Direkte Prüfung der neuen Leerzeichen-Escapes mit Git | Filterzuordnung weiterhin fehlerhaft |

Die neun Pakete sind `cmd/nebel` sowie `internal/config`, `internal/filterop`, `internal/format`, `internal/gitutil`, `internal/kdf`, `internal/localkey`, `internal/siv` und `internal/tag`.

### Aussagegrenzen

- **Laufzeitbeleg:** konkret ausgeführter Test oder direkt beobachtetes Git-Verhalten.
- **Codebeleg:** direkt sichtbare Implementierung und deren kontrollierbarer Ablauf.
- **Folgerung:** aus dem Code abgeleitete Auswirkung; nicht automatisch ein separat reproduzierter Fehlerfall.

Nicht sämtliche früheren Diagnoseszenarien wurden erneut als separate Ende-zu-Ende-Tests ausgeführt. Insbesondere die Index-Sonderkonstellation, Unterbrechungen während einer Rotation und konkurrierende Schlüsseldateizugriffe wurden in dieser erneuten Prüfung aus dem Code abgeleitet. Diese Grenzen werden bei den Befunden benannt.

Es erfolgten keine aktuelle Schwachstellendatenbankprüfung der Abhängigkeiten, keine Prüfung veröffentlichter Release-Artefakte und keine Untersuchung realer Benutzer-Repositories auf frühere Geheimnisoffenlegungen. Die erfolgreichen lokalen Tests belegen keinen erfolgreichen Lauf auf anderen Betriebssystemen.

Die Analyse änderte keinen Anwendungscode und keine bestehenden Tests. Dieser Bericht ist die anschließend angeforderte Dokumentation. Quellen und Zeilennummern beziehen sich auf `8599e77`.

## 3. Status der früheren Befunde

| ID | Thema | Ergebnis der erneuten Prüfung |
|---|---|---|
| P01 | Datenverlust bei erneutem `init` | Teilweise behoben: gewöhnliche Änderungen werden erkannt; ein eigenständiger Indexzustand bleibt ungeschützt. |
| P02 | Klartextrest bei ` #` in zitiertem YAML | Behoben für den untersuchten Fehlerpfad; Regressionstest besteht. |
| P03 | Kollision von Punkt-Schlüsseln und verschachtelten Pfaden | Mehrdeutige Zielfelder werden abgelehnt. Literal-Punktschlüssel sind weiterhin nicht allgemein adressierbar. |
| P04 | Doppelte JSON-Schlüssel | Mehrdeutige Treffer für das Zielfeld werden erkannt und abgelehnt. |
| P05 | Nicht authentisierter Feldtyp | Neue Tags binden den Typ; historische Tags behalten die frühere Schwäche. |
| P06 | Schlüssel in Prozessargumenten | Durch direkte Speicherung in einer eigenen Schlüsseldatei behoben; deren Schreibverfahren hat separate Risiken. |
| P07 | Abweichende Filter-/Regelzuordnung | Fehlende Regeltreffer führen zum Abbruch, ungültige Muster werden geprüft. Leerzeichen bleiben fehlerhaft behandelt. |
| P08 | Präfix `ENC[` verhindert Verschlüsselung | Eingegrenzt, aber durch eine weiterhin unvollständige Tag-Erkennung nicht vollständig geschlossen. |
| P09 | Unvollständige Rotation / verspätete Passwortanzeige | Weiterhin offen. |
| P10 | YAML-Zeilenumbrüche ändern ihren Wert | Der ursprüngliche LF-Roundtrip ist behoben. Bestimmte andere Steuerzeichen werden erst beim Smudge zurückgewiesen. |
| P11 | Nur erstes YAML-Dokument geschützt | Mehrdokument-YAML wird jetzt ausdrücklich abgelehnt. |
| P12 | Erfolgscode trotz echter Checkout-Fehler | Echte Checkout-Fehler führen nun zu einem Fehlerstatus; fehlende Schlüsselversionen bleiben bewusst ein eingeschränkter Erfolgszustand. |
| P13 | YAML-Blockskalare lassen Klartext stehen | Betroffene Blockskalare werden ausdrücklich abgelehnt. |

„Abgelehnt“ bedeutet in dieser Tabelle eine Sicherheitskorrektur durch begrenzten Funktionsumfang. Es bedeutet nicht, dass die betreffende YAML- oder Pfadvariante inzwischen unterstützt wird.

## 4. Priorisierte verbleibende Probleme

### R01 — Leerzeichen in Dateinamen bleiben ein Klartextpfad

**Priorität: hoch. Nachweis: Code und direkte Git-Laufzeitprüfung.**

`escapeGitattributesPattern` ersetzt Leerzeichen durch Backslash-Leerzeichen. Für `my secret.pem` entsteht:

```text
my\ secret.pem filter=nebel
```

Diese Syntax erzeugt in Git nicht die beabsichtigte Filterzuordnung. Die Prüfung erfolgte ohne Änderung einer Repository-Datei, indem die Attributdefinition über stdin bereitgestellt wurde:

```bash
git -c core.attributesfile=/dev/stdin check-attr filter -- 'my secret.pem' \
  <<< 'my\ secret.pem filter=nebel'
```

Beobachtete Ausgabe:

```text
my secret.pem: filter: unspecified
```

Die Kontrollprüfung mit einer doppelt zitierten Attributdefinition, `"my secret.pem" filter=nebel`, lieferte dagegen `filter: nebel`.

**Auswirkung:** `nebel add file 'my secret.pem'` kann eine Regel registrieren, ohne dass Git den Filter für diese Datei aufruft. Bei anschließendem Staging kann der Inhalt daher unverschlüsselt bleiben. In dieser erneuten Prüfung wurde die Attributauflösung direkt reproduziert; der vollständige CLI-/Commit-Ablauf wurde nicht erneut separat ausgeführt.

**Testlücke:** `TestEscapeGitattributesPattern` erwartet genau den problematischen String. Der Test prüft die Ausgabe der Hilfsfunktion, nicht die tatsächliche Wirkung auf Git.

Quellen: [add.go](../cmd/nebel/add.go), Zeilen 334–339; [add_test.go](../cmd/nebel/add_test.go), insbesondere Zeilen 19–20.

### R02 — `init` übersieht eine Änderung ausschließlich im Index

**Priorität: hoch. Nachweis: vollständiger Codepfad; hohe Konfidenz, nicht separat zur Laufzeit reproduziert.**

`DirtyFiles` verwendet nur `git diff --name-only HEAD -- <paths>`. Damit wird nicht unabhängig geprüft, ob der Index vom Commit abweicht.

Die relevante Konstellation ist:

1. HEAD enthält den Inhalt A.
2. Der Benutzer ändert die Datei zu B und stagt B.
3. `git restore --source=HEAD --worktree <pfad>` setzt ausschließlich die Arbeitsdatei wieder auf A.
4. Arbeitsdatei und HEAD enthalten A, der Index enthält weiterhin B.

Die aktuelle Prüfung kann diesen Zustand als unverändert behandeln. Das spätere `git checkout HEAD -- <pfad>` setzt jedoch sowohl Arbeitsdatei als auch Index auf A. Die gestagte Änderung B wird dadurch aus dem Index verdrängt.

**Abgrenzung:** Die gewöhnlichen früheren Fälle mit einer gegenüber HEAD veränderten Arbeitsdatei werden inzwischen abgefangen. Der Restbefund betrifft die unabhängige Bedeutung des Index, nicht das völlige Fehlen einer Dirty-Prüfung.

Quellen: [gitutil.go](../internal/gitutil/gitutil.go), Funktion `DirtyFiles`, ab Zeile 277, und Funktion `CheckoutAll`, insbesondere der Checkout ab Zeile 376.

### R03 — Rotation bleibt bei Fehlern unvollständig

**Priorität: mittel, bei fehlendem automatisch erzeugtem Passwort mit erheblicher Betriebswirkung. Nachweis: Code.**

`runRotate` führt die Zustandsänderungen weiterhin in folgender Reihenfolge aus:

1. neuen Schlüssel speichern;
2. neue Konfiguration schreiben;
3. Konfiguration stagen;
4. verwaltete Inhalte neu verschlüsseln und stagen;
5. automatisch erzeugtes Passwort anzeigen.

Scheitert ein späterer Schritt, fehlen Rückabwicklung und ein abgesicherter Wiederanlaufpfad. Die Konfiguration kann bereits die neue Schlüsselversion benennen, während die Migration noch nicht vollständig abgeschlossen ist. Ein automatisch erzeugtes Passwort wurde in diesem Fall möglicherweise nie angezeigt, obwohl sein abgeleiteter Schlüssel bereits aktiv ist.

Dies beweist keinen unvermeidlichen dauerhaften Verlust sämtlicher Daten: Alte Schlüssel bleiben grundsätzlich erhalten und der lokale abgeleitete neue Schlüssel kann vorhanden sein. Es bleibt jedoch ein konkretes Problem für Wiederherstellung und Weitergabe an andere Clones.

Der aktuelle [Abhilfeplan für mittlere Befunde](2026-09-29-medium-findings-validation-and-mitigation-plan.md) führt P09 selbst weiterhin als offen.

Quelle: [rotate.go](../cmd/nebel/rotate.go), Zeilen 127–161.

### R04 — Die neue Schlüsseldatei wird nicht atomar geschrieben

**Priorität: mittel. Nachweis: Code; Unterbrechungs- und Parallelitätsfolgen sind nicht reproduzierte Folgerungen.**

Der Wechsel von Git-Konfigurationsargumenten auf eine eigene Datei schließt den früheren argv-Offenlegungspfad. Die Datei wird bei ihrer Erstellung mit `0600` angelegt. Allerdings verwendet `writeKeyFile` direkt `os.WriteFile`, ohne temporäre Datei mit anschließendem atomaren Austausch und ohne Synchronisierung der Lesen-Ändern-Schreiben-Sequenz.

Daraus ergeben sich folgende mögliche Auswirkungen:

- Ein Abbruch nach dem Kürzen der Datei kann eine leere oder unvollständige Schlüsselablage hinterlassen.
- Zwei gleichzeitige `Set`-Aufrufe können auf demselben alten Stand aufbauen und anschließend die Änderung des jeweils anderen überschreiben.
- Ein parallel laufender Filter kann im Schreibfenster eine leere Schlüsseldatei lesen. Wenn außerdem keine Legacy-Schlüssel vorhanden sind, kann die bestehende No-Key-Logik Eingaben unverändert durchreichen.

Der letzte Fall verbindet ein seltenes Parallelitätsfenster mit einem möglichen Klartextpfad. Er wurde nicht als Race reproduziert und ist entsprechend nicht als beobachteter Datenabfluss zu verstehen.

Quellen: [localkey.go](../internal/localkey/localkey.go), Funktion `writeKeyFile`, Zeilen 147–167, sowie `Set`, Zeilen 233–239; [filter.go](../cmd/nebel/filter.go), Zeilen 74–83.

### R05 — Die Tag-Erkennung akzeptiert weiterhin ungültige vermeintliche Ciphertexte

**Priorität: mittel; deutlich engerer Auslöser als zuvor. Nachweis: Code.**

`LooksEncrypted` prüft Anfang, Ende und einen erkannten Algorithmusnamen. Die übrigen Felder müssen nicht vorhanden oder gültig sein. Deshalb wird beispielsweise folgender Klartext weiterhin als bereits verschlüsselt behandelt:

```text
ENC[AES256_SIV,not-a-real-tag]
```

Clean reicht diesen Wert unverändert durch. Ein späterer Parse-Fehler beim Smudge verhindert nicht die vorherige Klartextausgabe durch Clean.

**Einordnung:** Das ursprüngliche beliebige `ENC[`-Präfix reicht nicht mehr aus. Die neue Bedingung ist deutlich unwahrscheinlicher, aber kein vollständiger Nachweis eines gültigen Ciphertexts. Die gewünschte Unterstützung alter Tags erklärt die tolerante Erkennung, beseitigt den Restfehler jedoch nicht.

Quellen: [tag.go](../internal/tag/tag.go), Zeilen 191–204; [filterop.go](../internal/filterop/filterop.go), insbesondere Zeile 83 und die entsprechende Prüfung in `cleanValues`.

### R06 — Erfolgreiche Verschlüsselung garantiert nicht die spätere Ausgabefähigkeit

**Priorität: mittel. Nachweis: vorhandener Laufzeittest für Steuerzeichen, Codefolgerung für Zahlen.**

Der Test `TestSmudgeValuesRejectsUnrenderableControlCharacter` bestätigt ausdrücklich: Ein YAML-Wert mit dem Steuerzeichen `0x01` wird von Clean akzeptiert und verschlüsselt, kann vom späteren Smudge aber nicht wieder ausgegeben werden. Der Checkout scheitert dann mit `ErrControlCharacterUnsupported`.

Das ist sicherer als eine stille Veränderung des Werts, lässt aber weiterhin Inhalte erfolgreich in den Verschlüsselungspfad gelangen, die das Tool anschließend nicht regulär zurückschreiben kann. Der Fehler wird erst auf der Rückrichtung sichtbar.

Ein zusätzlicher, statisch abgeleiteter Fall betrifft Zahlen: Der JSON-Parser erhält Zahlen durch `UseNumber` als Text. `validTypeLiteral` begrenzt Integer bei Smudge dagegen mit `strconv.ParseInt(value, 10, 64)` auf vorzeichenbehaftete 64 Bit. Ein JSON-Integer wie `18446744073709551615` kann somit verschlüsselt werden, während die spätere Ausgabe an der Bereichsprüfung scheitert. Dieser konkrete Zahlenwert wurde in der erneuten Prüfung nicht separat ausgeführt.

Quellen: [value_test.go](../internal/filterop/value_test.go), Zeilen 125–139; [json.go](../internal/format/json.go), Zeilen 33–34 und 143–147; [filterop.go](../internal/filterop/filterop.go), Zeilen 297–302 und 319–332.

## 5. Bestätigte Verbesserungen und verbleibende Grenzen

### Formatverarbeitung

- **P02:** Zitierte YAML-Tokens mit ` #` werden nicht mehr wie nachfolgende Kommentare abgeschnitten. Die Regression prüft den ursprünglichen Klartextrest.
- **P03/P04:** Die Pfadauflösung prüft Mehrdeutigkeiten anhand der Dokumentblätter. Punkt-/Nested-Kollisionen sowie doppelte Treffer für das JSON-Zielfeld führen zu einem Fehler.
- **P10:** Der eingebettete LF eines zitierten YAML-Strings bleibt beim Clean-/Smudge-Roundtrip erhalten. Entsprechende Tests bestehen.
- **P11:** Mehrdokument-YAML wird ausdrücklich zurückgewiesen, statt nur das erste Dokument zu berücksichtigen.
- **P13:** YAML-Blockskalare werden zurückgewiesen, statt lediglich ihren Blockindikator durch einen Tag zu ersetzen.

Die Begrenzungen für literal enthaltene Punkte in Schlüsseln, Blockskalare und Mehrdokument-YAML sind damit teilweise Nutzbarkeitseinschränkungen. Eine klar erkannte und abgelehnte Eingabe ist von einem erfolgreichen Vorgang mit ungeschütztem Geheimnis zu unterscheiden.

Quellen: [format.go](../internal/format/format.go), Funktion `checkUnambiguous`; [yaml.go](../internal/format/yaml.go), Zeilen 68–115 und Funktion `scalarText`; [format_test.go](../internal/format/format_test.go), Tests ab Zeilen 143, 218, 250 und 481; [value_test.go](../internal/filterop/value_test.go), Zeile 99.

### Typauthentisierung: neue Tags gegenüber historischen Tags

Neue Feld-Tags verwenden `AES256_SIV_TB` und beziehen den Typ in die Authentisierungsdaten ein. Die Typmanipulation an einem solchen Tag wird im Regressionstest mit einem Authentisierungsfehler abgewiesen.

Historische `AES256_SIV`-Feld-Tags werden weiterhin ohne Typbindung akzeptiert. Der bestehende Test `TestSmudgeValuesLegacyTagTypeStillUnauthenticated` bestätigt, dass ein geeigneter historischer String weiterhin durch Manipulation des Typfelds als Boolean ausgegeben werden kann. Die zusätzliche Literalprüfung begrenzt bestimmte Ausgaben, authentisiert aber den alten Typ nicht.

**Folgerung:** Die Korrektur schützt neue Tags. Sie entfernt nicht rückwirkend alte, weiterhin akzeptierte Ciphertexte aus Git-Historie oder anderen Clones. Ein Angreifer mit Schreibzugriff kann bei weiter verfügbarem alten Schlüssel grundsätzlich historische Tags erneut einbringen. Dieses Restverhalten ist im Code dokumentiert; ein neuer Tag allein beseitigt es nicht.

Quellen: [tag.go](../internal/tag/tag.go), Beschreibung der Legacy-Kompatibilität und Funktion `EncodeValue`; [filterop.go](../internal/filterop/filterop.go), Zeilen 270–299; [value_test.go](../internal/filterop/value_test.go), Tests ab Zeilen 405 und 459.

### Filterabweichungen und Checkout-Fehler

Für einen von Git an den Filter übergebenen Pfad ohne passende Regel liefert Clean jetzt `ErrNoMatchingRule`. Der zuvor gefährliche Fall `*.env` gegenüber `config/prod.env` wird dadurch blockiert. Syntaktisch ungültige Muster werden beim Laden der Konfiguration geprüft. Die unterschiedliche Mustersprache bleibt eine Bedienungseinschränkung, führt in diesem geprüften Fall aber nicht mehr zu stillem Klartext-Passthrough.

Echte Checkout-Fehler werden nun als Fehlerstatus zurückgegeben. Dateien, die lediglich auf eine noch nicht vorhandene Schlüsselversion warten, bleiben bewusst ein eingeschränkter Erfolgszustand mit Diagnose. Diese Unterscheidung ist kein unverändert offener P12-Befund.

Quellen: [filterop.go](../internal/filterop/filterop.go), Zeilen 73–76; [config.go](../internal/config/config.go), Zeilen 123–127; [filtermatch_e2e_test.go](../cmd/nebel/filtermatch_e2e_test.go); [init.go](../cmd/nebel/init.go), Zeilen 312–319.

## 6. Wartbarkeit und Nutzbarkeit

### Echte verbleibende Lücken

- **Fehlender Statusbefehl:** `nebel status` ist weiterhin in Spec 09 und der Interaktionsdokumentation beschrieben, aber nicht im Dispatcher implementiert. Eine solche Zustands-/CI-Prüfung darf daher nicht als vorhandene Absicherung vorausgesetzt werden.
- **Falsche Rotationshilfe:** Die CLI-Hilfe sagt weiterhin, Rotation berühre bestehende verschlüsselte Inhalte nicht. Die Implementierung führt dagegen eine Neuverschlüsselung aus.
- **Testabdeckung der tatsächlichen Integration:** Der Leerzeichen-Test erwartet die Ausgabe einer Hilfsfunktion, ohne deren Wirkung in Git zu prüfen. Die erfolgreiche Suite belegt deshalb für diesen Fall nicht die zugesagte Schutzwirkung.

Quellen: [main.go](../cmd/nebel/main.go), Zeilen 22–38 und 63–65; [Spec 09](../specs/09-cli-status.md); [add_test.go](../cmd/nebel/add_test.go).

### Optimierungspotenzial

Die zusätzliche Mehrdeutigkeitsprüfung durchläuft beziehungsweise parst das Dokument für jedes geschützte Feld erneut. Bei vielen Feldern und großen Dokumenten kann dies unnötige Arbeit verursachen. Solange keine problematischen Laufzeiten gemessen sind, ist dies Optimierungspotenzial und kein nachgewiesener Sicherheitsfehler.

Die Architektur bleibt grundsätzlich überschaubar. Die neuen spezifischen Fehlertypen, expliziten Formatgrenzen und Regressionstests verbessern Nachvollziehbarkeit und Wartbarkeit. Die offenen Punkte betreffen überwiegend Grenzen zwischen Komponenten: Git-Attributsyntax, Arbeitsbaum versus Index, dauerhafte Schlüsselablage und zulässige Werte bei Clean versus Smudge.

## 7. Schlussbewertung und Grenzen einer Freigabe

Die erfolgreiche bestehende Testsuite und das unauffällige Vet-Ergebnis sind positive Nachweise, aber keine Widerlegung der verbleibenden Probleme. Insbesondere R01 zeigt direkt, dass eine neue Korrektur samt passendem Unit-Test die tatsächliche Integration weiterhin verfehlen kann.

Für eine uneingeschränkte Einsatzempfehlung fehlen insbesondere belastbare Nachweise gegen die verbliebenen Klartext- und Indexverlustpfade sowie ein abgesichertes Verhalten bei unterbrochenen Rotationen und Schlüsseldateischreibvorgängen. Die bereits behobenen Punkte sollten dabei nicht weiter pauschal als offen geführt werden.

Dieser Bericht dokumentiert den Stand `8599e77`. Er enthält keine umgesetzten Fehlerbehebungen und keine Untersuchung bereits veröffentlichter Geheimnisse. Frühere Testartefakte und die ursprüngliche ausführliche Analyse sind nicht automatisch Teil dieses aktuellen Checkouts; die vorliegende Datei hält deshalb die erneuten Befunde und ihre Nachweisgrenzen eigenständig fest.

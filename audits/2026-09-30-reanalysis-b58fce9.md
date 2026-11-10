# Erneute Analyse nach den Korrekturen R01–R06

Berichtsdatum: 30. September 2026

Geprüfter Commit: `b58fce9` — `Merge pull request #12 from MuffinUser/worktree-audit-fixes-r01-r06`

Vergleichsstand: `8599e77`

Schwerpunkte: Sicherheit, Wartbarkeit und Nutzbarkeit. Dieser Bericht verschriftlicht die zuletzt durchgeführte Analyse und deren Testergebnisse. Seine Erstellung beinhaltet keinen weiteren Testlauf und keine Fehlerbehebung.

## 1. Gesamtbewertung

Der untersuchte Stand verbessert die Sicherheit erneut deutlich. Die bisherigen Fehlerfälle R01 (Leerzeichen in Dateinamen), R02 (Verlust ausschließlich gestagter Änderungen) und R06 (Verschlüsselung nicht wieder ausgebbarer Werte) sind für die geprüften Szenarien behoben.

R03, R04 und R05 wurden ebenfalls verbessert, bleiben aber teilweise offen:

- Bei Rotation wird ein automatisch erzeugtes Passwort rechtzeitig angezeigt. Der neue Hinweis zur Wiederherstellung nach Fehlern beschreibt jedoch Git falsch und kann den Benutzer zum Verwerfen anderer lokaler Änderungen verleiten.
- Die Schlüsseldatei wird jetzt atomar ausgetauscht. Parallele Prozesse können sich bei der Lesen-Ändern-Schreiben-Sequenz weiterhin gegenseitig Änderungen überschreiben.
- Die Tag-Erkennung ist strenger, akzeptiert aber noch bestimmte ungültige Zeichenfolgen als bereits verschlüsselt.

Die Bewertung fällt deshalb weniger kritisch aus als beim ursprünglichen Stand: Häufigere Klartext- und Datenverlustfälle wurden weitgehend geschlossen. Eine pauschale Sicherheitsfreigabe ergibt sich daraus weiterhin nicht. Die verbleibenden Risiken betreffen insbesondere Fehlerbehandlung, Nebenläufigkeit, historische Kompatibilität und eine engere Klartext-Erkennungslücke.

Dieser Bericht weist keine tatsächliche Kompromittierung eines Benutzer-Repositories nach.

## 2. Umfang und Verifikation

Geprüft wurden insbesondere die Änderungen zwischen `8599e77` und `b58fce9`, ihre Tests und die weiterhin relevanten angrenzenden Codepfade. Dazu gehörten Git-Attributsyntax, Dirty-Prüfung, Rotation, Schlüsselablage, Tag-Erkennung und die Vorabprüfung von Feldwerten.

### Ausgeführte Prüfungen

Unter Go 1.27.1 auf Linux/amd64:

```bash
go vet ./...
go test ./... -count=1 -timeout 120s
```

Aufgerufen wurde `/usr/lib/go-1.24/bin/go` mit `GOTOOLCHAIN=auto` und entsprechend ergänzt gesetztem `PATH`. Die Prüfung verwendete die automatisch ausgewählte Go-1.27.1-Toolchain. Der Go-Buildcache benötigte Schreibzugriff außerhalb der eingeschränkten Umgebung.

| Prüfung | Ergebnis |
|---|---|
| `go vet ./...` | Exitcode 0, keine Meldungen |
| Vollständige vorhandene Testsuite | Exitcode 0; alle neun Pakete erfolgreich |
| Zusätzliche gezielte Tests und Vet für `internal/tag` und `internal/filterop` | Erfolgreich |
| Repository-Zustand nach der Analyse | Sauber; keine Änderungen durch die Analyse |

Die neun erfolgreich geprüften Pakete waren `cmd/nebel`, `internal/config`, `internal/filterop`, `internal/format`, `internal/gitutil`, `internal/kdf`, `internal/localkey`, `internal/siv` und `internal/tag`. `-count=1` schloss die Wiederverwendung gecachter Testergebnisse aus.

### Nachweisgrenzen

- **Laufzeitbeleg:** Eine Eigenschaft wurde durch einen tatsächlich ausgeführten Test geprüft.
- **Codebeleg:** Der relevante Ablauf ist unmittelbar in der Implementierung erkennbar.
- **Folgerung:** Eine Auswirkung wird aus diesem Ablauf abgeleitet, wurde aber nicht notwendigerweise separat reproduziert.

Die neu beschriebenen Restfälle der Tag-Erkennung, eine Unterbrechung nach dem Stagen während Rotation sowie konkurrierende Schlüsseldateischreibvorgänge verschiedener Prozesse wurden in dieser Runde nicht als zusätzliche Laufzeitreproduktionen ausgeführt.

Es gab keine neue Schwachstellendatenbankprüfung, keine Prüfung veröffentlichter Binärartefakte und keine Untersuchung realer Benutzer-Repositories auf frühere Offenlegungen. Die Linux-Prüfungen sind kein eigener Laufzeitnachweis für Windows oder macOS.

## 3. Status der sechs zuletzt beschriebenen Befunde

| Befund | Status | Begründung |
|---|---|---|
| R01: Dateinamen mit Leerzeichen | Behoben für die geprüften Fälle | Git-kompatible zitierte Muster; Integrationstest prüft die tatsächliche Attributauflösung. |
| R02: Verlust ausschließlich gestagter Änderungen | Behoben für den bisherigen Fehlerfall | Separate Vergleiche von Arbeitsbaum und Index gegen HEAD; Regressionstest für `HEAD=A`, Index=`B`, Arbeitsbaum=`A`. |
| R03: unvollständige Rotation / verspätete Passwortanzeige | Teilweise behoben | Passwort erscheint vor Zustandsänderungen. Die Rotation bleibt nicht transaktional; der neue Rücksetz-Hinweis ist falsch. |
| R04: nicht atomare Schlüsseldatei | Wesentlich verbessert, teilweise offen | Temporäre Datei, Synchronisierung und Rename verhindern unvollständige Beobachtungen. Die Sperre wirkt nur innerhalb eines Prozesses. |
| R05: ungültige Tags verhindern Verschlüsselung | Weiter eingegrenzt, teilweise offen | Mehr Feldprüfungen vorhanden; doppelte Felder, fehlende Pflichtkombinationen und leere Daten werden noch nicht zuverlässig ausgeschlossen. |
| R06: verschlüsselt, aber später nicht ausgebbar | Behoben für die bisherigen Fälle | Clean prüft Literal und Renderbarkeit vor der Verschlüsselung. |

### R01 — Korrekte Attributsyntax und aussagekräftigerer Test

Die Escape-Funktion verwendet für Muster mit Leerzeichen nun eine doppelt zitierte Form anstelle eines Backslashs vor dem Leerzeichen. Der neue Integrationstest legt eine tatsächliche `.gitattributes` in einem temporären Git-Repository an und prüft die Zuordnung mit `git check-attr`.

Dies schließt nicht nur den bisherigen Fehlerfall, sondern verbessert die Aussagekraft des Tests: Er prüft die tatsächliche Git-Wirkung und nicht ausschließlich einen erwarteten Ausgabestring der Hilfsfunktion.

Quellen: [add.go](../cmd/nebel/add.go), Funktion `escapeGitattributesPattern`; [add_test.go](../cmd/nebel/add_test.go), Funktion `TestEscapeGitattributesPatternResolvesInGit`.

### R02 — Arbeitsbaum und Index werden getrennt berücksichtigt

`DirtyFiles` vereinigt die Ergebnisse von `git diff HEAD` und `git diff --cached HEAD`. Damit wird auch eine Änderung erkannt, die nur noch im Index vorhanden ist, während der Arbeitsbaum bereits wieder HEAD entspricht.

Der neue Test bildet die frühere Konstellation direkt nach. Für normale Git-Zustände wurde in dieser Prüfung kein weiterer Bypass dieses Schutzes gefunden. Das ist keine Aussage über beliebige ungewöhnliche Git-Flags oder nicht geprüfte Dateisystemzustände.

Quellen: [gitutil.go](../internal/gitutil/gitutil.go), ab Zeile 286; [gitutil_test.go](../internal/gitutil/gitutil_test.go), Funktion `TestCheckoutAllRefusesIndexOnlyDirtyState`.

### R06 — Frühe Ablehnung statt späterem Checkout-Fehler

Vor dem Verschlüsseln eines neuen Feldwerts ruft Clean jetzt dieselbe Literalprüfung und die Render-Funktion auf, die beim späteren Smudge relevant sind. Die früher beschriebenen Fälle mit nicht renderbaren YAML-Steuerzeichen beziehungsweise außerhalb der akzeptierten Zahlenbereiche liegenden Werten werden dadurch bereits vor der Verschlüsselung abgelehnt.

Das ist eine Sicherheits- und Nutzbarkeitsverbesserung durch frühe Fehlererkennung, keine Erweiterung der unterstützten Wertemenge. Größere Zahlen oder besondere YAML-Zahlenformen werden nicht automatisch unterstützt, nur weil ihre Ablehnung jetzt früher erfolgt.

Quellen: [filterop.go](../internal/filterop/filterop.go), Zeilen 207–219; [value_test.go](../internal/filterop/value_test.go), Regressionstests für nicht wieder ausgebbare Werte.

## 4. Priorisierte verbleibende Probleme

### 4.1 Fehlerhafte Wiederherstellungsanleitung nach Rotationsfehlern

**Einordnung:** echter Betriebs- und Nutzbarkeitsfehler. Hohe Konfidenz aus Code und Git-Befehlssemantik; kein zusätzlicher Fehler-Injektionstest.

Der neue `rotateRecoveryHint` behauptet, `git checkout -- .` verwerfe die Rotation vollständig. Dieser Befehl stellt jedoch den Arbeitsbaum aus dem Index wieder her, nicht aus HEAD. Rotation kann die neue `.nebel.yaml` und migrierte Dateien zu diesem Zeitpunkt bereits gestagt haben.

**Folgerungen:**

- Die gestagten Rotationsänderungen bleiben bestehen; der behauptete vollständige Rücksetzvorgang findet nicht statt.
- Andere nicht gestagte Änderungen im Arbeitsbaum können durch den breit wirkenden Befehl verworfen werden.
- Ein Benutzer kann nach Befolgen der Anleitung irrtümlich von einem vollständig zurückgesetzten Zustand ausgehen.

Die ebenfalls erwähnte Alternative `git reset --hard HEAD` ist ausdrücklich destruktiv und wird in der Meldung zwar eingeschränkt, macht die erste Behauptung aber nicht korrekt. Die Befehle wurden während der Analyse nicht auf dem Benutzer-Repository ausgeführt.

**Was tatsächlich behoben ist:** Ein automatisch erzeugtes Passwort wird nun unmittelbar nach der Erzeugung und vor den zustandsverändernden Schritten angezeigt. Der bisherige Pfad „neuer Schlüssel aktiv, Passwort wegen späteren Fehlers nie angezeigt“ ist damit geschlossen.

**Was offen bleibt:** Die Rotation selbst ist weiterhin nicht atomar. Ein zusätzlicher Text mit Wiederherstellungshinweisen ersetzt keinen nachgewiesenen Wiederanlauf- oder Rücksetzablauf. Insbesondere wurde kein Test gefunden, der einen Fehler nach dem Stagen provoziert und anschließend die behauptete vollständige Wiederherstellung prüft.

Quellen: [rotate.go](../cmd/nebel/rotate.go), Passwortausgabe ab Zeile 82, Staging ab Zeile 152, `rotateRecoveryHint` ab Zeile 174.

### 4.2 Ungültige tagähnliche Klartexte können weiterhin unverschlüsselt bleiben

**Einordnung:** echter, aber enger eingabeabhängiger Vertraulichkeitsfehler; mittlere Priorität. Codebeleg mit hoher Konfidenz, neue Beispiele nicht separat ausgeführt.

`LooksEncrypted` prüft inzwischen erkannte Algorithmusnamen, ein vorhandenes `data:`-Feld, Base64-Dekodierbarkeit und die Syntax einzelner weiterer Felder. Die folgenden Bedingungen fehlen jedoch weiterhin:

- keine doppelten Felder;
- konsistente Reihenfolge beziehungsweise eine eindeutig akzeptierte Grammatik;
- erforderliche Feldkombinationen für typgebundene Tags;
- Ausschluss leerer Ciphertext-Daten.

Damit passieren unter anderem diese Zeichenfolgen die Erkennung:

```text
ENC[AES256_SIV,data:]
ENC[AES256_SIV,data:AAAA,data:AAAA]
ENC[AES256_SIV_TB,data:AAAA]
```

Clean behandelt solche Eingaben als bereits verschlüsselt und reicht sie unverändert durch. Die reguläre Tag-Verarbeitung akzeptiert diese Formen nicht als gültige aktuelle Tags. Leere Base64-Daten lassen sich zwar dekodieren, sind aber kein erfolgreich erzeugter AES-SIV-Ciphertext.

**Folgerung:** Ein tatsächlicher Klartextwert, der eine dieser Formen hat, wird weiterhin nicht geschützt. Der Auslöser ist wesentlich spezieller als beim ursprünglichen bloßen `ENC[`-Präfix. Der konkrete Fehlerfall des vorherigen Berichts, `ENC[AES256_SIV,not-a-real-tag]`, wird inzwischen dagegen korrekt als nicht verschlüsselt erkannt.

Die Kommentarbehauptung, der Unterschied zu `Parse` beschränke sich auf ein optionales historisches Schlüsselfeld, entspricht deshalb nicht dem gesamten implementierten Verhalten.

Quellen: [tag.go](../internal/tag/tag.go), Zeilen 198–235; [filterop.go](../internal/filterop/filterop.go), Prüfung in `Clean` ab Zeile 83 und in `cleanValues`.

### 4.3 Prozessübergreifende konkurrierende Schlüsseländerungen

**Einordnung:** echter Nebenläufigkeitsfehler unter paralleler Nutzung; mittlere Priorität. Codebeleg, kein prozessübergreifender Belastungstest.

Die neue Schreibweise verwendet eine temporäre Datei, `Sync`, gesetzte Rechte und anschließendes Rename. Dadurch wird unter der hier untersuchten Linux-Umgebung der frühere Kürzungszustand vermieden: Ein paralleler Leser soll einen vollständigen alten oder neuen Stand sehen.

Die neue Sperre ist allerdings ein `sync.Mutex` innerhalb des Prozesses. Sie verhindert nicht, dass zwei unabhängige `nebel`-Prozesse denselben alten Inhalt lesen und danach jeweils unterschiedliche Ergänzungen veröffentlichen.

Beispiel der möglichen Ablaufreihenfolge:

1. Prozess A und B lesen beide die Schlüsseldatei mit Version 1.
2. A ergänzt Version 2; B ergänzt Version 3.
3. A schreibt den vollständigen Stand 1+2.
4. B schreibt den vollständigen Stand 1+3.
5. Version 2 ist anschließend nicht mehr in der Datei enthalten.

Auch zwei parallele Rotationen können dieselbe nächste Versionsnummer mit unterschiedlichen Schlüsseln erzeugen. Die Einschränkung ist im Code ausdrücklich dokumentiert. Das schafft Transparenz, verhindert den möglichen Konflikt aber nicht.

**Abgrenzung:** Der frühere Klartextpfad durch eine vorübergehend leere Schlüsseldatei wird hier ausdrücklich nicht unverändert fortgeschrieben. Das atomare Ersetzen ist eine wirksame Verbesserung; das Restproblem liegt in der nicht prozessübergreifend serialisierten Gesamtoperation.

Quellen: [localkey.go](../internal/localkey/localkey.go), Beschreibung von `setMu` ab Zeile 38, `writeKeyFile` ab Zeile 166 und `Set` ab Zeile 273; [rotate.go](../cmd/nebel/rotate.go), Berechnung und Speicherung der neuen Schlüsselversion.

### 4.4 Historische Tags behalten die alte Typmanipulierbarkeit

**Einordnung:** fortbestehende Integritätsgrenze der Rückwärtskompatibilität; relevant bei historischen Tags und Angreifern mit Schreibzugriff.

Neue Tags vom Typ `AES256_SIV_TB` authentisieren den Feldtyp und sind vom ursprünglichen Typwechsel nicht betroffen. Historische `AES256_SIV`-Feld-Tags werden weiterhin ohne Typbindung akzeptiert. Der vorhandene Test `TestSmudgeValuesLegacyTagTypeStillUnauthenticated` belegt weiterhin einen erfolgreichen Typwechsel für einen geeigneten historischen Wert.

Die Literalprüfung verwendet Go-Zahlen- und Booleanparser. Deren akzeptierte Zeichenfolgen sind nicht mit gültigen JSON-Literalen identisch. Beispielsweise kann ein historischer String `NaN` nach Änderung des Typs zu `float` die Literalprüfung passieren; die anschließende unquotierte Ausgabe ist dennoch kein gültiges JSON. Ein historischer String `1` kann nach Typänderung zu `bool` die Go-Prüfung bestehen und als JSON-Zahl statt Boolean ausgegeben werden.

Diese erweiterten Beispiele wurden statisch abgeleitet und nicht separat reproduziert. Sie erfordern passenden historischen Inhalt sowie die Möglichkeit, dessen Tag zu ändern. Sie sind kein Nachweis einer Manipulationsmöglichkeit an neuen typgebundenen Tags.

Quellen: [filterop.go](../internal/filterop/filterop.go), Legacy-AAD und Renderpfad ab Zeile 284 sowie `validTypeLiteral` ab Zeile 333; [json.go](../internal/format/json.go), Zeilen 163–175; [value_test.go](../internal/filterop/value_test.go), Funktion `TestSmudgeValuesLegacyTagTypeStillUnauthenticated`.

## 5. Wartbarkeit und Nutzbarkeit

### Fortschritte

- Der neue Attributtest prüft die tatsächliche Git-Integration. Damit wurde eine wesentliche Schwäche des bisherigen Stringvergleichs behoben.
- Die Dirty-Prüfung bildet Arbeitsbaum und Index nun als unterschiedliche Zustände ab.
- Die Vorabprüfung in Clean verhindert, dass bekannte, nicht ausgebbare Werte erst beim späteren Checkout auffallen.
- Die atomare Schlüsseldatei und der Regressionstest für parallele Aufrufe innerhalb eines Prozesses verbessern Robustheit und Testabdeckung.

### Weiterhin bestehende Lücken

- **Statusbefehl:** Der in Spec 09 und der Interaktionsdokumentation beschriebene `nebel status` ist weiterhin nicht im Dispatcher vorhanden. Er darf nicht als vorhandene Zustands- oder CI-Prüfung vorausgesetzt werden.
- **Rotationshilfe:** Die CLI-Hilfe behauptet weiterhin, Rotation berühre vorhandene verschlüsselte Inhalte nicht, obwohl die Implementierung sie neu verschlüsselt.
- **Funktionsumfang:** Bestimmte YAML-Formen, Sonderzeichen und Zahlenwerte bleiben bewusst nicht unterstützt. Ihre frühe Zurückweisung ist von einem erfolgreichen Vorgang mit falscher Schutzwirkung zu unterscheiden.
- **Recovery-Tests:** Ein fehlerfreier Rotationslauf belegt nicht die Richtigkeit der neuen Anweisungen nach einem Teilfehler.

Quellen: [main.go](../cmd/nebel/main.go), Dispatcher und Hilfe ab Zeile 63; [Spec 09](../specs/09-cli-status.md); [rotate.go](../cmd/nebel/rotate.go), Funktion `rotateRecoveryHint`.

### Reines Härtungs- beziehungsweise Optimierungspotenzial

Zusätzliche Verzeichnissynchronisierung nach dem Rename könnte die Dauerhaftigkeit bei Stromausfällen weiter absichern. Ohne gesonderten Stromausfalltest ist dies kein nachgewiesener aktueller Alltagsfehler. Ebenso bleibt weniger wiederholtes Parsen pro geschütztem Feld ein mögliches Performance-Thema, solange keine relevanten Laufzeitprobleme gemessen sind.

## 6. Bedeutung der erfolgreichen Tests

Die grüne Testsuite ist ein belastbarer Nachweis für die dort geprüften Eigenschaften, insbesondere die neuen R01-, R02- und R06-Regressionsfälle. Sie bestätigt jedoch nicht automatisch sämtliche Behauptungen in Kommentaren und Fehlermeldungen.

Bei den verbleibenden Problemen liegen die Unterschiede jeweils an einer Grenze:

- Arbeitsbaum aus dem Index wiederherstellen ist nicht dasselbe wie eine Rotation auf HEAD zurücksetzen.
- Einzelne Tag-Felder syntaktisch prüfen ist nicht dasselbe wie einen vollständigen gültigen Tag erkennen.
- Einen Dateiaustausch atomar machen ist nicht dasselbe wie die gesamte Aktualisierung gegen konkurrierende Prozesse absichern.
- Go-Literale akzeptieren ist nicht dasselbe wie gültige Literale des jeweiligen Ausgabeformats garantieren.

Diese Unterscheidungen erklären, warum Vet und vorhandene Tests erfolgreich sein können, während die beschriebenen Restfehler bestehen bleiben.

## 7. Abschluss und Geltungsbereich

Die häufigeren zuvor gefundenen Fehler sind weitgehend geschlossen. Die verbleibenden Probleme sind enger begrenzt, aber teilweise weiterhin sicherheits- oder datenrelevant. Insbesondere die Fehleranleitung bei Rotation sollte nicht als nachgewiesener vollständiger Rücksetzweg behandelt werden; die Tag-Erkennung ist weiterhin kein vollständiger Gültigkeitsnachweis.

Die Analyse bezieht sich ausschließlich auf Commit `b58fce9`. Sie enthält keine implementierten Änderungen und keine Aussage darüber, ob frühere Versionen in realen Repositories bereits Geheimnisse offengelegt haben. Der Bericht hält sowohl die Verbesserungen als auch die verbleibenden Risiken und ihre jeweiligen Nachweisgrenzen fest.

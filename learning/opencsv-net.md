# opencsv (opencsv.net) — Learning Notes

Notes on the opencsv library: what it is, how its API is organized, and — most
importantly — the extension points it exposes for building on top of it.

> **Naming note:** "opencsv.net" refers to the opencsv project hosted at
> [opencsv.sf.net](https://opencsv.sourceforge.net/) (SourceForge). Its original
> Maven group ID was `net.sf.opencsv`; since version 3.x the coordinates are
> `com.opencsv:opencsv`. It is a **Java** library (not a .NET port).

## 1. Quick facts

| Item | Value |
|---|---|
| Purpose | Simple, configurable CSV reading/writing for Java |
| Latest version | 5.12.0 (published 2025-07-26) |
| License | Apache 2.0 (commercial-friendly) |
| Java requirement | Java 8+ (JPMS/module support on Java 9+) |
| Maven coordinates | `com.opencsv:opencsv:5.12.0` |
| Website / docs | <https://opencsv.sourceforge.net/> |
| Source repository | `git clone https://git.code.sf.net/p/opencsv/source` (Maven build) |

Runtime dependencies (all Apache Commons):

- `commons-beanutils:commons-beanutils:1.11.0` (pulls in `commons-logging`, `commons-collections` 3.x)
- `org.apache.commons:commons-collections4:4.5.0`
- `org.apache.commons:commons-lang3:3.18.0`
- `org.apache.commons:commons-text:1.13.1`

Gradle:

```groovy
implementation 'com.opencsv:opencsv:5.12.0'
```

Core strengths: arbitrary numbers of values per line, commas inside quoted
elements, multi-line quoted entries, configurable separator/quote/escape
characters, two-way bean binding, and multi-threaded bean conversion.

## 2. Core API

### Reading (low level)

`CSVReader` returns each record as a `String[]`. Build it with
`CSVReaderBuilder`:

```java
try (CSVReader reader = new CSVReaderBuilder(new FileReader("file.csv")).build()) {
    String[] nextLine;
    while ((nextLine = reader.readNext()) != null) {
        // process fields
    }
}
```

- `reader.readAll()` slurps everything into a `List<String[]>`.
- `CSVIterator` / `reader.iterator()` supports for-each iteration.
- `CSVReaderHeaderAware.readMap()` returns each row as a
  `Map<String, String>` keyed by header name, without defining a bean.

### Parsers

Field splitting is delegated to an `ICSVParser`, of which two implementations
ship with the library:

- **`CSVParser`** — the original, highly configurable parser; best for
  non-standard CSV (custom separators, escape characters).
- **`RFC4180Parser`** — strict RFC 4180 compliance; uses doubled quotes
  (`""`) for escaping instead of an escape character. Prefer this when
  interoperating with other RFC-compliant tools.

```java
CSVReader reader = new CSVReaderBuilder(fileReader)
    .withCSVParser(new CSVParserBuilder()
        .withSeparator('\t')
        .withQuoteChar('\'')
        .build())
    .build();
```

### Writing

```java
try (CSVWriter writer = new CSVWriterBuilder(new FileWriter("file.csv"))
        .withSeparator('\t')
        .build()) {
    writer.writeNext(new String[] {"first", "second", "third"});
}
```

## 3. Bean binding

The higher-level API maps CSV rows to/from annotated Java beans.

### Reading into beans

```java
List<MyBean> beans = new CsvToBeanBuilder<MyBean>(new FileReader("file.csv"))
    .withType(MyBean.class)
    .build()
    .parse();
```

### Writing beans

```java
try (Writer writer = new FileWriter("file.csv")) {
    StatefulBeanToCsv<MyBean> beanToCsv =
        new StatefulBeanToCsvBuilder<MyBean>(writer).build();
    beanToCsv.write(beans);
}
```

### Annotations

By header name: `@CsvBindByName`, `@CsvBindAndSplitByName` (one column → a
`Collection`), `@CsvBindAndJoinByName` (several columns → a
`MultiValuedMap`), `@CsvCustomBindByName` (custom converter).

By position: `@CsvBindByPosition`, `@CsvBindAndSplitByPosition`,
`@CsvBindAndJoinByPosition`, `@CsvCustomBindByPosition`.

Type conversion and structure: `@CsvDate` (any `TemporalAccessor` plus legacy
`Date`, with separate `writeFormat` since 5.0), `@CsvNumber` (pattern +
locale), `@CsvRecurse` (nested beans), `@CsvIgnore`.

```java
public class Visitors {
    @CsvBindByName(required = true)
    private String firstName;

    @CsvBindByName(column = "Last Name")
    private String lastName;

    @CsvBindByName
    @CsvNumber("#,###")
    private int visitsToWebsite;

    @CsvBindByName(column = "valid since")
    @CsvDate(value = "yyyy-MM-dd", writeFormat = "MM/dd/yyyy")
    private LocalDate startDate;
}
```

### Mapping strategies

The builders pick a strategy automatically from the annotations present, but
you can supply one explicitly with `withMappingStrategy(...)`:

- `HeaderColumnNameMappingStrategy` — exact header-name match
- `ColumnPositionMappingStrategy` — by column index
- `HeaderColumnNameTranslateMappingStrategy` — maps arbitrary header names to
  field names via a translation map
- `FuzzyMappingStrategy` — fuzzy string matching between headers and field
  names (minimizes annotation boilerplate)

## 4. Building on top of opencsv — extension points

The documentation's stated design goal is that opencsv "should be configurable
enough to process almost all csv files but be extensible" — extension is done
by implementing small interfaces and plugging them into the builders or
annotations. These are the supported seams:

### 4.1 Custom field converters

For one-off field types, extend `AbstractBeanField` and attach it with
`@CsvCustomBindByName` / `@CsvCustomBindByPosition`:

```java
public class ConvertSalaryWithCurrency extends AbstractBeanField<BigDecimal, String> {
    @Override
    protected Object convert(String value) throws CsvDataTypeMismatchException {
        // strip currency symbol, handle locale, etc.
        return new BigDecimal(value.replaceAll("[^0-9.]", ""));
    }
}

@CsvCustomBindByName(converter = ConvertSalaryWithCurrency.class)
private BigDecimal salary;
```

For converting the *elements* of split/joined collections, extend
`AbstractCsvConverter` and implement both directions:

```java
public class TextToTeacher extends AbstractCsvConverter {
    @Override
    public Object convertToRead(String value) { /* String -> Teacher */ }
    @Override
    public String convertToWrite(Object value) { /* Teacher -> String */ }
}
```

### 4.2 Custom mapping strategies

Implement the `MappingStrategy<T>` interface (or, in practice, extend one of
the shipped strategies) to control header handling and field lookup entirely —
e.g. to support a proprietary header scheme or computed columns:

```java
MappingStrategy<MyBean> strategy = new FuzzyMappingStrategyBuilder<MyBean>().build();
strategy.setType(MyBean.class);
List<MyBean> beans = new CsvToBeanBuilder<MyBean>(reader)
    .withMappingStrategy(strategy)
    .build()
    .parse();
```

### 4.3 Validators

Three granularities, all pluggable via builder methods or annotations:

- **`LineValidator`** — sees the raw line *before* parsing
  (`builder.withLineValidator(...)`). Example: reject lines containing a
  forbidden string.
- **`RowValidator`** — sees the parsed `String[]`
  (`builder.withRowValidator(...)`). `RowFunctionValidator` wraps a lambda:

  ```java
  RowValidator threeColumns = new RowFunctionValidator(
      row -> row.length == 3, "Row must have three columns!");
  ```
- **`StringValidator`** via `@PreAssignmentValidator` — validates a single
  field value before conversion/assignment:

  ```java
  @PreAssignmentValidator(validator = MustMatchRegexExpression.class,
                          paramString = "^[0-9]{3,6}$")
  @CsvBindByName(column = "id")
  private int beanId;
  ```

Validation failures surface as `CsvValidationException`.

### 4.4 Processors (data mutation before binding)

- **`RowProcessor`** (`builder.withRowProcessor(...)`) mutates the whole
  parsed row, e.g. normalizing blanks to `null`:

  ```java
  public class BlankColumnsBecomeNull implements RowProcessor {
      @Override
      public void processRow(String[] row) {
          for (int i = 0; i < row.length; i++) {
              if (row[i] != null && row[i].isEmpty()) row[i] = null;
          }
      }
  }
  ```
- **`StringProcessor`** via `@PreAssignmentProcessor` transforms one field
  value, e.g. substituting a default for empty strings:

  ```java
  @PreAssignmentProcessor(processor = ConvertEmptyToDefault.class, paramString = "N/A")
  @CsvBindByName(column = "status")
  private String status;
  ```

### 4.5 Custom parsers

If neither `CSVParser` nor `RFC4180Parser` fits (exotic quoting/escaping
rules), implement `ICSVParser` (`parseLine`, `parseLineMulti`, …) and inject it
with `CSVReaderBuilder.withCSVParser(new MyCustomParser())`. Everything above
the parser (readers, bean binding, validators) works unchanged.

### 4.6 Error-handling policy

`CsvExceptionHandler` decides, per exception, whether bean conversion should
throw, queue, or ignore:

```java
CsvToBean<MyBean> csv = new CsvToBeanBuilder<MyBean>(reader)
    .withType(MyBean.class)
    .withExceptionHandler(e -> e)   // queue instead of throwing
    .build();
List<MyBean> beans = csv.parse();
List<CsvException> problems = csv.getCapturedExceptions();
```

Returning the exception queues it (retrieve with `getCapturedExceptions()`),
throwing it aborts processing, returning `null` silently drops the row.

### 4.7 Locales and formats

`@CsvBindByName(locale = "de-DE")` combined with `@CsvNumber` / `@CsvDate`
handles locale-specific parsing and formatting per field, with independent
read and write formats since 5.0.

## 5. Building opencsv itself from source

```bash
git clone https://git.code.sf.net/p/opencsv/source opencsv
cd opencsv
mvn package        # requires Maven 3.3+, JDK 8+
```

Browse online at
<https://sourceforge.net/p/opencsv/source/ci/master/tree/>. Tests use JUnit 5,
Mockito, and Spock.

## 6. Practical guidance for building on top

1. **Prefer the builders** (`CSVReaderBuilder`, `CsvToBeanBuilder`,
   `StatefulBeanToCsvBuilder`) over constructors — every extension point above
   is wired through them.
2. **Choose the parser deliberately**: `RFC4180Parser` for interop-clean data,
   `CSVParser` for messy real-world files.
3. **Layer your logic in the intended order**: line validators → parser → row
   validators → row processors → field processors/validators → converters →
   bean. Putting cleanup in a `RowProcessor` keeps converters simple.
4. **Wrap, don't fork**: nearly all customization (types, validation,
   cleanup, error policy, header schemes) is achievable via the public
   interfaces, so an application-level facade over the builders is usually all
   a wrapper library needs.
5. **Mind the transitive dependencies** (four Apache Commons artifacts) when
   embedding opencsv in dependency-audited projects; all are Apache-2.0.

## Sources

- Official site and user guide: <https://opencsv.sourceforge.net/>
- Source repository info: <https://opencsv.sourceforge.net/scm.html>
- Dependency report: <https://opencsv.sourceforge.net/dependencies.html>
- SourceForge project: <https://sourceforge.net/projects/opencsv/>
- Maven Central: <https://central.sonatype.com/artifact/com.opencsv/opencsv>

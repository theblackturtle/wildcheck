# wildcheck

A simple tool to detect wildcards domain based on Amass's wildcards detector.

## Installation:

```
GO111MODULE=on go get -u github.com/theblackturtle/wildcheck
```

## Usage

```
Usage of wildcheck:
  -d string
        Main domain
  -i string
        Subdomains list. Default is stdin (default "-")
  -rate int
        Max DNS Limit per second (default 20000)
  -t int
        Threads (default 10)
```

## Example commands

#### Input from Stdin

```
cat subdomains.lst | wildcheck -t 10 -d example.com
```

#### Input from file

```
wildcheck -i subdomains.lst -t 10 -d example.com
```

## Credits:

Based on the work on Amass project by @caffix.


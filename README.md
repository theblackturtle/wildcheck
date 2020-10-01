# wildcheck
A simple tool to detect wildcards domain based on Amass's wildcards detector.

## Installation:
```
GO111MODULE=on go get -u github.com/theblackturtle/wildcheck
```

## Features
- Check resolvers are working or not.
- Check your IP Address is blocked in resolver or not.
- Auto detect main domain (If you input the list with different domains)
- Use CNAME, A, AAAA to detect wildcards domain
- Get resolvers from Public-DNS based on your ip address location.

## Usage
```
Usage of wildcheck:
  -i string
        Subdomains list. Default is stdin (default "-")
  -p    Get resolvers from Public-DNS
  -r string
        Your resolvers list
  -t int
        Threads to use (default 10)
```

## Example commands
#### Input from Stdin
```
cat subdomains.lst | wildcheck -t 100
```
#### Input from file
```
wildcheck -i subdomains.lst -t 100
```
#### Get resolvers from resolvers file and Public-DNS
```
wildcheck -i subdomains.lst -r resolvers.txt -p -t 100
```

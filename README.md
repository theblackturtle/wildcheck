# wildcheck
A simple tool to detect wildcards domain based on Amass's wildcards detector.

## Features
- Check resolvers are working or not.
- Check your IP Address is blocked in resolver or not.
- Auto detect main domain (If you input the list with different domains)
- Use CNAME, A, AAAA to detect wildcards domain
- Get resolvers from Public-DNS based on your ip address location.

## Usage
```
Usage of ./wildcheck:
  -i string
        Subdomains list
  -p    Use public-dns
  -r string
        Your resolvers list
  -t int
        Threads to use (default 10)
```
# vuxml-go

`vuxml-go` is a Go port of the original Python [`vuxml`](https://github.com/HubTou/vuxml/) utility by Hubert Tournier.

- Fetches and caches the latest VuXML.
- Flexible search: by ID, topic, package, date, CVE, etc.
- Colorized, human-friendly terminal output.
- Static binaries for Linux and FreeBSD (amd64/arm64).

## Install

**From source:**

```sh
make
sudo cp vuxml-go-$(go env GOOS)-$(go env GOARCH) /usr/local/bin/vuxml-go
```
## Usage
```sh
vuxml-go -desc -package "openssl~1.1.1u"
vuxml-go -id 73a697d7-1d0f-11ef-a490-84a93843eb75
vuxml-go -keyword "Remote Code Execution"
vuxml-go -latest 5
vuxml-go -package curl
vuxml-go -package "open.*" -re-names
vuxml-go -ref "cvename~CVE-2023-2975"
vuxml-go -topic openssl
```

### Options

| Flag               | Description                                                                |
| ------------------ | -------------------------------------------------------------------------- |
| `-desc`            | Print the full vulnerability description.                                  |
| `-discovery DATE`  | Search for the specified dates (YYYY, YYYY-MM, YYYY-MM-DD).                |
| `-entry DATE`      | Search for the specified dates (YYYY, YYYY-MM, YYYY-MM-DD).                |
| `-id VID`          | Search for the specified Vulnerability ID.                                 |
| `-keyword RE`      | Search for the specified regex in topics and descriptions.                 |
| `-latest N`        | Show the N latest vulnerabilities.                                         |
| `-modified DATE`   | Search for the specified dates (YYYY, YYYY-MM, YYYY-MM-DD).                |
| `-package PID`     | Search for the specified name in affected packages (`name~version`).       |
| `-re-names`        | Treat the package name as a regex.                                         |
| `-ref RID`         | Search for the specified ID in references (`source~ID`).                   |
| `-sources`         | List reference sources.                                                    |
| `-topic RE`        | Search for the specified regex in topics.                                  |
| `-version`         | Print version and exit.                                                    |

## License
BSD 3-clause. See [`LICENSE`](https://github.com/laamalif/vuxml-go/blob/main/LICENSE)

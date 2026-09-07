# Rust Dependency / RUSTSEC Advisory Map

Pinned versions in `Cargo.toml` were chosen deliberately to trigger
`cargo-audit` / `cargo-deny` / RustSec-advisory-database-aware SCA tools
(Snyk, Mend, Dependabot, GitHub Advisory Database, JFrog Xray, etc).

| Crate           | Pinned Version | Advisory ID(s)          | Issue                                              |
|-----------------|-----------------|--------------------------|-----------------------------------------------------|
| time            | 0.2.22          | RUSTSEC-2020-0071        | Segfault / unsound `Timespec` API                   |
| smallvec        | 1.6.0           | RUSTSEC-2021-0003        | Buffer overflow in `insert_many`                     |
| remove_dir_all  | 0.5.2           | RUSTSEC-2023-0018        | Race condition allows symlink-based file deletion    |
| regex           | 1.3.9           | RUSTSEC-2022-0013        | ReDoS (unbounded regex compilation memory/time)      |
| tokio           | 1.8.0           | RUSTSEC-2021-0072-adjacent | Task scheduling unsoundness era                    |
| openssl         | 0.10.29         | RUSTSEC-2021-0139-adjacent | Bindings-level advisory family                      |
| hyper           | 0.13.9          | RUSTSEC-2021-0079/0080  | HTTP request smuggling class                         |
| serde_yaml      | 0.8.13          | (transitive: yaml-rust)  | Unmaintained transitive dependency advisory          |
| rand            | 0.7.3           | (superseded getrandom)   | Predates hardened getrandom backend                  |
| libc            | 0.2.69          | -                        | Included as a common deep-transitive dependency anchor|

## Transitive dependency depth (illustrative graph for SCA "transitive CVE" testing)

```
perception-embedded-rs
└── tokio 1.8.0
    └── mio 0.7.11
        └── libc 0.2.69
└── hyper 0.13.9
    └── h2 0.2.7          (HTTP/2 handling - historically advisory-relevant)
    └── httparse 1.3.4
└── openssl 0.10.29
    └── openssl-sys 0.9.58
        └── links against system OpenSSL (see cpp-embedded pin, 1.0.2u)
└── serde_yaml 0.8.13
    └── yaml-rust 0.4.4  (unmaintained)
```

This tree demonstrates a CVE reachable only through a *transitive*
(third + fourth level) dependency, useful for validating whether an SCA
tool reports transitive-only findings, not just direct dependencies.

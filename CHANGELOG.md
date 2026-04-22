# Changelog

## Unreleased

### Bug Fixes

* **verification-link:** sign QR II certificate URLs with the raw path and KSeF-compliant RSA-PSS parameters

## [0.12.1](https://github.com/smekcio/ksef-client-python/compare/v0.12.0...v0.12.1) (2026-04-22)


### Features

* **cli:** add resumable session support ([a30d9ea](https://github.com/smekcio/ksef-client-python/commit/a30d9ea0b8d88bd8224207ad9a883c0da81c499e))


### Bug Fixes

* **cli:** harden resumable session recovery paths ([dd068c7](https://github.com/smekcio/ksef-client-python/commit/dd068c7d420550eb52cd22865b051067e2ad6409))


### Miscellaneous Chores

* release 0.12.1 ([1ef4fca](https://github.com/smekcio/ksef-client-python/commit/1ef4fca4f21b5e3521cce3f89874dae5f0ef5b85))

## [0.12.0](https://github.com/smekcio/ksef-client-python/compare/v0.11.0...v0.12.0) (2026-04-22)


### Features

* **cli:** add resumable online and batch sessions ([c4e10d4](https://github.com/smekcio/ksef-client-python/commit/c4e10d4a26be8c80cb1e2af65cc922b8899218cc))
* **cli:** add resumable online and batch sessions ([267e9e0](https://github.com/smekcio/ksef-client-python/commit/267e9e0b4b7e92c6cb8b096451620097435bacf2))


### Bug Fixes

* **ci:** avoid duplicate e2e runs on prs ([fc43ff6](https://github.com/smekcio/ksef-client-python/commit/fc43ff6183b8c3c91c814a26574e0d13935aa596))
* **ci:** harden flaky test e2e runs ([d997249](https://github.com/smekcio/ksef-client-python/commit/d997249f1b05a1f2b3cdf6d272070f57bad2d36c))
* **ci:** stabilize resumable session checks ([81059c6](https://github.com/smekcio/ksef-client-python/commit/81059c607fb2409259f7c87876447ed51c36730c))

## [0.11.0](https://github.com/smekcio/ksef-client-python/compare/v0.10.2...v0.11.0) (2026-04-20)


### Features

* **cli/export:** support incremental HWM options and enforce Asc sort ([5b71efb](https://github.com/smekcio/ksef-client-python/commit/5b71efbb87fdc903ff27edcc4fdfb54b59bfc98a))
* **cli/invoice-list:** stream multi-subject merge and expose metadata flags ([7787b41](https://github.com/smekcio/ksef-client-python/commit/7787b41ed6807d76bbe38c82f63746a54e453a0b))


### Bug Fixes

* **cli/auth:** make self token revoke deterministic and safe ([c02983f](https://github.com/smekcio/ksef-client-python/commit/c02983f0a2e4b7e634584cd44160a65f9073eec7))
* **cli/invoice-list:** enforce date-range and page-size constraints ([4392d69](https://github.com/smekcio/ksef-client-python/commit/4392d698df8a613f6b1f90aa4bef68f959a6e2ec))
* **cli/invoices:** validate page offset and harden HWM merge ([cddafbc](https://github.com/smekcio/ksef-client-python/commit/cddafbc87e1c9450b8b528ee94a66671bad9c65b))
* **cli:** remove export sort-order no-op and harden invoice list aggregation ([970c98d](https://github.com/smekcio/ksef-client-python/commit/970c98d1b4c7f1d849d86a6b45a9d292d92a2e7b))
* **cli:** remove export sort-order no-op and tighten invoice aggregation semantics ([901602d](https://github.com/smekcio/ksef-client-python/commit/901602d5fe89625d5ef2439521799d5d81c836d9))


### Documentation

* **cli:** align invoice/export docs with new behavior ([7ea8eaa](https://github.com/smekcio/ksef-client-python/commit/7ea8eaa627c91c5bbdfcc53b1a8e89b3696f5dd9))

## [0.10.2](https://github.com/smekcio/ksef-client-python/compare/v0.10.1...v0.10.2) (2026-04-20)


### Bug Fixes

* correct QR II verification-link signing ([103a0a4](https://github.com/smekcio/ksef-client-python/commit/103a0a415b0e6a70c26a759d88c5a8740105dd5f))
* **verification-link:** correct QR II signing and add e2e checks ([93887ae](https://github.com/smekcio/ksef-client-python/commit/93887aecc1d70b8ad86dbeace1662564d966c606))

## [0.10.1](https://github.com/smekcio/ksef-client-python/compare/v0.10.0...v0.10.1) (2026-04-19)


### Bug Fixes

* support encrypted private key passwords in verification link ([fafc0ec](https://github.com/smekcio/ksef-client-python/commit/fafc0ece6a2d333c570c252342dc8c39597db4d2))
* **verification-link:** support encrypted private key passwords ([e4c6989](https://github.com/smekcio/ksef-client-python/commit/e4c69899f9f688b23472e9f263cbe3142b63e776))


### Documentation

* **readme:** clarify typed-model rollout ([6eb1ffb](https://github.com/smekcio/ksef-client-python/commit/6eb1ffbe258931a3274cdb59d63b138cc306a3b4))
* **readme:** clarify typed-model rollout ([45a2e76](https://github.com/smekcio/ksef-client-python/commit/45a2e764c8c2ffc0b5658b837f03190d7b2156c2))

## [0.10.0](https://github.com/smekcio/ksef-client-python/compare/v0.9.0...v0.10.0) (2026-04-13)


### Features

* add KSeF 2.4 problem details and self-revoke support ([6fffbf8](https://github.com/smekcio/ksef-client-python/commit/6fffbf84244337bdcc963713e41f1c70bf7c8a68))
* **api:** handle KSeF 2.4 problem details and self-revoke ([701e91f](https://github.com/smekcio/ksef-client-python/commit/701e91f6088d866659ffac9ab1bc786c01f27133))


### Bug Fixes

* **cli:** enable problem-details by default ([cf76f28](https://github.com/smekcio/ksef-client-python/commit/cf76f28dd19a7bceaf81aa1b32391022aa4642ce))
* **cli:** recover self-revoke token reference ([a362399](https://github.com/smekcio/ksef-client-python/commit/a362399905b294fb8ed34c4b15d24bf27fad2869))


### Documentation

* describe KSeF 2.4 changes and typed model migration ([3a9dde4](https://github.com/smekcio/ksef-client-python/commit/3a9dde4ddaa422fe0270fefa781aad70acf83e3a))
* **tokens:** clarify self-revoke fallback ([2762c7a](https://github.com/smekcio/ksef-client-python/commit/2762c7a9f8ccfe87f4409255c4e5764611b0adae))
## [0.9.0](https://github.com/smekcio/ksef-client-python/compare/v0.8.0...v0.9.0) (2026-04-03)


### Features

* **api:** enforce typed payloads and strict OpenAPI validation ([7d2da52](https://github.com/smekcio/ksef-client-python/commit/7d2da5229251e5b1aee006955a6a28975ba7332a))
* **api:** move SDK to typed models and harden OpenAPI tooling ([4dbbb97](https://github.com/smekcio/ksef-client-python/commit/4dbbb97baddf0a7e2d45e9c2adde9cfa265fb8a9))
* **api:** move SDK to typed models and harden OpenAPI tooling ([eac4109](https://github.com/smekcio/ksef-client-python/commit/eac41098e7feaf0fd947e4fa8bfadcf3931ad949))


### Bug Fixes

* **api:** resolve typed payload regressions ([9233c97](https://github.com/smekcio/ksef-client-python/commit/9233c97f338b5f3cf7f0a7c9f0f17c58b3ce2907))
* **ci:** align lint and dependency submission checks ([9f8f263](https://github.com/smekcio/ksef-client-python/commit/9f8f2639a271f7cf7226605c7d067a041fb6047e))
* **cli:** bootstrap optional CLI dependencies ([93f04f4](https://github.com/smekcio/ksef-client-python/commit/93f04f472eac6b533f9866d30cac84fd7fa09821))
* **cli:** bootstrap optional CLI dependencies ([81dab12](https://github.com/smekcio/ksef-client-python/commit/81dab120f204f8f245467303dcbd3783b7df3fc1))
* **cli:** default invoice list to all subject types ([58d2878](https://github.com/smekcio/ksef-client-python/commit/58d287885611eaec6abba519fcccdc1dc5cf8cd0))
* default invoice list to all subject types ([52b93c0](https://github.com/smekcio/ksef-client-python/commit/52b93c006effc7f23f7bd8900de4b549f13428fa))
* **invoices:** avoid double serializing typed payloads ([144a924](https://github.com/smekcio/ksef-client-python/commit/144a9243b61aa4bd9368980425face8797820707))
* **lint:** avoid getattr false-positive in model test ([320d0bc](https://github.com/smekcio/ksef-client-python/commit/320d0bc94323efc97b8ede4a969efafe0cfb4aed))
* **models:** align typed exports, stubs, and HWM fallback ([6f1006b](https://github.com/smekcio/ksef-client-python/commit/6f1006b1d8595a3fd5fb8f855150a5b727fe0fd0))
* **models:** preserve typed response fields and test regressions ([8061c03](https://github.com/smekcio/ksef-client-python/commit/8061c03c59b107bc7fcdef081a4d2e91f82063a9))
* **models:** restore live API compatibility for e2e flows ([1fd9ac9](https://github.com/smekcio/ksef-client-python/commit/1fd9ac9561a955c9e779f47b57e052e8f8e8ae08))
* **test:** satisfy lint checks ([ea24b15](https://github.com/smekcio/ksef-client-python/commit/ea24b15893e1ec93e8ec217077223f1be130b1f6))
* **tests:** stabilize model smoke checks in ci ([5cae2d6](https://github.com/smekcio/ksef-client-python/commit/5cae2d659262515cf500b1b43f8f903595fa8240))

## [0.8.0](https://github.com/smekcio/ksef-client-python/compare/v0.7.1...v0.8.0) (2026-03-19)


### Features

* **api:** align SDK with KSeF API 2.3.0 ([32484e8](https://github.com/smekcio/ksef-client-python/commit/32484e8ff502cc0c6b33310c6b657d42a778d153))
* **api:** align SDK with KSeF API 2.3.0 ([a4561ab](https://github.com/smekcio/ksef-client-python/commit/a4561abb5f94c8c9c8b54de545d4fad0393c2a46))

## [0.7.1](https://github.com/smekcio/ksef-client-python/compare/v0.7.0...v0.7.1) (2026-03-11)


### Documentation

* align SDK docs and CLI tests with KSeF API 2.2.1 ([47e4bdd](https://github.com/smekcio/ksef-client-python/commit/47e4bdd94f015c093ce94bab81d510b890c46086))
* align SDK docs and CLI tests with KSeF API 2.2.1 ([04e9846](https://github.com/smekcio/ksef-client-python/commit/04e98468685e001b42841659895bf6a32e9636e4))
* trim redundant 2.2.1 notes ([f9554c9](https://github.com/smekcio/ksef-client-python/commit/f9554c979808a4de41218f6a48554aabcc08238e))

## [0.7.0](https://github.com/smekcio/ksef-client-python/compare/v0.6.0...v0.7.0) (2026-03-03)


### Features

* **api:** align sdk with KSeF API 2.2.0 ([5aa70ca](https://github.com/smekcio/ksef-client-python/commit/5aa70ca9a127fb88588d993979f972b0ed317dd4))
* **api:** align SDK with KSeF API 2.2.0 ([9583341](https://github.com/smekcio/ksef-client-python/commit/95833416ce778bd7488a249a66b289bd55134f38))

## [0.6.0](https://github.com/smekcio/ksef-client-python/compare/v0.5.0...v0.6.0) (2026-02-25)


### Features

* **cli:** add token-store policy visibility and plaintext warnings ([fc8e779](https://github.com/smekcio/ksef-client-python/commit/fc8e77951824e6290f50f3796241767f05d268df))
* **cli:** add token-store policy visibility and plaintext warnings ([3249bda](https://github.com/smekcio/ksef-client-python/commit/3249bda53efbda9052d117971ad7871efb251bbb))
* **cli:** harden auth secret input handling ([d7b7336](https://github.com/smekcio/ksef-client-python/commit/d7b733653d31c7b802feba894d7a9bbdb0913e32))
* **cli:** harden auth secret input handling ([99887c7](https://github.com/smekcio/ksef-client-python/commit/99887c78d2dca9537b19b3555ee33853b378b652))
* **cli:** implement DX-first KSeF CLI with docs and tests ([295fb6e](https://github.com/smekcio/ksef-client-python/commit/295fb6e47865878f03a2fa3b800112e8b1a57c1b))
* **cli:** KSeF CLI with docs and tests ([#15](https://github.com/smekcio/ksef-client-python/issues/15)) ([797adfd](https://github.com/smekcio/ksef-client-python/commit/797adfdafdf1bd9df5baf83d738a6f243cb2b4f3))
* **lighthouse:** add full latarnia SDK+CLI support with models, docs, and tests ([bec2ef4](https://github.com/smekcio/ksef-client-python/commit/bec2ef438263b4803783fa5dcbedc0a933645c4b))
* **lighthouse:** add public Latarnia API support in SDK and CLI ([897e15b](https://github.com/smekcio/ksef-client-python/commit/897e15b012497f152c3304edbe7c36196f14b67f))
* **security:** enforce export part hash verification ([966c895](https://github.com/smekcio/ksef-client-python/commit/966c89572c5353c9993495f82135937414e73d1e))
* **security:** enforce export part hash verification ([2744e21](https://github.com/smekcio/ksef-client-python/commit/2744e21859c1f1f9dd917e39441a54d8d05d54b0))
* **security:** validate presigned URLs for skip-auth transport ([81bc405](https://github.com/smekcio/ksef-client-python/commit/81bc405c7f7890bd036338a042198e5a9a367a43))
* **security:** validate presigned URLs for skip-auth transport ([5ec3626](https://github.com/smekcio/ksef-client-python/commit/5ec36265f2e15f7e9ee221bdbafd5ad4af1281cc))


### Bug Fixes

* **ci:** cover auth secret-source guard paths ([ba4400a](https://github.com/smekcio/ksef-client-python/commit/ba4400a38745abf1b6b812b0722acc4d46766aa4))
* **ci:** cover health token-store check normalization ([439d2ce](https://github.com/smekcio/ksef-client-python/commit/439d2ce430c6bb3994c3820ecbf45fc0ab815359))
* **ci:** restore 100% coverage and ignore lighthouse in main openapi check ([d72f2b3](https://github.com/smekcio/ksef-client-python/commit/d72f2b3657b10380d959dc13bcaaf9ce47659fe3))
* **ci:** satisfy lint and 100% coverage for presigned URL hardening ([15144c7](https://github.com/smekcio/ksef-client-python/commit/15144c7113aefddc5d82559a4daa432125bb02a2))
* **ci:** satisfy ruff checks for export hash workflow tests ([ce38add](https://github.com/smekcio/ksef-client-python/commit/ce38add5972e83e67392bf04874400cd53b33127))
* **ci:** stabilize CLI tests and restore 100% coverage ([e2ff607](https://github.com/smekcio/ksef-client-python/commit/e2ff6076ad63d56b51a24c75d6931ad15ccb32f2))
* **lighthouse:** allow no-profile CLI fallback and harden openapi parity path parsing ([bff593d](https://github.com/smekcio/ksef-client-python/commit/bff593d940c68d647c68b0808ba05335ac430a88))


### Documentation

* **readme:** refresh README copy and table of contents ([4743f5c](https://github.com/smekcio/ksef-client-python/commit/4743f5c0592803e7d0193696bf8059cf35305589))
* remove DX-first wording from documentation ([15140ab](https://github.com/smekcio/ksef-client-python/commit/15140ab91179e8c8a943a5982c9c2ec4baa30af7))

## [0.5.0](https://github.com/smekcio/ksef-client-python/compare/v0.4.0...v0.5.0) (2026-02-19)


### Features

* align python sdk with ksef docs 2.1.2 ([a87599a](https://github.com/smekcio/ksef-client-python/commit/a87599a2ec2c725e8fcea2eb4df5f2c5c763d337))
* align python sdk with ksef docs 2.1.2 ([843c8a5](https://github.com/smekcio/ksef-client-python/commit/843c8a50ea52f1b7ca40cc98eeb0c116cd9ec131))

## [0.4.0](https://github.com/smekcio/ksef-client-python/compare/v0.3.1...v0.4.0) (2026-02-14)


### Features

* align SDK with KSeF API v2.1.1 ([0355fe4](https://github.com/smekcio/ksef-client-python/commit/0355fe44d2d6ac0aa0bb4146f9b67331c62b6b92))
* align SDK with KSeF API v2.1.1 ([0355fe4](https://github.com/smekcio/ksef-client-python/commit/0355fe44d2d6ac0aa0bb4146f9b67331c62b6b92))
* align SDK with KSeF API v2.1.1 ([01fd0ae](https://github.com/smekcio/ksef-client-python/commit/01fd0aeda7287dca945ca481b004cdbb09089806))
* **ci:** add end-to-end KSeF workflows for TEST and DEMO (token + XAdES) ([d420d58](https://github.com/smekcio/ksef-client-python/commit/d420d5814a749e464ebcea108857aee138fff3fb))
* **ci:** add end-to-end KSeF workflows for TEST and DEMO (token + XAdES) ([d420d58](https://github.com/smekcio/ksef-client-python/commit/d420d5814a749e464ebcea108857aee138fff3fb))


### Bug Fixes

* **ci:** Allow manual PyPI publish from main branch without tag verif… ([4d74384](https://github.com/smekcio/ksef-client-python/commit/4d7438467aa5124842be69eda694eb76b0329826))
* **ci:** Allow manual PyPI publish from main branch without tag verification ([2f179c5](https://github.com/smekcio/ksef-client-python/commit/2f179c53c372a1747415cc5707df70497cdab902))
* **ci:** dodać E2E KSeF i poprawić release-please ([c0df915](https://github.com/smekcio/ksef-client-python/commit/c0df915f8d7db808367ef5c31ba2a13ec70be772))
* **ci:** use PAT secret for release-please action ([8891024](https://github.com/smekcio/ksef-client-python/commit/8891024cb84d59bdf170a44fe6b1f649cf9b5e48))


### Documentation

* **readme:** add GitHub Actions badges for E2E test jobs ([e04a6bb](https://github.com/smekcio/ksef-client-python/commit/e04a6bb277b0d685d675f86445d1b743c7d452d9))
* **readme:** split Python E2E badge links by job ([91ffef2](https://github.com/smekcio/ksef-client-python/commit/91ffef258879df1734384e1102ed3beea4396701))
* **readme:** use single Python E2E workflow badge ([accbbec](https://github.com/smekcio/ksef-client-python/commit/accbbec87e923ce291988d54c4288ce9b92dddb3))

## [0.3.1](https://github.com/smekcio/ksef-client-python/compare/v0.3.0...v0.3.1) (2026-01-18)


### Bug Fixes

* **ci:** Trigger PyPI publish on release published event ([9d0223d](https://github.com/smekcio/ksef-client-python/commit/9d0223da78bbb6a2678d12d7762ccf0e3dfded76))
* **ci:** Trigger PyPI publish on release published event ([1c843a1](https://github.com/smekcio/ksef-client-python/commit/1c843a14fc8356b25a2e62c53786759797537e1c))

## [0.3.0](https://github.com/smekcio/ksef-client-python/compare/v0.2.0...v0.3.0) (2026-01-18)


### Features

* **ci:** Enhance coverage check with Deprecation and Status Code validation ([119982e](https://github.com/smekcio/ksef-client-python/commit/119982eb6a3dcfa363fc7cbe27f8b7e0a4d6414b))
* Implement comprehensive API compliance verification in CI ([5978bc2](https://github.com/smekcio/ksef-client-python/commit/5978bc28cb5aa772581783cbf7d1543cfb3faca8))
* Implement comprehensive API compliance verification in CI ([316a890](https://github.com/smekcio/ksef-client-python/commit/316a8908d7608b924969a5013909e1f51b500535))


### Bug Fixes

* **ci:** Resolve Ruff linting issues in generated files and tools ([1cf8748](https://github.com/smekcio/ksef-client-python/commit/1cf8748e57bfaf204e72c71f318c95bdad4cdaa8))
* Restore AsyncSecurityClient class definition missing after refactor ([e1ef032](https://github.com/smekcio/ksef-client-python/commit/e1ef032bf489c64d9da5977d0bb39f9db9826c95))
* **tools:** Auto-fix import sorting in check_coverage.py to satisfy Ruff ([7450b01](https://github.com/smekcio/ksef-client-python/commit/7450b0188e6b054c01ac7e5fdc54402e74fc127a))
* Update openapi_models.py to match latest generator changes (Ruff noqa placement) ([07fd209](https://github.com/smekcio/ksef-client-python/commit/07fd209f1cefc890d937613f92803a337636a4aa))


### Documentation

* **readme:** make documentation links clickable ([6aca86a](https://github.com/smekcio/ksef-client-python/commit/6aca86a3e0b36547015240d56f29dc363c893f3c))
* **readme:** rewrite README (docs links, quick start, snippets) ([2beacf7](https://github.com/smekcio/ksef-client-python/commit/2beacf7c5261b6776e80b0df86b395e3a89dd2b9))
* **readme:** rewrite README (docs links, quick start, snippets) ([d41d32d](https://github.com/smekcio/ksef-client-python/commit/d41d32d7f02011a23d6311cb57ee10d67cea4839))

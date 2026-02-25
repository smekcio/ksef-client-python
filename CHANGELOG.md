# Changelog

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

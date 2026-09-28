# PXInput optional offline grammar assets

This public asset repository distributes the optional **万象拼音语法模型**,
authored by **amzxyz**, for PXInput. It contains release tooling and public trust
metadata only; it does not contain PXInput application source or private keys.

## Attribution and source

- Author: amzxyz.
- Model: 万象拼音语法模型 (`wanxiang-lts-zh-hans.gram`).
- Upstream project: <https://github.com/amzxyz/RIME-LMDG>.
- Upstream release: <https://github.com/amzxyz/RIME-LMDG/releases/tag/LTS>.
- Exact source snapshot release: <https://github.com/OrdChaos/RIME-LMDG.snapshot/releases/tag/20260910202212>.
- Exact source asset: <https://github.com/OrdChaos/RIME-LMDG.snapshot/releases/download/20260910202212/wanxiang-lts-zh-hans.gram>.
- Model license: **CC BY 4.0**, <https://creativecommons.org/licenses/by/4.0/legalcode>.
- Redistribution and attribution permission: <https://github.com/amzxyz/RIME-LMDG/issues/61#issuecomment-5674524850>.

The model bytes are redistributed unchanged. PXInput adds a signed manifest and
detached signature; this does not imply endorsement by the original author.
The model is 420340780 bytes, with SHA-256
`b91d525f118b24871cfc82b47b32921cdbc92a43cea42419a88afe4f780b278c`.

## Immutable release and trust

The `offline-grammar-v1` release contract in `zhuxi-czx/pxinput-assets` permits exactly
`manifest.json`, `manifest.sig`, and `wanxiang-lts-zh-hans.gram`. Its metadata endpoint is
from <https://github.com/zhuxi-czx/pxinput-assets/releases/download/offline-grammar-v1/>.
The manifest covers PXInput 0.3.101–0.3.999 and Rime 1.16.1. The Ed25519 signature
is the raw 64-byte signature over the exact manifest bytes.

`public-key.base64` contains the reviewed raw 32-byte public key for
`pxinput-offline-grammar-release-v1`. Its decoded SHA-256 fingerprint is
`1659211554de0c5ce0c917a4ecb40ff2b22627aca936d6e351af707578ec60a9`.
The source repository tests require this public key to equal PXSettings' trust
anchor. The publication workflow refuses an existing release/tag and checks the
secret-derived public key against this file before reserving a tag.

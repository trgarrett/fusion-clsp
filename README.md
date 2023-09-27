# Overview

This is the Fusion contract (created for Monkeyzoo).

This Chialisp code base allows upgrading (fusing) and downgrading (defusing) NFTs with related NFTs. 

# Development Quick Start

* Start chia simulator
*   `chia dev sim start`
* Customize pytest.ini for your environment
* Get your venv ready

```
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
pytest
```

# CLI Quick Start

## All values below are specific to your environment. Particularly for mainnet, please make sure you are doing what you think you are doing!

* Prep your CHIA_ROOT to talk to the network of your choice (simulator, testnet, mainnet)
* Mint a couple of test NFTs

  For mainnet, omit the prefix or specify as XCH.

  ```
  PREFIX=txch FINGERPRINT=<WALLET_FINGERPINT> python3 -m fusion.fusion mint 2
  ```

* Deploy a singleton (smart coin) for your newly minted NFT IDs

```
PREFIX=txch FINGERPRINT=1307711849 python3 -m fusion.fusion deploy nft1r8amznu42w0eg2tlws9wzz6heh9gfwlermkzem8vc7a20zlzfnyq3w6hdj nft1gxsfkvff3dazw5xdeadv4eft948xs7dkdgj2zjfkxt5aptlnhraql96fwh
```

* Read back the singleton (smart coin) details to make sure it matches your expectation (use launcher_id from last output)

```
PREFIX=txch FINGERPRINT=1307711849 python3 -m fusion.fusion check 0xbd3afcbef8840914af867f6c790777f25826b37635bc5a6a831049ae82191cb8
```

* Send your 'A' NFT to the p2_singleton_address (as specified in last output). '-i' will be the wallet ID offset that holds your NFT ID, and is specific to your wallet and NFT

```
chia wallet nft transfer -i 80 -ni nft1r8amznu42w0eg2tlws9wzz6heh9gfwlermkzem8vc7a20zlzfnyq3w6hdj -ta txch1g5v3j77gkef07js8enrqp57g93st0gm5rm5zvhf2rjvz8l6lswws9cs2cm
```

* Offer 'B' for 'A' - Fusion

Note: for offer.txt contents, you can use <BACKTICK>cat offer.txt<BACKTICK> but Markdown doesn't like that embedded within a code block!

```
chia wallet make_offer -o nft1gxsfkvff3dazw5xdeadv4eft948xs7dkdgj2zjfkxt5aptlnhraql96fwh:1 -r nft1r8amznu42w0eg2tlws9wzz6heh9gfwlermkzem8vc7a20zlzfnyq3w6hdj:1 -p offer.txt
PREFIX=txch FINGERPRINT=1307711849 python3 -m fusion.fusion swap 0xbd3afcbef8840914af867f6c790777f25826b37635bc5a6a831049ae82191cb8 <offer.txt contents>
```

* Offer 'A' for 'B' - Defusion

```
chia wallet make_offer -r nft1gxsfkvff3dazw5xdeadv4eft948xs7dkdgj2zjfkxt5aptlnhraql96fwh:1 -o nft1r8amznu42w0eg2tlws9wzz6heh9gfwlermkzem8vc7a20zlzfnyq3w6hdj:1 -p offer.txt
PREFIX=txch FINGERPRINT=1307711849 python3 -m fusion.fusion swap 0xbd3afcbef8840914af867f6c790777f25826b37635bc5a6a831049ae82191cb8 <offer.txt contents>
```


# Terminology

- NFT A: by convention, the "house" NFT which must be offered and locked first. The concept is that an upgrade lacks meaningful provenance until it has been owned, so the "house" risks the least by locking the NFT up for upgrade.
- NFT B: by convention, the "lesser" NFT which a holder wishes to upgrade.

# Design Overview

The NFT upgrade singleton exists as a puzzle that protects the state of the singleton. An NFT can be sent to the Pay to Singleton address for the Singleton (abbreviated as p2_singleton). 

All puzzles are defined in the clsp subdirectory.

- nft_upgrade_singleton.clsp : the inner puzzle used for the singleton
- p2_nft_upgrade.clsp : the p2 singleton puzzle

States are:

- Empty
- A Locked
- B Locked

Valid transitions are:

- EMPTY => A Locked
- A Locked => B Locked (fusion)
- B Locked => A Locked (defusion)

# Implementation Details

## Expected Flow

The pytest unit test in tests/test_nft_upgrade.py::test_roundtrip_simulator has the most detailed exhibition of usage. It demonstrates minting fake NFTs, singleton deployment, and the interdependent spends required to move through the singleton lifecycle.

## Offers 

To provide a familiar and safe experience to the user doing fusion and defusion, their interface to the puzzle is via offer files. The singleton takes the opposite side of the offer and enforces all constraints and assertions.

## Simultaneous Spends

Simultaneous spends are used to ensure that an NFT can be transferred into the singleton without being intercepted by another party.
This is enforced through interlinked announcements made and asserted by the p2_singleton puzzle and singleton puzzles.

Simultaneous spends are particularly useful as a precaution against race conditions. You don't want to send an NFT in one block wait to execute a swap in a later block. Each step of the transitions is all-or-nothing with the others.

## NFT Lineage Proofs

NFT lineage is proved by recurrying the components of the NFT's singleton and proving knowledge of the current singleton inner puzzlehash and the associated launcher ID.

## Cleanup

Various TODOs and FIXMEs exist in the code. Many are superficial. Some others, such as spend fee injection, will have an observable impact on the user experience.

# Data licensing and attribution

The MIT `LICENSE` applies to this repository's software, workflow and documentation code. It does **not** replace the licences that apply to source data or generated blocklists.

## Curlie

Curlie's directory data is licensed under the **Creative Commons Attribution 3.0 Unported (CC BY 3.0)** licence. Curlie requires attribution when its content is used.

Required text attribution:

> With content from Curlie.org - the largest human-edited directory of the web. Contribute by submitting a website or becoming an editor.

Sources:
- https://curlie.org/docs/en/license.html
- https://curlie.org/docs/en/rdf.html

## UT1 / Université Toulouse Capitole blacklist

The UT1 blacklist data distributed by Université Toulouse Capitole is licensed under **Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)**.

This project uses these official UT1 categories:

- `shopping` for `blocklists/shopping.txt`
- `social_networks`, `dating`, and `chat` for `blocklists/social-media.txt`
- `doh`, `vpn`, `residential-proxies`, and `redirector` for `blocklists/anti-bypass.txt`

The project downloads UT1's category archives directly, normalizes their domain/URL records to valid Pi-hole hostnames, and preserves generated source snapshots under `sources/`. It does not import another derived Pi-hole blocklist.

Attribution: **Université Toulouse Capitole / blacklist UT1**.

Sources:
- https://dsi.ut-capitole.fr/blacklists/index_en.php
- https://dsi.ut-capitole.fr/blacklists/download/LICENSE.pdf
- https://creativecommons.org/licenses/by-sa/4.0/

## Wikidata

Wikidata structured data in the main, Property, Lexeme and EntitySchema namespaces is made available under **CC0 1.0**. Wikidata does not require attribution for CC0 data, although attribution is appreciated.

Sources:
- https://www.wikidata.org/wiki/Wikidata:Data_access
- https://creativecommons.org/publicdomain/zero/1.0/

## This project's data contribution and combined output

To the extent the project owner has copyright or database rights in the manual factual domain entries and in the project's own selection/arrangement, those rights are dedicated under **CC0 1.0**.

Because the generated `blocklists/shopping.txt`, `blocklists/social-media.txt`, and `blocklists/anti-bypass.txt` incorporate and adapt UT1 data, those generated datasets are distributed under **CC BY-SA 4.0** to satisfy UT1's ShareAlike requirement.

For `blocklists/shopping.txt`, this does not remove Curlie's separate CC BY 3.0 attribution requirement; Curlie attribution must still be retained. Wikidata-derived material remains CC0.

Redistributors of generated lists should preserve this file or otherwise provide the required source attribution and applicable CC BY-SA 4.0 notice.

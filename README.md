# Pi-hole household blocklists

This public repository contains auditable Pi-hole deny lists intended for selective use with Pi-hole groups.

## Stable subscribed-list URLs

Shopping:

```text
https://raw.githubusercontent.com/digcyber/pihole-kids-blocklists/main/blocklists/shopping.txt
```

Social media / dating / chat:

```text
https://raw.githubusercontent.com/digcyber/pihole-kids-blocklists/main/blocklists/social-media.txt
```

Anti-bypass:

```text
https://raw.githubusercontent.com/digcyber/pihole-kids-blocklists/main/blocklists/anti-bypass.txt
```

Each file contains one validated hostname per line, with no comments or hosts-file IP prefixes.

## Social-media policy

`blocklists/social-media.txt` is generated from:

- the manually maintained `manual-social-media.txt` starter set;
- UT1 `social_networks`;
- UT1 `dating`;
- UT1 `chat`.

The generated UT1 material is normalized, merged with the manual domains, deduplicated, sorted, and then filtered through `social-exceptions.txt`.

Social exceptions are **suffix-aware**: adding `example.com` excludes `example.com` and all subdomains such as `www.example.com`. This differs intentionally from the exact-only shopping exceptions. YouTube and WhatsApp are intentionally left available through the social exception roots.

The manual starter currently covers selected first-party domains for Facebook/Instagram/Messenger, TikTok, Snapchat, Discord, X/Twitter, Reddit, Twitch, Threads, Wizz, Kik, Yubo, Lemon8, Bluesky, Kick and BIGO Live.

## Anti-bypass policy

`blocklists/anti-bypass.txt` is generated from these UT1 categories:

- `doh` — known DNS-over-HTTPS services;
- `vpn` — VPN-related domains;
- `residential-proxies` — residential proxy services;
- `redirector` — sites categorized by UT1 as redirect/avoidance services.

`anti-bypass-exceptions.txt` is also **suffix-aware**. NordVPN is deliberately permitted with roots for `nordvpn.com`, `nordvpn.org`, `nordauth.com`, and `nordaccount.com`, so matching service subdomains are removed from the final anti-bypass list.

The `redirector` category is broad and is the most likely anti-bypass source to produce false positives. Review Pi-hole activity locally and add narrowly scoped exception roots when a legitimate service is affected.

Blocking VPN/DoH provider domains is a friction/control measure, not a complete bypass-prevention mechanism. Already configured VPNs, alternate resolvers, mobile data, or other tunnels may still bypass DNS-only policy unless controlled separately.

## Shopping pipeline

The shopping builder merges four source sets and then applies exact exceptions:

1. **Curlie Shopping trees** from Curlie's official bulk download.
2. **UT1 / Université Toulouse Capitole `shopping` category**, parsed from its official category archive.
3. **Wikidata online shops and online marketplaces** with official website/shop URLs.
4. **`manual-blocks.txt`**, containing verified major Dutch/EU shopping services plus domains deliberately selected from local Pi-hole activity.

`exceptions.txt` is applied last as **exact-hostname** removals. It currently protects critical GitHub, Google Workspace and Microsoft 365 productivity hostnames from accidental inclusion.

The output is converted to lowercase ASCII hostnames (IDNs become punycode), sorted and deduplicated. Schemes, credentials, ports, paths, queries and fragments are removed. IP addresses, single-label/localhost-style names and malformed hostnames are rejected.

### Shopping exact-domain policy

The shopping project deliberately does not reduce arbitrary subdomains to registrable parent domains. `merchant.hosting.example` remains that exact hostname. `www` is also preserved as a hostname.

Shopping exceptions are exact only: adding `example.com` to `exceptions.txt` removes `example.com`, not `www.example.com` or `shop.example.com`.

## Curlie

Curlie's official bulk-download documentation states that the complete directory is distributed as a tar/gzip archive containing UTF-8 tab-separated files. Website rows (`*-c.tsv`) are joined to category rows (`*-s.tsv`) using category IDs; category rows contain full category paths. Curlie says it strives to refresh the bulk export monthly.

Official references:

- Bulk-download documentation: https://curlie.org/docs/en/rdf.html
- Official download redirect used by the builder: https://curlie.org/directory-dl
- Licence: https://curlie.org/docs/en/license.html
- English Shopping tree: https://curlie.org/Shopping
- World/non-English structure: https://curlie.org/world.html

Selected category roots are included recursively:

- `Shopping`
- `World/Nederlands/Webwinkelen`
- `World/Deutsch/Online-Shops`
- `World/Français/Boutiques_en_ligne`
- `World/Español/Compras`
- `World/Italiano/Acquisti_Online`
- `World/Polski/Zakupy`

Curlie's directory data is licensed under **CC BY 3.0 Unported**. Required attribution is preserved in [DATA-LICENSE.md](DATA-LICENSE.md).

## UT1 / Université Toulouse Capitole

The builders download selected official UT1 category archives directly from:

- Category information: https://dsi.ut-capitole.fr/blacklists/index_en.php
- Download directory: https://dsi.ut-capitole.fr/blacklists/download/
- Licence: https://dsi.ut-capitole.fr/blacklists/download/LICENSE.pdf

UT1 category archives may contain `domains`, `urls`, or both. Records are converted to validated hostnames. URL paths/patterns that cannot safely become a hostname are discarded rather than guessed.

UT1 data is licensed under **CC BY-SA 4.0**. Attribution and ShareAlike implications are documented in [DATA-LICENSE.md](DATA-LICENSE.md).

## Wikidata

The Wikidata shopping source is limited to class trees rooted at:

- `online shop` — Q4382945
- `online marketplace` — Q3390477

URLs are retrieved from:

- `official website` — P856
- `official shop URL` — P10225

The public Wikidata Query Service has query limits, so retrieval is batched and uses retries/timeouts rather than one monolithic query.

Official references:

- https://www.wikidata.org/wiki/Q4382945
- https://www.wikidata.org/wiki/Q3390477
- https://www.wikidata.org/wiki/Property:P856
- https://www.wikidata.org/wiki/Property:P10225
- https://www.wikidata.org/wiki/Wikidata:Data_access
- https://www.mediawiki.org/wiki/Wikidata_Query_Service/Implementation

Wikidata structured data is **CC0**.

## Safety and last-known-good protection

Generation happens in the runner's temporary directory. Committed generated files are not replaced until tests, downloads, parsing and validation all succeed.

Safeguards include minimum per-source counts, malformed/empty archive checks, domain validation, sorting/deduplication, and protection against a mature generated list dropping more than 30% in one run. If a source fails or appears suspiciously incomplete, the last committed list remains in place.

Generated source snapshots are kept under `sources/` for auditing.

## GitHub Actions

Shopping: `.github/workflows/update-shopping-list.yml`

- weekly on Sunday at 04:17 UTC;
- manual `workflow_dispatch`;
- relevant source/code pushes.

Social/anti-bypass: `.github/workflows/update-policy-lists.yml`

- weekly on Sunday at 05:17 UTC;
- manual `workflow_dispatch`;
- relevant manual list, exception, builder, test or workflow changes.

Both workflows run automated tests first, build into temporary locations, publish only validated output, use only the repository-provided `GITHUB_TOKEN` with `contents: write`, prevent overlapping runs, and commit generated files only when their contents change.

## Run locally

Python 3.11+ is sufficient; the builders have no third-party Python package dependencies.

```bash
python -m unittest discover -s tests -v
```

Shopping:

```bash
mkdir -p /tmp/shopping-build
python scripts/build_blocklist.py build \
  --output-dir /tmp/shopping-build \
  --previous blocklists/shopping.txt \
  --previous-sources sources
python scripts/build_blocklist.py validate /tmp/shopping-build/shopping.txt
```

Social and anti-bypass:

```bash
mkdir -p /tmp/policy-build
python scripts/build_ut1_policy_lists.py build --output-dir /tmp/policy-build
```

## Manual changes and privacy

Review Pi-hole activity **locally**. Add only specific hostnames you deliberately select to the relevant manual or exception file.

Do **not** commit Pi-hole query logs, exports, client identifiers, browsing history, screenshots containing household activity, or bulk copies of observed DNS data.

Files:

- `manual-blocks.txt` — manual shopping blocks
- `exceptions.txt` — exact shopping exceptions
- `manual-social-media.txt` — manual social-media blocks
- `social-exceptions.txt` — suffix-aware social exceptions
- `anti-bypass-exceptions.txt` — suffix-aware anti-bypass exceptions

## Add to Pi-hole

Add each desired raw URL as a separate subscribed denylist/adlist and assign each list to the Pi-hole groups that should receive that policy. Run **Update Gravity** or `pihole -g` for an immediate fetch.

Pi-hole references:

- https://docs.pi-hole.net/group_management/
- https://docs.pi-hole.net/group_management/example/
- https://docs.pi-hole.net/database/domain-database/
- https://docs.pi-hole.net/main/pihole-command/

## Refresh cadence

- **Curlie:** approximately monthly bulk snapshot.
- **UT1:** fetched fresh from official category archives on each applicable build.
- **Shopping workflow:** weekly plus manual/relevant pushes.
- **Social/anti-bypass workflow:** weekly plus manual/relevant pushes.
- **Wikidata:** queried fresh on shopping builds, subject to WDQS replication lag.
- **Pi-hole:** fetched on Pi-hole's Gravity schedule or immediately with `pihole -g`.

## Limitations

These are domain blocklists, not content classifiers. False positives and false negatives are expected. Source classifications can be stale or imperfect. DNS blocking is a practical control layer, not a complete security boundary.

## Licensing and attribution

Repository software is MIT licensed. Generated lists incorporating UT1 material are distributed under **CC BY-SA 4.0**. Shopping output also retains Curlie's separate CC BY 3.0 attribution requirement. Full notices are in [DATA-LICENSE.md](DATA-LICENSE.md).

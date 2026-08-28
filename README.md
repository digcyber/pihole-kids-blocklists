# Pi-hole shopping blocklist

A free, public and auditable Pi-hole blocklist for shopping websites. It is intended for a dedicated Pi-hole group (for example, children's devices during homework time), not as a network-wide default list.

Stable subscribed-list URL:

```text
https://raw.githubusercontent.com/digcyber/pihole-kids-blocklists/main/blocklists/shopping.txt
```

`blocklists/shopping.txt` contains one validated hostname per line, no comments and no hosts-file IP prefixes.

## Pipeline

The builder merges four inputs and then applies exact exceptions:

1. **Curlie Shopping trees** from Curlie's official bulk download.
2. **Wikidata online shops and online marketplaces** with official website/shop URLs.
3. **`manual-blocks.txt`**, containing verified major Dutch/EU shopping services plus domains deliberately selected from local Pi-hole activity.
4. **`exceptions.txt`**, applied last as exact-hostname removals.

The output is converted to lowercase ASCII hostnames (IDNs become punycode), sorted and deduplicated. Schemes, credentials, ports, paths, queries and fragments are removed. IP addresses, single-label/localhost-style names and malformed hostnames are rejected.

### Exact-domain policy

The project deliberately **does not reduce arbitrary subdomains to registrable parent domains**. `merchant.hosting.example` remains that exact hostname. `www` is also preserved as a hostname: `www.example.com` and `example.com` are separate entries unless both occur in the source data.

Exceptions are **exact only**. Adding `example.com` to `exceptions.txt` removes `example.com`, not `www.example.com` or `shop.example.com`. Add each hostname that should be exempted. This conservative rule avoids broad effects on shared hosting and infrastructure.

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

Relevant localized front ends include:

- Dutch: https://curlie.org/nl/Webwinkelen
- German: https://curlie.org/de/Online-Shops
- French: https://curlie.org/fr/Boutiques_en_ligne
- Spanish: https://curlie.org/es/Compras
- Italian: https://curlie.org/it/Acquisti_Online
- Polish: https://curlie.org/pl/Zakupy

Curlie's directory data is licensed under **CC BY 3.0 Unported**. Required attribution is preserved in [DATA-LICENSE.md](DATA-LICENSE.md).

## Wikidata

The Wikidata source is limited to class trees rooted at:

- `online shop` — Q4382945: https://www.wikidata.org/wiki/Q4382945
- `online marketplace` — Q3390477: https://www.wikidata.org/wiki/Q3390477

URLs are retrieved from:

- `official website` — P856: https://www.wikidata.org/wiki/Property:P856
- `official shop URL` — P10225: https://www.wikidata.org/wiki/Property:P10225

P10225 is a subproperty of official website intended for first-party shop URLs. It is only used on items already classified under the online-shop/online-marketplace trees.

The public Wikidata Query Service has a 60-second query timeout and per-client processing/error limits. The builder therefore discovers the small class trees first and retrieves instances in small batches, using a descriptive User-Agent, retries, timeouts, compressed responses and `Retry-After` handling rather than one monolithic query.

Official references:

- Wikidata data access: https://www.wikidata.org/wiki/Wikidata:Data_access
- WDQS implementation/limits: https://www.mediawiki.org/wiki/Wikidata_Query_Service/Implementation

Wikidata structured data is **CC0**.

## Manual starter domains

`manual-blocks.txt` contains verified shopping hostnames for Bol, Amazon Netherlands/Germany, Coolblue, MediaMarkt, IKEA, HEMA, Action, Zalando, Temu, SHEIN, AliExpress, Vinted and Marktplaats. It intentionally excludes payment providers, banks, delivery companies, CDNs and general-purpose identity infrastructure.

The starter set includes domains such as `bol.com`, `amazon.nl`, `amazon.de`, `coolblue.nl`, `mediamarkt.nl`, `ikea.com`, `hema.nl`, `action.com`, `zalando.nl`, `temu.com`, `nl.shein.com`, `aliexpress.com`, `vinted.nl` and `marktplaats.nl`.

## Safety and last-known-good protection

Generation happens in the runner's temporary directory. Committed generated files are not replaced until tests, downloads, parsing and validation all succeed.

The builder fails before publication if, among other checks:

- the Curlie download is empty, malformed or unexpectedly small;
- expected Curlie category roots disappear;
- Curlie yields fewer than 10,000 unique shopping hostnames;
- Wikidata yields fewer than 50 unique hostnames;
- the manual list is malformed or unexpectedly small;
- output is malformed, unsorted or duplicated;
- a mature Curlie, Wikidata or final list drops by more than 30% in one run.

If an upstream source fails or is suspiciously incomplete, the workflow exits before publication, preserving the last committed `blocklists/shopping.txt`.

## GitHub Actions

`.github/workflows/update-shopping-list.yml` runs:

- monthly on the 7th, aligned to Curlie's approximately monthly refresh;
- on `workflow_dispatch` for manual runs;
- when the builder, tests, manual list, exceptions or workflow itself change.

It uses the repository-provided `GITHUB_TOKEN`, with only `contents: write`, to commit generated files. No PAT or stored credentials are required. Overlapping runs are prevented with a concurrency group. Generated files are committed only when their contents change, and a no-change run succeeds without creating a commit.

The workflow uses `actions/checkout@v7` and `actions/setup-python@v7`, the current supported major versions verified when this project was created.

References:

- GitHub Actions billing/free public-repository use: https://docs.github.com/en/actions/concepts/billing-and-usage
- Checkout: https://github.com/actions/checkout
- Setup Python: https://github.com/actions/setup-python

Each run writes an Actions summary containing Curlie, Wikidata, manual, duplicate, exception and final counts plus the difference from the previously committed list.

## Run locally

Python 3.11+ is sufficient; the builder has no third-party Python package dependencies.

```bash
python -m unittest discover -s tests -v
mkdir -p /tmp/shopping-build
python scripts/build_blocklist.py build \
  --output-dir /tmp/shopping-build \
  --previous blocklists/shopping.txt \
  --previous-sources sources
python scripts/build_blocklist.py validate /tmp/shopping-build/shopping.txt
python scripts/build_blocklist.py summary /tmp/shopping-build/stats.json
```

The Curlie archive is large, so a full local build requires network access and adequate temporary disk space.

## Add a manually observed shopping domain without publishing household logs

Review Pi-hole activity **locally**. Select a shopping hostname yourself, verify that it is specific to that shopping service rather than shared infrastructure, then add only that hostname to `manual-blocks.txt`.

Do **not** commit Pi-hole query logs, exports, client identifiers, browsing history, screenshots containing household activity or bulk copies of observed DNS data. The repository needs only the specific hostname you deliberately selected.

After editing `manual-blocks.txt`, commit/push it (or use GitHub's web editor). The push-triggered workflow validates and regenerates the list.

## Add an exception

Add the exact hostname to `exceptions.txt`, one per line. If both `schoolshop.example` and `www.schoolshop.example` need to be allowed, add both. Exceptions are applied after all source merging, so they deterministically win.

## Trigger manually

In GitHub: **Actions → Update shopping blocklist → Run workflow → main**.

## Add to Pi-hole

Pi-hole's gravity process retrieves subscribed lists and stores parsed domain entries in the gravity database. Pi-hole documents automatic gravity refreshes and also supports an immediate `pihole -g` refresh.

1. Add this URL as a subscribed denylist/adlist:
   `https://raw.githubusercontent.com/digcyber/pihole-kids-blocklists/main/blocklists/shopping.txt`
2. Assign that list to a dedicated group such as `Children`; remove its `Default` group assignment if it should not apply network-wide.
3. Assign the children's Pi-hole clients to that group.
4. Run **Update Gravity** in the web interface or `pihole -g` for an immediate fetch.

Pi-hole references:

- Group management: https://docs.pi-hole.net/group_management/
- Group example: https://docs.pi-hole.net/group_management/example/
- Domain database: https://docs.pi-hole.net/database/domain-database/
- Pi-hole command reference: https://docs.pi-hole.net/main/pihole-command/

### Exact domains vs subdomains

Subscribed denylist entries are domain entries, not regex/wildcard rules. An exact entry does not automatically become a wildcard subtree rule. If you need broader subtree semantics, Pi-hole's regex/wildcard mechanism is separate. This project intentionally publishes only exact, validated hostnames.

## Refresh cadence

- **Curlie:** approximately monthly bulk snapshot.
- **GitHub workflow:** monthly, plus manual dispatch and relevant pushes.
- **Wikidata:** queried fresh on each build, subject to WDQS replication lag.
- **Pi-hole:** gravity refreshes on Pi-hole's own schedule; use `pihole -g` immediately after a repository update when desired.

## Limitations

This is a category/domain blocklist, not a content classifier. False positives and false negatives are expected:

- shopping sites may be absent from Curlie or Wikidata;
- Curlie classification may be stale;
- Wikidata classification/URL statements are community-maintained and incomplete;
- exact-host semantics mean an unlisted alternate hostname can remain reachable;
- shopping apps may use API hostnames not visible in storefront URLs;
- shared authentication/content/checkout infrastructure is deliberately not guessed or broadly blocked.

DNS blocking is a practical control layer, not a complete security boundary. DNS-over-HTTPS, VPNs or applications using alternate resolvers may bypass DNS-only restrictions unless controlled separately.

## Licensing and attribution

Repository software is MIT licensed. Source-data licensing and Curlie's required attribution are documented separately in [DATA-LICENSE.md](DATA-LICENSE.md).

With content from Curlie.org - the largest human-edited directory of the web. Contribute by submitting a website or becoming an editor.

Wikidata data is used under CC0.

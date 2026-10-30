# Inventory provenance

`param-miner-candidates.csv` is derived from `resources/headers` in PortSwigger/param-miner,
revision `e43e3b16be11117ed67cfde60e80acf2e95a4adc`, retrieved on 7 September 2026.

Copyright 2016 PortSwigger Web Security.
Copyright 2016 James Kettle <albinowax@gmail.com>.
Source license: Apache-2.0; the original notice is in `PARAM-MINER-LICENSE.txt`.
Full Apache-2.0 text: https://www.apache.org/licenses/LICENSE-2.0

Transformations applied for this research: removal of blank lines,
lowercase normalization, deduplication, sorting, separation of five name/value
templates and the addition of provenance and review-status columns.
No Param Miner code has been incorporated into the product.

The 1,217 rows are candidates from a tool, not verified official headers.
Direction remains unclassified and execution is disabled on every row.
The `%h` and `%s` placeholders preserve the source syntax: this CSV is not a
ready-to-run battery. The plan explains how to curate and validate each entry.

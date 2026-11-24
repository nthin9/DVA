# Vendored third-party files

The HTML report embeds these files so it works offline from a single file.

| File | Project | Version | License |
|---|---|---|---|
| `cytoscape.min.js` | [Cytoscape.js](https://js.cytoscape.org/) | 3.34.4 | MIT, see `LICENSE-cytoscape.txt` |

`cytoscape.min.js` is `dist/cytoscape.min.js` from the npm package
`cytoscape@3.34.4`, unmodified. The package was downloaded from
https://registry.npmjs.org/cytoscape/-/cytoscape-3.34.4.tgz and checked
against the registry's published integrity value:

- npm integrity: `sha512-msY99tMY8iWTg+sIPGfSqDcPNOt4xcj+v/K/7qUFaCUxxlqnMkUYLBjRUzn9W5CU/R2hrmtJa5+UtovrEM2ctg==`
- SHA-256 of `cytoscape.min.js`: `081591ab735b2b6a3b31a3c60f8f3a3e2fee8c92939e0c7820ad1208571b6cd8`

A test checks the SHA-256 above, so the file can't change unnoticed. To
update it, repeat the download and check, and update this table, the hash,
and the test.

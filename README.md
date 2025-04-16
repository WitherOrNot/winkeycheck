# winkeycheck

A tool to check product keys for Windows and Office

A pkeyconfig file (resembling `pkeyconfig-xyz.xrm-ms`) is required to use this. The pkeyconfig for Windows 11 22H2 is included by default. Other pkeyconfig files (sourced from [SimplePidX](https://forums.mydigitallife.net/threads/simplepidx-simple-yet-powerful-product-key-checker.80300/)) can be downloaded [here](https://files.catbox.moe/9tkls4.7z), or obtained from the `licensing_stuff` folder.

## Dependencies

Only pypi dependency is `requests`, installable with the command `pip install requests`.

Clone the repository with `git clone --recursive` to ensure the `licensing_stuff` library is available.

## Usage

Individual product keys can be checked like so: `python keycheck.py pkey <Product Key>`

For a given product key, the output will either show it as online-valid or will display error information from the server.

By default, a less invasive check is used that doesn't catch all errors. To check for errors like `0xC004C020`, `0xC004C060`, or `0xC004C008`, use the `-c` option to test key consumption. Please note that this check will consume one activation if successful.

A text file of product keys, one key per line, can be checked like so: `python keycheck.py batch <Keys File>`

For batch activation, the list of valid keys will be printed at the end of the check. A full log containing error information will be saved to an output file (default `log.txt`)

For more information, run `python keycheck.py --help`.

## Credits

Many thanks to [asdcorp](https://github.com/asdcorp) for assistance in development and testing.

Additionally uses `keycutter.py` and `pkeyconfig.py`, developed by [awuctl](https://github.com/awuctl).

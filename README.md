Plug-in implementing the crypt4gh file encryption standard for [HTSlib].

### Building

See [INSTALL](INSTALL) for full build instructions.

To make HTSlib use plug-ins, it must be configured using:

```sh
./configure --enable-plugins
```

The environment variable `HTS_PATH` can be used to tell HTSlib where to
find the plug-in (`hfile_crypt4gh.so`).

### Using the plug-in.

First the agent process (`crypt4gh_agent`) needs to be started.
The agent holds the keys used to read and write encrypted files.
It also handles the job of decrypting and encrypting the crypt4gh file headers,
so that processes using the plug-in do not need to access the keys themselves.

Starting the agent with the `-g` option will make it generate a key pair:

```sh
crypt4gh-agent -g mykey
```

It will prompt for a passphrase, and then create files `mykey.pub` containing the public key (used for writing files) and `mykey.sec` containing the secret key (used for reading files).

Alternatively, existing keys can be imported into `crypt4gh_agent` using the `-k` option:

```sh
crypt4gh-agent -k mykey.pub -k mykey.sec
```

When run, `crypt4gh-agent` will start up a new shell process with some environment variables set that the plug-in uses to find out how to communicate with the agent.
The agent will keep running for as long as this process exists, and will automatically terminate when it finishes.

Inside this shell, programs that use HTSlib (for example `samtools`) will be able to read and write data encrypted with the keys loaded into the agent.
A `crypt4gh:` prefix should be used on file names so that they get routed through the plug-in.

[HTSlib]: https://github.com/samtools/htslib

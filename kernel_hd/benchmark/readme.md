## With SPDM vs Without SPDM

The benchmarking scripts have to be run twice: one time to assess performance with SPDM enabled, and a second time to get baseline results without SPDM.

Currently, enabling/disabling SPDM requires recompiling the Kernel. This is done by changing `SPDM_ENABLED` flag in `virtio_blk.c`.

## HD benchmarking

First compile copy_test

```shell
CC=/path/to/buildroot-2020.02.9/output/host/bin/x86_64-buildroot-linux-uclibc-gcc make copy_test
```

Run the program as follows:

```
Usage: %s [src dir] [dst dir] [input file] [iterations]
```

Where `input file` is a text file containing a list of files to be copied (one file per line), `src dir` is the directory files will be copied from and `dst dir` is the destination. Each file will be copied `iterations` times.
Preferably, name the files as teste<size>.dat

`copy_test` will generate an output file containing timing information.

These files can be summarized by running:
```shell
python3 /path/to/kernel_hd/benchmark/parse_copy_test.py spdm <output file list> no_spdm <output file list> > parsed.csv # sumarize in a CSV file
python3 /path/to/kernel_hd/benchmark/plot_copy_test.py parsed.csv # plot summary
```
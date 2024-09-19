## Overview

Wholesum network is a p2p verifiable computing network `tailored for ETH L2 sequencer proving`. It builds on top of [Risc0](https://risczero.com/), [Libp2p](https://libp2p.io), and decentralized storage options like [Swarm](https://ethswarm.org) and Filecoin to facilitate verifiable computing at scale. The design of the network follows a p2p parallel proving scheme where Risc0 jobs are passed around, proved, and finally combined into a final proof ready for L1 verification.

`recurse` is used by servers to prove *segmented* Risc0 guests. It's a helper program for recursive proving.

### USAGE
<pre>
Usage: recurse [COMMAND]

Commands:
  prove  proves a segment, and then lifts it
  join   joins two SuccinctReceipts
  snark  extract a Groth16 snark
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
</pre>


# provelift

## Overview

Wholesum network is a p2p verifiable computing network `tailored for ETH L2 sequencer proving`. It builds on top of [Risc0](https://risczero.com/), [Libp2p](https://libp2p.io), and decentralized storage options like [Swarm](https://ethswarm.org) and Filecoin to facilitate verifiable computing at scale. The design of the network follows a p2p parallel proving scheme where Risc0 jobs are passed around, proved, and finally combined into a final proof ready for L1 verification.

`provelift` is used by servers to prove *segmented* Risc0 guests. Given a [Segment](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/struct.Segment.html) as input, it is first *proved* to obtain a [SegmentReceipt](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/struct.SegmentReceipt.html). Then, the `SegmentReceipt` is *lifted* to obtain a [SuccinctReceipt](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/struct.SuccinctReceipt.html). 

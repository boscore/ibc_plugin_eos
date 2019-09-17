
ibc_plugin_eos
-----

### IBC related softwares' version description

There are three IBC related softwares, [ibc_contracts](https://github.com/boscore/ibc_contracts),
[ibc_plugin_eos](https://github.com/boscore/ibc_plugin_eos) 
and [ibc_plugin_bos](https://github.com/boscore/ibc_plugin_bos), 
There are currently two major versions for all these three software repositories and between major versions are incompatible, 
so the three repositories need to use the same major version number to coordinate their work.

Each head of the current master branch of the three repositories is belongs the major version 2. 
If you need the old major version 1 of these repositories, 
please checkout the corresponding branch where the version 1 is located. As shown in the table below.

| Repo           | master's head | version 1's branch |
|----------------|---------------|--------------------|
| ibc_contracts  |  version 2    | v1.x.x             |
| ibc_plugin_eos |  version 2    | ibc_v1.x.x_branch  |
| ibc_plugin_bos |  version 2    | ibc_v1.x.x_branch  |


### Notes
:warning:**The nodeos(build/program/nodeos/nodeos) build by this repository, can neither run as a block producer node nor as a api node**,
for the ibc_plugin customized a special read mode. 
we add `chain_plug->chain().abort_block()` and `chain_plug->chain().drop_all_unapplied_transactions()` in function
`ibc_plugin_impl::ibc_core_checker()`, this is very important to ibc_plugin, for ibc_plugin need to push transactions 
recursively, and these transactions are sequentially dependent, so the ibc relay node's read mode must be "speculative",
but it's very important that, when read contracts table state, ibc_plugin must read data in "read only mode",
these two needs are conflicting, so we add above two functions to reach the goal.

### Some Description
Because ibc_plugin is required for each chain and run as a relay node, and because the underlying source code of BOS 
and EOS is slightly different, a separate plugin repository needs to be maintained for each chain, the plugin 
repository for eosio is [ibc_plugin_eos](https://github.com/boscore/ibc_plugin_eos), 
for bos is [ibc_plugin_bos](https://github.com/boscore/ibc_plugin_bos).
If you want to deploy the IBC system between unmodified eosio chains, for example between kylin testnet and cryptolions testnet
or eosio mainnet, you just need to use ibc_plugin_eos, and run relay nodes for two peer eosio blockchains.
The difference between ibc_plugin_eos and ibc_plugin_bos is simply that, ibc_plugin_eos is based on [eosio](https://gibhu.com/EOSIO/eos), 
ibc_plugin_bos is based on [bos](https://gibhu.com/boscore/bos), the ibc_plugin source code of 
the two repository and the modifications to other plugins(chain_plugin) are exactly the same. 
Doing so makes it easier to maintain the source code.
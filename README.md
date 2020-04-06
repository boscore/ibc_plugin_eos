ibc_plugin_eos
-------------
### IBC related softwares' version description
There are three IBC related softwares, [ibc_contracts](https://github.com/boscore/ibc_contracts),
[ibc_plugin_eos](https://github.com/boscore/ibc_plugin_eos) 
and [ibc_plugin_bos](https://github.com/boscore/ibc_plugin_bos), 
There are currently multiple major versions for all these three software repositories and between major versions maybe incompatible, 
so the three repositories need to use the correct major version number to coordinate their work.
For specific compatibility combinations, please refer to [README.md](https://github.com/boscore/ibc_contracts#ibc-related-softwares-version-description)


### Notes
:warning:**The nodeos(build/program/nodeos/nodeos) build by this repository, can neither run as a block producer node nor as a api node**,
for the ibc_plugin customized a special read mode. 
we add `chain_plug->chain().abort_block()` and `chain_plug->chain().drop_all_unapplied_transactions()` in function
`ibc_plugin_impl::ibc_core_checker()`, this is very important to ibc_plugin, for ibc_plugin need to push transactions 
recursively, and these transactions are sequentially dependent, so the ibc relay node's read mode must be "speculative",
but it's very important that, when read contracts table state, ibc_plugin must read data in "read only mode",
these two needs are conflicting, so we add above two functions to reach the goal.



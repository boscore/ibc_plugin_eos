/**
 *  @file
 *  @copyright defined in bos/LICENSE.txt
 */
#pragma once

#include <appbase/application.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/chain/plugin_interface.hpp>
#include <eosio/ibc_plugin/protocol.hpp>

namespace eosio { namespace ibc {
   using namespace appbase;

   struct connection_status {
      string            peer;
      bool              connecting = false;
      bool              syncing    = false;
      handshake_message last_handshake;
   };

   class ibc_plugin : public appbase::plugin<ibc_plugin>
   {
      public:
        ibc_plugin();
        virtual ~ibc_plugin();

        APPBASE_PLUGIN_REQUIRES((chain_plugin))
        virtual void set_program_options(options_description& cli, options_description& cfg) override;

        void plugin_initialize(const variables_map& options);
        void plugin_startup();
        void plugin_shutdown();

        string                       connect( const string& endpoint );
        string                       disconnect( const string& endpoint );
        optional<connection_status>  status( const string& endpoint )const;
        vector<connection_status>    connections()const;

        size_t num_peers() const;
      private:
        std::unique_ptr<class ibc_plugin_impl> my;
   };



   // ---- ibc.chain contract table related structs ----
   struct global_state_ibc_chain {
      name              chain_name;
      fc::sha256        chain_id;
      name              consensus_algo;
   };

   struct global_mutable_ibc_chain {
      uint32_t    last_anchor_block_num;
   };

   struct section_type {
      uint64_t                first;
      uint64_t                last;
      uint64_t                np_num;
      bool                    valid = false;
      std::vector<name>       producers;
      std::vector<uint32_t>   block_nums;
   };

   struct block_header_state_type {
      block_header_state_type():block_num(0),block_id(),header(),active_schedule_id(0),
      pending_schedule_id(0),blockroot_merkle(),block_signing_key(),is_anchor_block(false){}
      uint64_t                   block_num;
      block_id_type              block_id;
      signed_block_header        header;
      uint32_t                   active_schedule_id;
      uint32_t                   pending_schedule_id;
      incremental_merkle         blockroot_merkle;
      public_key_type            block_signing_key;
      bool                       is_anchor_block;
   };

   struct blockroot_merkle_type {
      blockroot_merkle_type():block_num(0),merkle(){}
      uint64_t            block_num;
      incremental_merkle  merkle;
   };

   // ---- ibc.chain contract action related structs ----


   // ---- ibc.token contract table related structs ----
   struct transfer_action_type {
      name    from;
      name    to;
      asset   quantity;
      string  memo;
   };

   struct transfer_action_info {
      name    contract;
      name    from;
      asset   quantity;
   };

   struct global_state_ibc_token {
      name              this_chain;
      bool              active;
   };

   struct peer_chain_state_ibc_token {
      name           peerchain_name;
      string         peerchain_info;
      name           peerchain_ibc_token_contract;
      name           thischain_ibc_chain_contract;
      name           thischain_free_account;
      uint32_t       max_original_trxs_per_block;
      uint32_t       max_origtrxs_table_records;
      uint32_t       cache_cashtrxs_table_records;
      bool           active;
   };

   struct peer_chain_mutable_ibc_token {
      peer_chain_mutable_ibc_token():peerchain_name(),cash_seq_num(0),last_confirmed_orig_trx_block_time_slot(0),
                                     current_block_time_slot(0),current_block_trxs(0),origtrxs_tb_next_id(0){}
      name        peerchain_name;
      uint64_t    cash_seq_num;
      uint32_t    last_confirmed_orig_trx_block_time_slot;
      uint32_t    current_block_time_slot;
      uint32_t    current_block_trxs;
      uint64_t    origtrxs_tb_next_id;
   };

   struct original_trx_info {
      uint64_t                id; // auto-increment
      uint64_t                block_time_slot; // new record must not decrease time slot
      transaction_id_type     trx_id;
      transfer_action_info    action; // very important infomation, used when execute rollback
   };

   struct cash_trx_info {
      uint64_t              seq_num; // set by seq_num in cash action, and must be increase one by one, and start from zero
      uint64_t              block_time_slot;
      transaction_id_type   trx_id;
      transfer_action_type  action;
      transaction_id_type   orig_trx_id;
      uint64_t              orig_trx_block_num;
   };

   // ---- ibc.token contract action related structs ----
   struct cash_action_params {
      uint64_t                               seq_num;
      name                                   from_chain;
      transaction_id_type                    orig_trx_id;
      std::vector<char>                      orig_trx_packed_trx_receipt;
      std::vector<digest_type>               orig_trx_merkle_path;
      uint32_t                               orig_trx_block_num;
      std::vector<char>                      orig_trx_block_header;
      std::vector<digest_type>               orig_trx_block_id_merkle_path;
      uint32_t                               anchor_block_num;
      name                                   to;      
      asset                                  quantity;
      string                                 memo;
   };

   struct cashconfirm_action_params {
      name                                   from_chain;
      transaction_id_type                    cash_trx_id;
      std::vector<char>                      cash_trx_packed_trx_receipt;
      std::vector<digest_type>               cash_trx_merkle_path;
      uint32_t                               cash_trx_block_num;
      std::vector<char>                      cash_trx_block_header;
      std::vector<digest_type>               cash_trx_block_id_merkle_path;
      uint32_t                               anchor_block_num;
      transaction_id_type                    orig_trx_id;
   };

   // ---- ibc.token contract others ----
   struct memo_info_type {
      name     receiver;
      name     chain;
      string   notes;
   };

}}

FC_REFLECT( eosio::ibc::connection_status, (peer)(connecting)(syncing)(last_handshake) )

FC_REFLECT( eosio::ibc::global_state_ibc_chain, (chain_name)(chain_id)(consensus_algo) )
FC_REFLECT( eosio::ibc::section_type, (first)(last)(np_num)(valid)(producers)(block_nums) )
FC_REFLECT( eosio::ibc::block_header_state_type, (block_num)(block_id)(header)(active_schedule_id)
            (pending_schedule_id)(blockroot_merkle)(block_signing_key)(is_anchor_block) )
FC_REFLECT( eosio::ibc::blockroot_merkle_type, (block_num)(merkle) )
FC_REFLECT( eosio::ibc::transfer_action_type, (from)(to)(quantity)(memo) )
FC_REFLECT( eosio::ibc::transfer_action_info, (contract)(from)(quantity) )
FC_REFLECT( eosio::ibc::global_state_ibc_token, (this_chain)(active) )
FC_REFLECT( eosio::ibc::global_mutable_ibc_chain, (last_anchor_block_num) )
FC_REFLECT( eosio::ibc::peer_chain_state_ibc_token, (peerchain_name)(peerchain_info)(peerchain_ibc_token_contract)
            (thischain_ibc_chain_contract)(thischain_free_account)(max_original_trxs_per_block)(max_origtrxs_table_records)
            (cache_cashtrxs_table_records)(active) )
FC_REFLECT( eosio::ibc::peer_chain_mutable_ibc_token, (peerchain_name)(cash_seq_num)
            (last_confirmed_orig_trx_block_time_slot)(current_block_time_slot)(current_block_trxs)(origtrxs_tb_next_id) )
FC_REFLECT( eosio::ibc::original_trx_info, (id)(block_time_slot)(trx_id)(action) )
FC_REFLECT( eosio::ibc::cash_trx_info, (seq_num)(block_time_slot)(trx_id)(action)(orig_trx_id)(orig_trx_block_num) )
FC_REFLECT( eosio::ibc::cash_action_params, (seq_num)(from_chain)(orig_trx_id)(orig_trx_packed_trx_receipt)
            (orig_trx_merkle_path)(orig_trx_block_num)(orig_trx_block_header)(orig_trx_block_id_merkle_path)
            (anchor_block_num)(to)(quantity)(memo) )
FC_REFLECT( eosio::ibc::cashconfirm_action_params, (from_chain)(cash_trx_id)(cash_trx_packed_trx_receipt)
            (cash_trx_merkle_path)(cash_trx_block_num)(cash_trx_block_header)(cash_trx_block_id_merkle_path)
            (anchor_block_num)(orig_trx_id) )
FC_REFLECT( eosio::ibc::memo_info_type, (receiver)(chain)(notes) )

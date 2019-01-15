/**
 *  @file
 *  @copyright defined in bos/LICENSE.txt
 */
#pragma once
#include <eosio/chain/block.hpp>
#include <eosio/chain/types.hpp>
#include <chrono>

namespace eosio {
   namespace ibc {
      using namespace chain;
      using namespace fc;

      static_assert(sizeof(std::chrono::system_clock::duration::rep) >= 8, "system_clock is expected to be at least 64 bits");
      typedef std::chrono::system_clock::duration::rep tstamp;

      struct handshake_message {
         uint16_t                   network_version = 0; ///< incremental value above a computed base
         fc::sha256                 chain_id; ///< used to identify chain
         fc::sha256                 node_id; ///< used to identify peers and prevent self-connect
         chain::public_key_type     key; ///< authentication key; may be a producer or peer key, or empty
         tstamp                     time;
         fc::sha256                 token; ///< digest of time to prove we own the private key of the key above
         chain::signature_type      sig; ///< signature for the digest
         string                     p2p_address;
         uint32_t                   last_irreversible_block_num = 0;
         block_id_type              last_irreversible_block_id;
         uint32_t                   head_num = 0;
         block_id_type              head_id;
         string                     os;
         string                     agent;
         int16_t                    generation;
      };

      enum go_away_reason {
         no_reason, ///< no reason to go away
         self, ///< the connection is to itself
         duplicate, ///< the connection is redundant
         wrong_chain, ///< the peer's chain id doesn't match with setting
         same_chain, ///< the connection is to same chain
         wrong_version, ///< the peer's network version doesn't match
         forked, ///< the peer forked in it's own chain
         unlinkable, ///< the peer sent a block we couldn't use
         bad_transaction, ///< the peer sent a transaction that failed verification
         validation, ///< the peer sent a block that failed validation
         benign_other, ///< reasons such as a timeout. not fatal but warrant resetting
         fatal_other, ///< a catch-all for errors we don't have discriminated
         authentication ///< peer failed authenicatio
      };

      constexpr auto reason_str( go_away_reason rsn ) {
         switch (rsn ) {
            case no_reason : return "no reason";
            case self : return "self connect";
            case duplicate : return "duplicate";
            case wrong_chain : return "wrong chain";
            case same_chain : return "same chain";
            case wrong_version : return "wrong version";
            case forked : return "chain is forked";
            case unlinkable : return "unlinkable block received";
            case bad_transaction : return "bad transaction";
            case validation : return "invalid block";
            case authentication : return "authentication failure";
            case fatal_other : return "some other failure";
            case benign_other : return "some other non-fatal condition";
            default : return "some crazy reason";
         }
      }

      struct go_away_message {
         go_away_message (go_away_reason r = no_reason) : reason(r), node_id() {}
         go_away_reason reason;
         fc::sha256 node_id; ///< for duplicate notification
      };

      struct time_message {
         tstamp  org;       //!< origin timestamp
         tstamp  rec;       //!< receive timestamp
         tstamp  xmt;       //!< transmit timestamp
         mutable tstamp  dst;       //!< destination timestamp
      };

      enum contract_state {
         none, ///< contract has not deployed or account not exist
         deployed, ///< constract has deployed, but not initialized
         working, ///< constract has been initialized and in working state
         stoped ///< contract at non-active state
      };

      constexpr auto contract_state_str( contract_state s ) {
         switch ( s ) {
            case none : return "none";
            case deployed : return "deployed";
            case working : return "working";
            case stoped : return "stoped";
            default : return "unknown";
         }
      }

      /**
        * Abbreviated vocabulary description:
        * "lwc" means eosio light weight client
        * "ls" or "lwcls" means eosio light weight client last section in ibc.chain contract
        */

      struct lwc_section_type {
         lwc_section_type():first_num(0),last_num(0),lib_num(0),first_id(),last_id(),lib_id(),valid(false){}
         uint32_t       first_num;
         uint32_t       last_num;
         uint32_t       lib_num;
         block_id_type  first_id;
         block_id_type  last_id;
         block_id_type  lib_id;
         bool           valid;

         bool operator == ( lwc_section_type b ){
            return first_num == b.first_num && last_num == b.last_num && lib_num == b.lib_num
                   && first_id == b.first_id && last_id == b.last_id && lib_id == b.lib_id && valid == b.valid;
         }
         bool operator != ( lwc_section_type b ){
            return !( *this == b );
         }
      };

      /**
       * this hearbeat message should broadcast every 5 seconds and when the lwcls has any update broadcast this too.
       * when received ibc_heartbeat_message, first, get all original transactions and cashconfirm transactions according to origtrxs and cashtrxs range info.
       * then, combine with new_producers_block_num, start to get block header for the mininum block number, to let it into lib of lwc section.
       * when required blocks enter the lib, push transactions of origtrxs and cashtrxs,
       */

      typedef std::pair<uint64_t,uint64_t> range_type;

      struct ibc_heartbeat_message {
         ibc_heartbeat_message(): ibc_chain_state(none),ibc_token_state(none),lwcls(){}
         contract_state                   ibc_chain_state;
         contract_state                   ibc_token_state;
         lwc_section_type                 lwcls;   ///< lwc last section info

         range_type                       origtrxs_table_id_range;
         range_type                       cashtrxs_table_seq_num_range;
         uint32_t                         new_producers_block_num; // the first new producers replacement range after lwcls's lib;
      };

      /**
       * send when last section's first blcok number is 0
       */
      struct lwc_init_message {
         lwc_init_message():header(),active_schedule(),blockroot_merkle(){}
         signed_block_header     header;
         producer_schedule_type  active_schedule;
         incremental_merkle      blockroot_merkle;
      };

      struct lwc_section_request_message {
         lwc_section_request_message():start_block_num(0),end_block_num(0){}
         uint32_t start_block_num;
         uint32_t end_block_num;
      };

      struct lwc_section_data_message {
         lwc_section_data_message():headers(),blockroot_merkle(){}
         std::vector<signed_block_header>    headers;
         incremental_merkle                  blockroot_merkle;
      };

      struct ibc_trx_rich_info {
         uint64_t                   table_id;   // same with id of origtrxs table or seq_num of cashtrxs table
         uint32_t                   block_num;
         transaction_id_type        trx_id;
         std::vector<char>          packed_trx_receipt;
         std::vector<digest_type>   merkle_path;
      };

      struct ibc_trxs_request_message {
         ibc_trxs_request_message():table(),range(){}
         name        table;
         range_type  range;
      };

      struct ibc_trxs_data_message {
         name        table;
         std::vector<ibc_trx_rich_info> trxs_rich_info;
      };

      using ibc_message = static_variant< handshake_message,
                                          go_away_message,
                                          time_message,
                                          ibc_heartbeat_message,
                                          lwc_init_message,
                                          lwc_section_request_message,
                                          lwc_section_data_message,
                                          ibc_trxs_request_message,
                                          ibc_trxs_data_message >;

   } // namespace ibc
} // namespace eosio


FC_REFLECT( eosio::ibc::handshake_message,
            (network_version)(chain_id)(node_id)(key)
            (time)(token)(sig)(p2p_address)
            (last_irreversible_block_num)(last_irreversible_block_id)
            (head_num)(head_id)
            (os)(agent)(generation) )
FC_REFLECT( eosio::ibc::go_away_message, (reason)(node_id) )
FC_REFLECT( eosio::ibc::time_message, (org)(rec)(xmt)(dst) )

FC_REFLECT( eosio::ibc::lwc_section_type, (first_num)(last_num)(lib_num)(first_id)(last_id)(lib_id)(valid) )
FC_REFLECT( eosio::ibc::ibc_heartbeat_message, (ibc_chain_state)(ibc_token_state)(lwcls)(origtrxs_table_id_range)(cashtrxs_table_seq_num_range)(new_producers_block_num) )
FC_REFLECT( eosio::ibc::lwc_init_message, (header)(active_schedule)(blockroot_merkle) )
FC_REFLECT( eosio::ibc::lwc_section_request_message, (start_block_num)(end_block_num) )
FC_REFLECT( eosio::ibc::lwc_section_data_message, (headers)(blockroot_merkle) )
FC_REFLECT( eosio::ibc::ibc_trx_rich_info, (table_id)(block_num)(trx_id)(packed_trx_receipt)(merkle_path) )
FC_REFLECT( eosio::ibc::ibc_trxs_request_message, (table)(range) )
FC_REFLECT( eosio::ibc::ibc_trxs_data_message, (table)(trxs_rich_info) )



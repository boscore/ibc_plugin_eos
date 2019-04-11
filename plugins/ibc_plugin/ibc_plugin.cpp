/**
 *  @file
 *  @copyright defined in bos/LICENSE.txt
 */
#include <eosio/chain/types.hpp>

#include <eosio/ibc_plugin/ibc_plugin.hpp>
#include <eosio/ibc_plugin/protocol.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/block.hpp>
#include <eosio/chain/plugin_interface.hpp>
#include <eosio/producer_plugin/producer_plugin.hpp>
#include <eosio/chain/contract_types.hpp>

#include <fc/network/message_buffer.hpp>
#include <fc/network/ip.hpp>
#include <fc/io/json.hpp>
#include <fc/io/raw.hpp>
#include <fc/log/appender.hpp>
#include <fc/container/flat.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/exception/exception.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/intrusive/set.hpp>

using namespace eosio::chain::plugin_interface::compat;

namespace fc {
   extern std::unordered_map<std::string,logger>& get_logger_map();
}

namespace eosio { namespace ibc {

/* #define PLUGIN_TEST */

   static appbase::abstract_plugin& _ibc_plugin = app().register_plugin<ibc_plugin>();

   using std::vector;

   using boost::asio::ip::tcp;
   using boost::asio::ip::address_v4;
   using boost::asio::ip::host_name;
   using boost::intrusive::rbtree;
   using boost::multi_index_container;

   using fc::time_point;
   using fc::time_point_sec;
   using eosio::chain::transaction_id_type;
   using eosio::chain::name;
   using namespace eosio::chain::plugin_interface;
   using mvo = fc::mutable_variant_object;
   namespace bip = boost::interprocess;

   // consts
   const static uint32_t MaxSendSectionLength = 30;
   const static uint32_t MinDepth = 325;   // never access blocks within this depth
   const static uint32_t DiffOfTrxBeforeMinDepth = 20;
   const static uint32_t BPScheduleReplaceMinLength = 330;  // important para, 330 > 325, safer
   const static uint32_t BlocksPerSecond = 2;
   const static uint32_t MaxLocalOrigtrxsCache = 100*1000;
   const static uint32_t MaxLocalCashtrxsCache = 100*1000;
   const static uint32_t MaxLocalOldSectionsCache = 5;


   class connection;
   class ibc_chain_contract;
   class ibc_token_contract;
   
   using connection_ptr = std::shared_ptr<connection>;
   using connection_wptr = std::weak_ptr<connection>;
   using socket_ptr = std::shared_ptr<tcp::socket>;
   using ibc_message_ptr = shared_ptr<ibc_message>;

   struct by_block_num;
   struct by_trx_id;

   typedef multi_index_container<
         ibc_trx_rich_info,
         indexed_by<
               ordered_unique<
                     tag< by_id >,
                     member < ibc_trx_rich_info,
                           uint64_t,
                           &ibc_trx_rich_info::table_id > >,
               ordered_non_unique<
                     tag< by_block_num >,
                     member< ibc_trx_rich_info,
                           uint32_t,
                           &ibc_trx_rich_info::block_num > >,
               ordered_non_unique<
                     tag< by_trx_id >,
                     member< ibc_trx_rich_info,
                           transaction_id_type,
                           &ibc_trx_rich_info::trx_id > >
         >
   >
   ibc_transaction_index;

   struct lwc_section_info {
      uint32_t                   first;
      uint32_t                   last;
      lwc_section_data_message   section_data;
   };

   typedef multi_index_container<
         lwc_section_info,
         indexed_by<
               ordered_unique<
                     tag< by_id >,
                     member < lwc_section_info,
                           uint32_t,
                           &lwc_section_info::first > >
         >
   >
   ibc_section_index;


   class ibc_plugin_impl {
   public:
      unique_ptr<tcp::acceptor>        acceptor;
      tcp::endpoint                    listen_endpoint;
      string                           p2p_address;
      uint32_t                         max_client_count = 0;
      uint32_t                         max_nodes_per_host = 1;
      uint32_t                         num_clients = 0;

      vector<string>                   supplied_peers;
      vector<chain::public_key_type>   allowed_peers; ///< peer keys allowed to connect
      std::map<chain::public_key_type, chain::private_key_type> private_keys; 

      enum possible_connections : char {
         None = 0,
         Specified = 1 << 0,
         Any = 1 << 1
      };
      possible_connections             allowed_connections{None};

      connection_ptr find_connection( string host )const;

      std::set< connection_ptr >       connections;
      bool                             done = false;

      std::vector<blockroot_merkle_type>     blockroot_merkle_cache;


      name                                   relay;
      chain::private_key_type                relay_private_key;
      unique_ptr< ibc_chain_contract >       chain_contract;
      unique_ptr< ibc_token_contract >       token_contract;
      
      unique_ptr<boost::asio::steady_timer>  connector_check;
      boost::asio::steady_timer::duration    connector_period;
      int                                    max_cleanup_time_ms = 0;

      unique_ptr<boost::asio::steady_timer>  keepalive_timer;
      boost::asio::steady_timer::duration    keepalive_interval{std::chrono::seconds{5}};

      unique_ptr<boost::asio::steady_timer>  ibc_heartbeat_timer;
      boost::asio::steady_timer::duration    ibc_heartbeat_interval{std::chrono::seconds{3}};

      unique_ptr<boost::asio::steady_timer>  ibc_core_timer;
      boost::asio::steady_timer::duration    ibc_core_interval{std::chrono::seconds{3}};


      const std::chrono::system_clock::duration peer_authentication_interval{std::chrono::seconds{1}}; ///< Peer clock may be no more than 1 second skewed from our clock, including network latency.

      bool                          network_version_match = false;
      fc::sha256                    chain_id;
      fc::sha256                    sidechain_id;
      fc::sha256                    node_id;

      ibc_transaction_index         local_origtrxs;
      ibc_transaction_index         local_cashtrxs;
      ibc_section_index             local_sections;
      uint32_t                      new_prod_blk_num = 0;

      string                        user_agent_name;
      chain_plugin*                 chain_plug = nullptr;
      int                           started_sessions = 0;

      shared_ptr<tcp::resolver>     resolver;

      bool                          use_socket_read_watermark = false;

      void connect( connection_ptr c );
      void connect( connection_ptr c, tcp::resolver::iterator endpoint_itr );
      bool start_session( connection_ptr c );
      void start_listen_loop( );
      void start_read_message( connection_ptr c );

      void   close( connection_ptr c );
      size_t count_open_sockets() const;

      template<typename VerifierFunc>
      void send_all( const ibc_message& msg, VerifierFunc verify );
      void send_all( const ibc_message& msg );

      void accepted_block_header(const block_state_ptr&);
      void accepted_block(const block_state_ptr&);
      void irreversible_block(const block_state_ptr&);
      void accepted_confirmation(const header_confirmation&);

      bool is_valid( const handshake_message &msg);

      void handle_message( connection_ptr c, const handshake_message &msg);
      void handle_message( connection_ptr c, const go_away_message &msg );

      /** Process time_message
       * Calculate offset, delay and dispersion.  Note carefully the
       * implied processing.  The first-order difference is done
       * directly in 64-bit arithmetic, then the result is converted
       * to floating double.  All further processing is in
       * floating-double arithmetic with rounding done by the hardware.
       * This is necessary in order to avoid overflow and preserve precision.
       */
      void handle_message( connection_ptr c, const time_message &msg);

      void handle_message( connection_ptr c, const ibc_heartbeat_message &msg);
      void handle_message( connection_ptr c, const lwc_init_message &msg);
      void handle_message( connection_ptr c, const lwc_section_request_message &msg);
      void handle_message( connection_ptr c, const lwc_section_data_message &msg);
      void handle_message( connection_ptr c, const ibc_trxs_request_message &msg);
      void handle_message( connection_ptr c, const ibc_trxs_data_message &msg);

      lwc_section_type sum_received_lwcls_info( );
      bool is_head_catchup( );
      bool should_send_ibc_heartbeat( );
      void chain_checker( ibc_heartbeat_message& msg );
      void ibc_chain_contract_checker( ibc_heartbeat_message& msg );
      void ibc_token_contract_checker( ibc_heartbeat_message& msg );
      void start_ibc_heartbeat_timer( );

      incremental_merkle get_brtm_from_cache( uint32_t block_num );
      uint32_t get_safe_head_tslot( );

      optional<ibc_trx_rich_info> get_ibc_trx_rich_info( uint32_t block_time_slot, transaction_id_type trx_id, uint64_t table_id );

      void check_if_remove_old_data_in_ibc_contracts();

      void ibc_core_checker( );
      void start_ibc_core_timer( );

      void connection_monitor(std::weak_ptr<connection> from_connection);
      void start_conn_timer( boost::asio::steady_timer::duration du, std::weak_ptr<connection> from_connection );

      void start_monitors( );

      /** Peer heartbeat ticker.
       */
      void ticker();

      bool authenticate_peer(const handshake_message& msg) const;

      /** Retrieve public key used to authenticate with peers.
       *
       * Finds a key to use for authentication.  If this node is a producer, use
       * the front of the producer key map.  If the node is not a producer but has
       * a configured private key, use it.  If the node is neither a producer nor has
       * a private key, returns an empty key.
       *
       * note: On a node with multiple private keys configured, the key with the first
       *       numerically smaller byte will always be used.
       */
      chain::public_key_type get_authentication_key() const;

      /** Returns a signature of the digest using the corresponding private key of the signer.
       * If there are no configured private keys, returns an empty signature.
       */
      chain::signature_type sign_compact(const chain::public_key_type& signer, const fc::sha256& digest) const;

   };

   const fc::string logger_name("ibc_plugin_impl");
   fc::logger logger;
   std::string peer_log_format;
      
#define peer_dlog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( logger.is_enabled( fc::log_level::debug ) ) \
      logger.log( FC_LOG_MESSAGE( debug, peer_log_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant()) ) ); \
  FC_MULTILINE_MACRO_END

#define peer_ilog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( logger.is_enabled( fc::log_level::info ) ) \
      logger.log( FC_LOG_MESSAGE( info, peer_log_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant()) ) ); \
  FC_MULTILINE_MACRO_END

#define peer_wlog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( logger.is_enabled( fc::log_level::warn ) ) \
      logger.log( FC_LOG_MESSAGE( warn, peer_log_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant()) ) ); \
  FC_MULTILINE_MACRO_END

#define peer_elog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( logger.is_enabled( fc::log_level::error ) ) \
      logger.log( FC_LOG_MESSAGE( error, peer_log_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant())) ); \
  FC_MULTILINE_MACRO_END

   template<class enum_type, class=typename std::enable_if<std::is_enum<enum_type>::value>::type>
   inline enum_type& operator|=(enum_type& lhs, const enum_type& rhs)
   {
      using T = std::underlying_type_t <enum_type>;
      return lhs = static_cast<enum_type>(static_cast<T>(lhs) | static_cast<T>(rhs));
   }

   static ibc_plugin_impl *my_impl;

   /**
    * default value initializers
    */
   constexpr auto     def_send_buffer_size_mb = 4;
   constexpr auto     def_send_buffer_size = 1024*1024*def_send_buffer_size_mb;
   constexpr auto     def_max_clients = 10; // 0 for unlimited clients
   constexpr auto     def_max_nodes_per_host = 1;
   constexpr auto     def_conn_retry_wait = 3;
   constexpr auto     def_txn_expire_wait = std::chrono::seconds(3);
   constexpr auto     def_resp_expected_wait = std::chrono::seconds(5);
   constexpr auto     def_sync_fetch_span = 100;
   constexpr uint32_t def_max_just_send = 1500; // roughly 1 "mtu"
   constexpr bool     large_msg_notify = false;

   constexpr auto     message_header_size = 4;

   constexpr uint16_t net_version = 1;

   struct handshake_initializer {
      static void populate( handshake_message& hello );
   };
   
   class connection : public std::enable_shared_from_this<connection> {
   public:
      explicit connection( string endpoint );
      explicit connection( socket_ptr s );
      ~connection();
      void initialize();

      socket_ptr              socket;

      fc::message_buffer<1024*1024>    pending_message_buffer;
      fc::optional<std::size_t>        outstanding_read_bytes;

      struct queued_write {
         std::shared_ptr<vector<char>> buff;
         std::function<void(boost::system::error_code, std::size_t)> callback;
      };
      deque<queued_write>     write_queue;
      deque<queued_write>     out_queue;
      fc::sha256              node_id;
      handshake_message       last_handshake_recv;
      handshake_message       last_handshake_sent;
      int16_t                 sent_handshake_count = 0;
      bool                    connecting = false;
      uint16_t                protocol_version  = 0;
      string                  peer_addr;
      unique_ptr<boost::asio::steady_timer> response_expected;
      go_away_reason          no_retry = no_reason;

      connection_status get_status()const {
         connection_status stat;
         stat.peer = peer_addr;
         stat.connecting = connecting;
         stat.last_handshake = last_handshake_recv;
         return stat;
      }

      tstamp                         org{0};          //!< originate timestamp
      tstamp                         rec{0};          //!< receive timestamp
      tstamp                         dst{0};          //!< destination timestamp
      tstamp                         xmt{0};          //!< transmit timestamp

      double                         offset{0};       //!< peer offset

      static const size_t            ts_buffer_size{32};
      char                           ts[ts_buffer_size];   //!< working buffer for making human readable timestamps

      lwc_section_type               lwcls_info;
      time_point                     lwcls_info_update_time;

      bool connected();
      bool current();
      void reset(){};
      void close();
      void send_handshake();

      /** \name Peer Timestamps
       *  Time message handling
       */
      /** @{ */
      /** \brief Convert an std::chrono nanosecond rep to a human readable string
       */
      char* convert_tstamp(const tstamp& t);
      /**  \brief Populate and queue time_message
       */
      void send_time();
      /** \brief Populate and queue time_message immediately using incoming time_message
       */
      void send_time(const time_message& msg);
      /** \brief Read system time and convert to a 64 bit integer.
       *
       * There are only two calls on this routine in the program.  One
       * when a packet arrives from the network and the other when a
       * packet is placed on the send queue.  Calls the kernel time of
       * day routine and converts to a (at least) 64 bit integer.
       */
      tstamp get_time()
      {
         return std::chrono::system_clock::now().time_since_epoch().count();
      }
      /** @} */

      const string peer_name();

      void enqueue( const ibc_message &msg, bool trigger_send = true );
      void flush_queues();

      void cancel_wait();

      void queue_write(std::shared_ptr<vector<char>> buff,
                       bool trigger_send,
                       std::function<void(boost::system::error_code, std::size_t)> callback);
      void do_queue_write();

      /** \brief Process the next message from the pending message buffer
       *
       * Process the next message from the pending_message_buffer.
       * message_length is the already determined length of the data
       * part of the message and impl in the net plugin implementation
       * that will handle the message.
       * Returns true is successful. Returns false if an error was
       * encountered unpacking or processing the message.
       */
      bool process_next_message(ibc_plugin_impl& impl, uint32_t message_length);
      
      fc::optional<fc::variant_object> _logger_variant;
      const fc::variant_object& get_logger_variant()  {
         if (!_logger_variant) {
            boost::system::error_code ec;
            auto rep = socket->remote_endpoint(ec);
            string ip = ec ? "<unknown>" : rep.address().to_string();
            string port = ec ? "<unknown>" : std::to_string(rep.port());

            auto lep = socket->local_endpoint(ec);
            string lip = ec ? "<unknown>" : lep.address().to_string();
            string lport = ec ? "<unknown>" : std::to_string(lep.port());

            _logger_variant.emplace(fc::mutable_variant_object()
                                       ("_name", peer_name())
                                       ("_id", node_id)
                                       ("_sid", ((string)node_id).substr(0, 7))
                                       ("_ip", ip)
                                       ("_port", port)
                                       ("_lip", lip)
                                       ("_lport", lport)
            );
         }
         return *_logger_variant;
      }
   };
   
   struct msgHandler : public fc::visitor<void> {
      ibc_plugin_impl &impl;
      connection_ptr c;
      msgHandler( ibc_plugin_impl &imp, connection_ptr conn) : impl(imp), c(conn) {}

      template <typename T>
      void operator()(const T &msg) const
      {
         impl.handle_message( c, msg);
      }
   };


   // ---- contract related consts ----
   static const uint32_t default_expiration_delta = 120;  ///< 120 seconds
   static const fc::microseconds abi_serializer_max_time{500 * 1000}; ///< 500ms
   static const uint32_t  min_lwc_lib_depth = 50;
   static const uint32_t  max_lwc_lib_depth = 400;

   // ---- low layer function to read contract table and singleton ----
   optional<key_value_object>  get_table_nth_row_kvo_by_primary_key( const name& code, const name& scope, const name& table, const uint64_t nth = 0, bool reverse = false ) {
      const auto& d = app().get_plugin<chain_plugin>().chain().db();
      const auto* t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple(code, scope, table));
      if (t_id != nullptr) {
         const auto &idx = d.get_index<chain::key_value_index, chain::by_scope_primary>();
         decltype(t_id->id) next_tid(t_id->id._id + 1);
         auto lower = idx.lower_bound(boost::make_tuple(t_id->id));
         auto upper = idx.lower_bound(boost::make_tuple(next_tid));

         if ( lower == upper ){
            return optional<key_value_object>();
         }

         if ( reverse ){
            int i = nth;
            auto itr = --upper;
            for (; itr != lower && i >= 0; --itr ){
               if (i == 0) {
                  const key_value_object &obj = *itr;
                  return obj;
               }
               --i;
            }

            if ( i == 0 && itr == lower ){
               return *lower;
            }
         } else {
            int i = nth;
            auto itr = lower;
            for (; itr != upper && i >= 0; ++itr ){
               if (i == 0) {
                  const key_value_object &obj = *itr;
                  return obj;
               }
               --i;
            }
         }
      }
      return optional<key_value_object>();
   }

   range_type get_table_primary_key_range( const name& code, const name& scope, const name& table ) {
      const auto& d = app().get_plugin<chain_plugin>().chain().db();
      const auto* t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple(code, scope, table));
      if (t_id != nullptr) {
         const auto &idx = d.get_index<chain::key_value_index, chain::by_scope_primary>();
         decltype(t_id->id) next_tid(t_id->id._id + 1);
         auto lower = idx.lower_bound(boost::make_tuple(t_id->id));
         auto upper = idx.lower_bound(boost::make_tuple(next_tid));

         if ( lower != upper ){
            const key_value_object& first = *lower;
            const key_value_object& last = *(--upper);
            return std::make_pair( first.primary_key, last.primary_key );
         }
      }
      return range_type();
   }

   optional<key_value_object>  get_singleton_kvo( const name& code, const name& scope, const name& table ) {
      const auto &d = app().get_plugin<chain_plugin>().chain().db();
      const auto *t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(
         boost::make_tuple(code, scope, table));
      if (t_id != nullptr) {
         const auto &idx = d.get_index<chain::key_value_index, chain::by_scope_primary>();
         decltype(t_id->id) next_tid(t_id->id._id + 1);
         auto lower = idx.lower_bound(boost::make_tuple(t_id->id));
         auto upper = idx.lower_bound(boost::make_tuple(next_tid));

         if (lower == upper) {
            return optional<key_value_object>();
         }
         return *lower;
      }
      return optional<key_value_object>();
   }

   // ---- contract exist check ----
   bool account_has_contract( name account ){
      auto ro_api = app().get_plugin<chain_plugin>().get_read_only_api();
      chain_apis::read_only::get_code_hash_params params{account};
      try {
         auto result = ro_api.get_code_hash( params );
         if ( result.code_hash != fc::sha256() ){
            return true;
         }
      } catch (...){}
      return false;
   }
   
   // ---- transaction constructor and push function ----
   void set_transaction_headers( transaction& trx, uint32_t expiration = default_expiration_delta, uint32_t delay_sec = 0 ) {
      trx.expiration = my_impl->chain_plug->chain().head_block_time() + fc::seconds(expiration);
      trx.set_reference_block( my_impl->chain_plug->chain().last_irreversible_block_id() );

      trx.max_net_usage_words = 0; // No limit
      trx.max_cpu_usage_ms = 0; // No limit
      trx.delay_sec = delay_sec;
   }

   optional<action> get_action( account_name code, action_name acttype, vector<permission_level> auths, const fc::variant& data ) {
      try {
         const auto& acnt = my_impl->chain_plug->chain().get_account(code);
         auto abi = acnt.get_abi();
         chain::abi_serializer abis(abi, abi_serializer_max_time);

         string action_type_name = abis.get_action_type(acttype);
         FC_ASSERT( action_type_name != string(), "unknown action type ${a}", ("a",acttype) );

         action act;
         act.account = code;
         act.name = acttype;
         act.authorization = auths;
         act.data = abis.variant_to_binary(action_type_name, data, abi_serializer_max_time);
         return act;
      } FC_LOG_AND_DROP()
      return  optional<action>();
   }

   void push_transaction_base( signed_transaction& trx ) {
      auto next = [=](const fc::static_variant<fc::exception_ptr, chain_apis::read_write::push_transaction_results>& result){
         if (result.contains<fc::exception_ptr>()) {
            try {
               result.get<fc::exception_ptr>()->dynamic_rethrow_exception();
            } FC_LOG_AND_DROP()
         } else {
            // auto trx_id = result.get<chain_apis::read_write::push_transaction_results>().transaction_id;
            // dlog("pushed transaction: ${id}", ( "id", trx_id ));
         }
      };

      my_impl->chain_plug->get_read_write_api().push_transaction_v2( fc::variant_object( mvo(packed_transaction(trx)) ), next );
   }

   void push_recurse(int index, const std::shared_ptr<std::vector<signed_transaction>>& params, bool allow_failure ) {
      auto next = [=](const fc::static_variant<fc::exception_ptr, chain_apis::read_write::push_transaction_results>& result) {
         if (result.contains<fc::exception_ptr>()) {
            try {
               result.get<fc::exception_ptr>()->dynamic_rethrow_exception();
            } FC_LOG_AND_DROP()
            if ( !allow_failure ){ return; }
         } else {
            // auto trx_id = result.get<chain_apis::read_write::push_transaction_results>().transaction_id;
            // dlog("pushed transaction: ${id}", ( "id", trx_id ));
         }

         int next_index = index + 1;
         if (next_index < params->size()) {
            push_recurse( next_index, params, allow_failure );
         }
      };

      my_impl->chain_plug->get_read_write_api().push_transaction_v2( fc::variant_object(mvo(packed_transaction( params->at(index) ))), next );
   }

   void push_transactions( const std::vector<signed_transaction>& params, bool allow_failure ){
      try {
         EOS_ASSERT( params.size() <= 1000, too_many_tx_at_once, "Attempt to push too many transactions at once" );
         auto params_copy = std::make_shared<std::vector<signed_transaction>>(params.begin(), params.end());
         push_recurse( 0, params_copy, allow_failure );
      } FC_LOG_AND_DROP()
   }

   optional<signed_transaction> generate_signed_transaction_from_action( action actn ){
      if ( my_impl->relay_private_key == chain::private_key_type() ){
         elog("ibc relay private key not found, can not execute action");
         return optional<signed_transaction>();
      }
      signed_transaction trx;
      trx.actions.emplace_back( actn );
      set_transaction_headers( trx );
      trx.sign( my_impl->relay_private_key, my_impl->chain_plug->chain().get_chain_id() );
      return trx;
   }
   
   void push_action( action actn ) {
      auto trx_opt = generate_signed_transaction_from_action( actn );
      if ( trx_opt.valid() ){
         push_transaction_base( *trx_opt );
      } else {
         elog("push_action failed, for generate_signed_transaction_from_action failed");
      }
   }

   
   // --------------- ibc_chain_contract ---------------
   class ibc_chain_contract {
   public:
      ibc_chain_contract( name contract ):account(contract){}

      contract_state                      state = none;
      uint32_t                            lwc_lib_depth = 0;
      std::vector<blockroot_merkle_type>  history_blockroot_merkles;

      // actions
      void chain_init( const lwc_init_message& msg );
      void pushsection( const lwc_section_data_message& msg );
      void blockmerkle( const blockroot_merkle_type& data );
      void rmfirstsctn();

      // tables
      optional<section_type>              get_sections_tb_reverse_nth_section( uint64_t nth = 0 ) const;
      uint32_t                            get_sections_tb_size() const;
      optional<block_header_state_type>   get_chaindb_tb_bhs_by_block_num( uint64_t num ) const;
      block_id_type                       get_chaindb_tb_block_id_by_block_num( uint64_t num ) const;
      optional<global_state_ibc_chain>    get_global_singleton() const;
      void                                get_blkrtmkls_tb() ;

      // other
      bool has_contract() const;
      bool lwc_initialized() const;
      bool lib_depth_valid() const;
      void get_contract_state();

   private:
      name account;
   };

   bool ibc_chain_contract::has_contract() const {
      return account_has_contract( account );
   }

   bool ibc_chain_contract::lwc_initialized() const {
      const auto& ret = get_sections_tb_reverse_nth_section();
      if ( ret.valid() ){
         return true;
      }
      return false;
   }
   
   void ibc_chain_contract::get_contract_state(){
      contract_state c_state = none;
      if ( has_contract() ) {
         c_state = deployed;
         auto sp = get_global_singleton();
         if ( sp.valid() ) {
            global_state_ibc_chain gstate = *sp;
            lwc_lib_depth = gstate.lib_depth;
         }
         if ( lwc_initialized() && lib_depth_valid() ){
            c_state = working;
         }
      }
      state = c_state;
   }

   bool ibc_chain_contract::lib_depth_valid() const {
      if ( lwc_lib_depth >= min_lwc_lib_depth && lwc_lib_depth <= max_lwc_lib_depth ){
         return true;
      }
      return false;
   }

   optional<section_type> ibc_chain_contract::get_sections_tb_reverse_nth_section( uint64_t nth ) const {
      auto p = get_table_nth_row_kvo_by_primary_key( account, account, N(sections), nth, true );
      if ( p.valid() ){
         auto obj = *p;
         fc::datastream<const char *> ds(obj.value.data(), obj.value.size());
         section_type result;
         fc::raw::unpack( ds, result );
         return result;
      }
      return optional<section_type>();
   }

   uint32_t ibc_chain_contract::get_sections_tb_size() const {
      chain_apis::read_only::get_table_rows_params par;
      par.json = true;  // must be true
      par.code = account;
      par.scope = account.to_string();
      par.table = N(sections);
      par.table_key = "primary_key";
      par.lower_bound = to_string(0);
      par.upper_bound = "";
      par.limit = 10;
      par.key_type = "i64";
      par.index_position = "1";

      try {
         auto result = my_impl->chain_plug->get_read_only_api().get_table_rows( par );
         return result.rows.size();
      } FC_LOG_AND_DROP()
      return 0;
   }

   optional<block_header_state_type> ibc_chain_contract::get_chaindb_tb_bhs_by_block_num( uint64_t num ) const {
      chain_apis::read_only::get_table_rows_params par;
      par.json = true;  // must be true
      par.code = account;
      par.scope = account.to_string();
      par.table = N(chaindb);
      par.table_key = "block_num";
      par.lower_bound = to_string(num);
      par.upper_bound = to_string(num + 1);
      par.limit = 1;
      par.key_type = "i64";
      par.index_position = "1";

      try {
         auto result = my_impl->chain_plug->get_read_only_api().get_table_rows( par );
         if ( result.rows.size() != 0 ){
            auto ret = result.rows[0];
            block_header_state_type bhs;
            bhs.block_num                 = ret["block_num"].as<uint64_t>();
            bhs.block_id                  = ret["block_id"].as<block_id_type>();

            bhs.header.timestamp    		= ret["header"]["timestamp"].as<block_timestamp_type>();
            bhs.header.producer    			= ret["header"]["producer"].as<account_name>();
            bhs.header.confirmed    		= ret["header"]["confirmed"].as<uint16_t>();
            bhs.header.previous    			= ret["header"]["previous"].as<block_id_type>();
            bhs.header.transaction_mroot	= ret["header"]["transaction_mroot"].as<checksum256_type>();
            bhs.header.action_mroot    	= ret["header"]["action_mroot"].as<checksum256_type>();
            bhs.header.schedule_version   = ret["header"]["schedule_version"].as<uint32_t>();
            bhs.header.new_producers    	= ret["header"]["new_producers"].as<optional<producer_schedule_type>>();
            /*bhs.header.header_extensions  = ret["header"]["header_extensions"].as<extensions_type>();*/ // a bug here
            bhs.header.producer_signature = ret["header"]["producer_signature"].as<signature_type>();

            bhs.active_schedule_id  = ret["active_schedule_id"].as<uint32_t>();
            bhs.pending_schedule_id = ret["pending_schedule_id"].as<uint32_t>();
            bhs.blockroot_merkle    = ret["blockroot_merkle"].as<incremental_merkle>();
            bhs.block_signing_key   = ret["block_signing_key"].as<public_key_type>();
            return bhs;
         }
      } FC_LOG_AND_DROP()
      return optional<block_header_state_type>();
   }

   block_id_type ibc_chain_contract::get_chaindb_tb_block_id_by_block_num( uint64_t num ) const {
      auto p = get_chaindb_tb_bhs_by_block_num( num );
      if ( p.valid() ){
         return p->block_id;
      }
      return block_id_type();
   }

   optional<global_state_ibc_chain> ibc_chain_contract::get_global_singleton() const {
      auto p = get_singleton_kvo( account, account, N(global) );
      if ( p.valid() ){
         auto obj = *p;
         fc::datastream<const char *> ds(obj.value.data(), obj.value.size());
         global_state_ibc_chain result;
         fc::raw::unpack( ds, result );
         return result;
      }
      return optional<global_state_ibc_chain>();
   }

   void ibc_chain_contract::get_blkrtmkls_tb() {
      const auto& d = app().get_plugin<chain_plugin>().chain().db();
      const auto* t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple(account, my_impl->relay, N(blkrtmkls)));
      if (t_id != nullptr) {
         const auto &idx = d.get_index<chain::key_value_index, chain::by_scope_primary>();
         decltype(t_id->id) next_tid(t_id->id._id + 1);
         auto lower = idx.lower_bound(boost::make_tuple(t_id->id));
         auto upper = idx.lower_bound(boost::make_tuple(next_tid));

         for (auto itr = lower; itr != upper; ++itr) {
            const key_value_object &obj = *itr;
            fc::datastream<const char *> ds(obj.value.data(), obj.value.size());
            blockroot_merkle_type result;
            fc::raw::unpack( ds, result );
            history_blockroot_merkles.push_back( result );
         }
      }
   }

   void ibc_chain_contract::chain_init( const lwc_init_message &msg ){
      auto actn = get_action( account, N(chaininit), vector<permission_level>{{ my_impl->relay, config::active_name}}, mvo()
            ("header",            fc::raw::pack(msg.header))
            ("active_schedule",   msg.active_schedule)
            ("blockroot_merkle",  msg.blockroot_merkle));

      if ( ! actn.valid() ){
         elog("chain_init: get action failed");
         return;
      }
      push_action( *actn );
   }

   void ibc_chain_contract::pushsection( const lwc_section_data_message& msg ){
      auto actn = get_action( account, N(pushsection), vector<permission_level>{{ my_impl->relay, config::active_name}}, mvo()
            ("headers",           fc::raw::pack(msg.headers))
            ("blockroot_merkle",  msg.blockroot_merkle)
            ("relay",             my_impl->relay));

      if ( ! actn.valid() ){
         elog("newsection: get action failed");
         return;
      }
      push_action( *actn );
   }

   void ibc_chain_contract::blockmerkle( const blockroot_merkle_type& data ){
      auto actn = get_action( account, N(blockmerkle), vector<permission_level>{{ my_impl->relay, config::active_name}}, mvo()
            ("block_num",         data.block_num)
            ("merkle",            data.merkle)
            ("relay",             my_impl->relay));

      if ( ! actn.valid() ){
         elog("newsection: get action failed");
         return;
      }
      push_action( *actn );
   }

   void ibc_chain_contract::rmfirstsctn(){
      auto actn = get_action( account, N(rmfirstsctn), vector<permission_level>{{ my_impl->relay, config::active_name}}, mvo()
         ("relay",             my_impl->relay));

      if ( ! actn.valid() ){
         elog("newsection: get action failed");
         return;
      }
      push_action( *actn );
   }

   // --------------- ibc_token_contract ---------------
   class ibc_token_contract {
   public:
      ibc_token_contract( name contract ):account(contract){}
      contract_state state = none;

      // actions
      void cash( const cash_action_params& p );
      void cashconfirm( const cashconfirm_action_params& p );

      // tables
      range_type                          get_table_origtrxs_id_range( bool raw = false );
      optional<original_trx_info>         get_table_origtrxs_trx_info_by_id( uint64_t id );
      range_type                          get_table_cashtrxs_seq_num_range( bool raw = false );
      optional<cash_trx_info>             get_table_cashtrxs_trx_info_by_seq_num( uint64_t seq_num );
      optional<global_state_ibc_token>    get_global_state_singleton();
      optional<global_mutable_ibc_token>  get_global_mutable_singleton();

      // other
      optional<transaction>            get_transaction( std::vector<char> packed_trx_receipt );
      optional<transfer_action_type>   get_original_action_params( std::vector<char> packed_trx_receipt, transaction_id_type* trx_id_ptr = nullptr );
      optional<cash_action_params>     get_cash_action_params( std::vector<char> packed_trx_receipt );

      transaction_id_type last_origtrx_pushed;  // note: update this even push failed

      // recurse actions
      void push_cash_recurse( int index, const std::shared_ptr<std::vector<cash_action_params>>& params, uint32_t start_seq_num );
      void push_cash_trxs( const std::vector<ibc_trx_rich_info>& params, uint32_t start_seq_num );

      void push_cashconfirm_recurse( int index, const std::shared_ptr<std::vector<cashconfirm_action_params>>& params );
      void push_cashconfirm_trxs( const std::vector<ibc_trx_rich_info>& params, uint64_t start_seq_num );

      void push_rborrm_recurse( int index, const std::shared_ptr<std::vector<transaction_id_type>>& params, name action_name);
      void rollback( const std::vector<transaction_id_type> trxs );
      void rmunablerb( const std::vector<transaction_id_type> trxs );

      optional<memo_info_type> get_memo_info( const string& memo );

      bool has_contract();
      void get_contract_state();

   private:
      name account;
   };

   optional<memo_info_type> ibc_token_contract::get_memo_info( const string& memo_str ){

      memo_info_type info;

      string memo = trim( memo_str );

      // --- get receiver ---
      auto pos = memo.find("@");
      if ( pos == std::string::npos ){
         elog("memo format error, didn't find charactor \'@\' in memo");
         return optional<memo_info_type>();
      }

      string receiver_str = memo.substr( 0, pos );
      receiver_str = trim( receiver_str );
      info.receiver = name( receiver_str );

      // --- trim ---
      memo = memo.substr( pos + 1 );
      memo = trim( memo );

      // --- get chain name and notes ---
      pos = memo.find(" ");
      if ( pos == std::string::npos ){
         info.chain = name( memo );
         info.notes = "";
      } else {
         info.chain = name( memo.substr(0,pos) );
         info.notes = memo.substr( pos + 1 );
         info.notes = trim( info.notes );
      }

      if ( info.receiver == name() ){
         elog("memo format error, receiver not provided in memo");
         return optional<memo_info_type>();
      }

      if ( info.chain == name() ){
         elog("memo format error, chain not provided in memo");
         return optional<memo_info_type>();
      }

      return info;
   }

   bool ibc_token_contract::has_contract(){
      return account_has_contract( account );
   }

   void ibc_token_contract::get_contract_state(){
      contract_state c_state = none;
      if ( has_contract() ) {
         c_state = deployed;
         auto p = get_global_state_singleton();
         if ( p.valid() ){
            const auto& obj = *p;
            if ( obj.ibc_contract != name() && obj.active ){
               c_state = working;
            }
         } else {
            dlog("get token contract global_state_singleton failed");
         }
      }
      state = c_state;
   }

   range_type ibc_token_contract::get_table_origtrxs_id_range( bool raw ) {
      auto range = get_table_primary_key_range( account, account, N(origtrxs) );
      if ( raw ){
         return range;
      }
      uint64_t safe_tslot = my_impl->get_safe_head_tslot() + DiffOfTrxBeforeMinDepth;

      chain_apis::read_only::get_table_rows_params par;
      par.json = true;  // must be true
      par.code = account;
      par.scope = account.to_string();
      par.table = N(origtrxs);
      par.table_key = "tslot";
      par.lower_bound = to_string(safe_tslot);
      par.upper_bound = "";   // to last
      par.limit = 1;
      par.key_type = "i64";
      par.index_position = "2";  // by_slot
      try {
         auto result = my_impl->chain_plug->get_read_only_api().get_table_rows( par );
         if ( result.rows.size() != 0 ){
            auto info = result.rows.front().as<original_trx_info>();
            range.second = info.id - 1;
            if ( range.second < range.first ){
               return range_type();
            }
         }
      } FC_LOG_AND_DROP()

      return range;
   }

   optional<original_trx_info> ibc_token_contract::get_table_origtrxs_trx_info_by_id( uint64_t id ) {
      chain_apis::read_only::get_table_rows_params par;
      par.json = true;  // must be true
      par.code = account;
      par.scope = account.to_string();
      par.table = N(origtrxs);
      par.table_key = "id";
      par.lower_bound = to_string(id);
      par.upper_bound = to_string(id + 1);
      par.limit = 1;
      par.key_type = "i64";
      par.index_position = "1";

      try {
         auto result = my_impl->chain_plug->get_read_only_api().get_table_rows( par );
         if ( result.rows.size() != 0 ){
            return result.rows.front().as<original_trx_info>();
         }
      } FC_LOG_AND_DROP()
      return optional<original_trx_info>();
   }

   range_type ibc_token_contract::get_table_cashtrxs_seq_num_range( bool raw ) {
      auto range = get_table_primary_key_range( account, account, N(cashtrxs) );
      if ( raw ){
         return range;
      }
      uint64_t safe_tslot = my_impl->get_safe_head_tslot() + DiffOfTrxBeforeMinDepth;

      chain_apis::read_only::get_table_rows_params par;
      par.json = true;  // must be true
      par.code = account;
      par.scope = account.to_string();
      par.table = N(cashtrxs);
      par.table_key = "tslot";
      par.lower_bound = to_string(safe_tslot);
      par.upper_bound = "";   // to last
      par.limit = 1;
      par.key_type = "i64";
      par.index_position = "2";  // by_slot
      try {
         auto result = my_impl->chain_plug->get_read_only_api().get_table_rows( par );
         if ( result.rows.size() != 0 ){
            auto info = result.rows.front().as<cash_trx_info>();
            range.second = info.seq_num - 1;
            if ( range.second < range.first ){
               return range_type();
            }
         }
      } FC_LOG_AND_DROP()

      return range;
   }

   optional<cash_trx_info> ibc_token_contract::get_table_cashtrxs_trx_info_by_seq_num( uint64_t seq_num ) {
      chain_apis::read_only::get_table_rows_params par;
      par.json = true;  // must be true
      par.code = account;
      par.scope = account.to_string();
      par.table = N(cashtrxs);
      par.table_key = "seq_num";
      par.lower_bound = to_string(seq_num);
      par.upper_bound = to_string(seq_num + 1);
      par.limit = 1;
      par.key_type = "i64";
      par.index_position = "1";

      try {
         auto result = my_impl->chain_plug->get_read_only_api().get_table_rows( par );
         if ( result.rows.size() != 0 ){
            return result.rows.front().as<cash_trx_info>();
         }
      } FC_LOG_AND_DROP()
      return optional<cash_trx_info>();
   }

   // singletons
   optional<global_state_ibc_token> ibc_token_contract::get_global_state_singleton() {
      auto p = get_singleton_kvo( account, account, N(globals) );
      if ( p.valid() ){
         auto obj = *p;
         fc::datastream<const char *> ds(obj.value.data(), obj.value.size());
         global_state_ibc_token result;
         try {
            fc::raw::unpack( ds, result );
            return result;
         } FC_LOG_AND_DROP()
      }
      return optional<global_state_ibc_token>();
   }

   optional<global_mutable_ibc_token> ibc_token_contract::get_global_mutable_singleton() {
      auto p = get_singleton_kvo( account, account, N(globalm) );
      if ( p.valid() ){
         auto obj = *p;
         fc::datastream<const char *> ds(obj.value.data(), obj.value.size());
         global_mutable_ibc_token result;
         try {
            fc::raw::unpack( ds, result );
            return result;
         } FC_LOG_AND_DROP()
      }
      return optional<global_mutable_ibc_token>();
   }

   optional<transaction> ibc_token_contract::get_transaction( std::vector<char> packed_trx_receipt ){
      try {
         transaction_receipt trx_rcpt  = fc::raw::unpack<transaction_receipt>( packed_trx_receipt );
         packed_transaction pkd_trx    = trx_rcpt.trx.get<packed_transaction>();
         return fc::raw::unpack<transaction>( pkd_trx.packed_trx );
      } FC_LOG_AND_DROP()
      return optional<transaction>();
   }
   
   optional<transfer_action_type> ibc_token_contract::get_original_action_params( std::vector<char> packed_trx_receipt, transaction_id_type* trx_id_ptr ){
      try {
         auto trx_opt = get_transaction( packed_trx_receipt );
         if ( trx_opt.valid() ){
            if ( trx_id_ptr != nullptr ){
               *trx_id_ptr = trx_opt->id();
            }
            return fc::raw::unpack<transfer_action_type>( trx_opt->actions.front().data );
         }
      } FC_LOG_AND_DROP()
      return optional<transfer_action_type>();
   }

   optional<cash_action_params> ibc_token_contract::get_cash_action_params( std::vector<char> packed_trx_receipt ){
      try {
         auto trx_opt = get_transaction( packed_trx_receipt );
         if ( trx_opt.valid() ){
            return fc::raw::unpack<cash_action_params>( trx_opt->actions.front().data );
         }
      } FC_LOG_AND_DROP()
      return optional<cash_action_params>();
   }

   void ibc_token_contract::push_cash_recurse( int index, const std::shared_ptr<std::vector<cash_action_params>>& params, uint32_t start_seq_num  ){
      auto next = [=](const fc::static_variant<fc::exception_ptr, chain_apis::read_write::push_transaction_results>& result) {
         uint32_t next_seq_num = start_seq_num;
         if (result.contains<fc::exception_ptr>()) {
            try {
               result.get<fc::exception_ptr>()->dynamic_rethrow_exception();
            } FC_LOG_AND_DROP()
            elog("push cash transaction failed, orig_trx_id ${id}, index ${i}",("id", params->at(index).orig_trx_id)("i",index));
         } else {
            auto trx_id = result.get<chain_apis::read_write::push_transaction_results>().transaction_id;
            dlog("pushed cash transaction: ${id}, index ${idx}", ( "id", trx_id )("idx", index));
            next_seq_num += 1;
         }

         last_origtrx_pushed = params->at(index).orig_trx_id; // used to push failed cash transactions a certain number of times
         int next_index = index + 1;
         if (next_index < params->size()) {
            push_cash_recurse( next_index, params, next_seq_num );
         } else {
            dlog("all ${sum} cash transactions have tried to push, which belongs to blocks [${f},${t}]",
                 ("sum",params->size())("f",params->front().orig_trx_block_num)("t",params->back().orig_trx_block_num));
         }
      };

      auto par = params->at(index);
      auto actn = get_action( account, N(cash), vector<permission_level>{{ my_impl->relay, config::active_name}}, mvo()
               ("seq_num",                      start_seq_num)
               ("orig_trx_block_num",           par.orig_trx_block_num)
               ("orig_trx_packed_trx_receipt",  par.orig_trx_packed_trx_receipt)
               ("orig_trx_merkle_path",         par.orig_trx_merkle_path)
               ("orig_trx_id",                  par.orig_trx_id)
               ("to",                           par.to)
               ("quantity",                     par.quantity)
               ("memo",                         par.memo)
               ("relay",                        my_impl->relay ));

      if ( ! actn.valid() ){
         elog("get cash action failed");
         return;
      }

      auto trx_opt = generate_signed_transaction_from_action( *actn );
      if ( ! trx_opt.valid() ){
         elog("generate_signed_transaction_from_action failed");
         return;
      }
      my_impl->chain_plug->get_read_write_api().push_transaction_v2( fc::variant_object(mvo(packed_transaction(*trx_opt))), next );
   }

   void ibc_token_contract::push_cash_trxs( const std::vector<ibc_trx_rich_info>& params, uint32_t start_seq_num ){
      std::vector<cash_action_params> actions;
      for ( const auto& trx : params ){
         cash_action_params par;
         par.seq_num = 0;
         par.orig_trx_block_num = trx.block_num;
         par.orig_trx_packed_trx_receipt = trx.packed_trx_receipt;
         par.orig_trx_merkle_path = trx.merkle_path;
         par.orig_trx_id = trx.trx_id;
         auto opt = get_original_action_params( trx.packed_trx_receipt );
         if ( opt.valid() ){
            transfer_action_type actn = *opt;

            auto info = get_memo_info( actn.memo );
            if ( ! info.valid() ){
               break;
            }

            par.to = info->receiver;
            par.quantity = actn.quantity;
            par.memo = "memo";
            par.relay = my_impl->relay;
            actions.push_back(par);
         } else {
            elog("internal error, failed to get transfer action infomation from packed_trx_receipt");
            break;
         }
      }

      if ( actions.empty() ){
         return;
      }

      try {
         EOS_ASSERT( actions.size() <= 1000, too_many_tx_at_once, "Attempt to push too many transactions at once" );
         auto params_copy = std::make_shared<std::vector<cash_action_params>>(actions.begin(), actions.end());
         push_cash_recurse( 0, params_copy, start_seq_num );
      } FC_LOG_AND_DROP()
   }


   void ibc_token_contract::push_cashconfirm_recurse( int index, const std::shared_ptr<std::vector<cashconfirm_action_params>>& params ){
      auto next = [=](const fc::static_variant<fc::exception_ptr, chain_apis::read_write::push_transaction_results>& result) {
         if (result.contains<fc::exception_ptr>()) {
            try {
               result.get<fc::exception_ptr>()->dynamic_rethrow_exception();
            } FC_LOG_AND_DROP()
            elog("push cashconfirm transaction failed, cash_trx_id: ${id}, ${s} succeed, ${l} left",("id",params->at(index).cash_trx_id)("s",index)("l",params->size() - index));
            return;
         } else {
            auto trx_id = result.get<chain_apis::read_write::push_transaction_results>().transaction_id;
            dlog("pushed cashconfirm transaction: ${id}, index ${idx}", ( "id", trx_id )("idx", index));
         }

         int next_index = index + 1;
         if (next_index < params->size()) {
            push_cashconfirm_recurse( next_index, params );
         } else {
            dlog("successfully pushed all ${sum} cashconfirm transactions, which belongs to blocks [${f},${t}]",
               ("sum",params->size())("f",params->front().cash_trx_block_num)("t",params->back().cash_trx_block_num));
         }
      };

      auto par = params->at(index);
      auto actn = get_action( account, N(cashconfirm), vector<permission_level>{{ my_impl->relay, config::active_name}}, mvo()
         ("cash_trx_block_num",           par.cash_trx_block_num)
         ("cash_trx_packed_trx_receipt",  par.cash_trx_packed_trx_receipt)
         ("cash_trx_merkle_path",         par.cash_trx_merkle_path)
         ("cash_trx_id",                  par.cash_trx_id)
         ("orig_trx_id",                  par.orig_trx_id));

      if ( ! actn.valid() ){
         elog("get cashconfirm action failed");
         return;
      }

      auto trx_opt = generate_signed_transaction_from_action( *actn );
      if ( ! trx_opt.valid() ){
         elog("generate_signed_transaction_from_action failed");
         return;
      }
      my_impl->chain_plug->get_read_write_api().push_transaction_v2( fc::variant_object(mvo(packed_transaction(*trx_opt))), next );
   }

   void ibc_token_contract::push_cashconfirm_trxs( const std::vector<ibc_trx_rich_info>& params, uint64_t start_seq_num ) {
      std::vector<cashconfirm_action_params> actions;
      uint64_t next_seq_num = start_seq_num;
      for ( const auto& trx : params ){
         auto opt_cash = get_cash_action_params( trx.packed_trx_receipt );
         if ( ! opt_cash.valid() ){
            elog("failed to get cash action parameters from packed_trx_receipt");
            return;
         }
         cash_action_params cash_params = *opt_cash;

         transaction_id_type orig_trx_id;
         auto opt_orig = get_original_action_params( cash_params.orig_trx_packed_trx_receipt, &orig_trx_id );
         if ( ! opt_orig.valid() ){
            elog("failed to get original action parameters from orig_trx_packed_trx_receipt");
            return;
         }
         transfer_action_type orig_params = *opt_orig;

         if ( cash_params.seq_num != next_seq_num ){
            elog("cash_params.seq_num ${n1} != next_seq_num ${n2}", ("n1",cash_params.seq_num)("n2",next_seq_num));
            return;
         }

         cashconfirm_action_params par;
         par.cash_trx_block_num = trx.block_num;
         par.cash_trx_packed_trx_receipt = trx.packed_trx_receipt;
         par.cash_trx_merkle_path = trx.merkle_path;
         par.cash_trx_id = trx.trx_id;
         par.orig_trx_id = orig_trx_id;
         actions.push_back( par );

         next_seq_num += 1;
      }

      if ( actions.empty() ){
         return;
      }

      try {
         EOS_ASSERT( actions.size() <= 1000, too_many_tx_at_once, "Attempt to push too many transactions at once" );
         auto params_copy = std::make_shared<std::vector<cashconfirm_action_params>>(actions.begin(), actions.end());
         push_cashconfirm_recurse( 0, params_copy );
      } FC_LOG_AND_DROP()
   }

   void ibc_token_contract::cash( const cash_action_params& p ){
      auto actn = get_action( account, N(cash), vector<permission_level>{{ my_impl->relay, config::active_name}}, mvo()
         ("seq_num",                      p.seq_num)
         ("orig_trx_block_num",           p.orig_trx_block_num)
         ("orig_trx_packed_trx_receipt",  p.orig_trx_packed_trx_receipt)
         ("orig_trx_merkle_path",         p.orig_trx_merkle_path)
         ("orig_trx_id",                  p.orig_trx_id)
         ("to",                           p.to)
         ("quantity",                     p.quantity)
         ("memo",                         p.memo)
         ("relay",                        p.relay));

      if ( ! actn.valid() ){
         elog("cash: get action failed");
         return;
      }
      push_action( *actn );
   }

   void ibc_token_contract::cashconfirm( const cashconfirm_action_params& p ){
      auto actn = get_action( account, N(cashconfirm), vector<permission_level>{{ my_impl->relay, config::active_name}}, mvo()
         ("cash_trx_block_num",          p.cash_trx_block_num)
         ("cash_trx_packed_trx_receipt", p.cash_trx_packed_trx_receipt)
         ("cash_trx_merkle_path",        p.cash_trx_merkle_path)
         ("cash_trx_id",                 p.cash_trx_id)
         ("orig_trx_id",                 p.orig_trx_id));

      if ( ! actn.valid() ){
         elog("cash: get action failed");
         return;
      }
      push_action( *actn );
   }

   void ibc_token_contract::push_rborrm_recurse( int index, const std::shared_ptr<std::vector<transaction_id_type>>& params, name action_name){
      auto next = [=](const fc::static_variant<fc::exception_ptr, chain_apis::read_write::push_transaction_results>& result) {
         if (result.contains<fc::exception_ptr>()) {
            try {
               result.get<fc::exception_ptr>()->dynamic_rethrow_exception();
            } FC_LOG_AND_DROP()
            elog("push rollback transaction failed, index ${idx}", ("idx", index));
         } else {
            auto trx_id = result.get<chain_apis::read_write::push_transaction_results>().transaction_id;
            dlog("pushed rollback transaction: ${id}, index ${idx}", ( "id", trx_id )("idx", index));
         }

         int next_index = index + 1;
         if (next_index < params->size()) {
            push_rborrm_recurse( next_index, params, action_name );
         }
      };

      auto trx_id = params->at(index);
      auto actn = get_action( account, action_name, vector<permission_level>{{ my_impl->relay, config::active_name}}, mvo()
         ("trx_id",         trx_id)
         ("relay",          my_impl->relay));

      if ( ! actn.valid() ){
         elog("newsection: get action failed");
         return;
      }

      auto trx_opt = generate_signed_transaction_from_action( *actn );
      if ( ! trx_opt.valid() ){
         elog("generate_signed_transaction_from_action failed");
         return;
      }
      my_impl->chain_plug->get_read_write_api().push_transaction_v2( fc::variant_object(mvo(packed_transaction(*trx_opt))), next );
   }

   void ibc_token_contract::rollback( const std::vector<transaction_id_type> trxs ){
      if ( trxs.empty() ){
         return;
      }

      try {
         EOS_ASSERT( trxs.size() <= 1000, too_many_tx_at_once, "Attempt to push too many transactions at once" );
         auto params_copy = std::make_shared<std::vector<transaction_id_type>>(trxs.begin(), trxs.end());
         push_rborrm_recurse( 0, params_copy, N(rollback) );
      } FC_LOG_AND_DROP()
   }

   void ibc_token_contract::rmunablerb( const std::vector<transaction_id_type> trxs ){
      if ( trxs.empty() ){
         return;
      }

      try {
         EOS_ASSERT( trxs.size() <= 1000, too_many_tx_at_once, "Attempt to push too many transactions at once" );
         auto params_copy = std::make_shared<std::vector<transaction_id_type>>(trxs.begin(), trxs.end());
         push_rborrm_recurse( 0, params_copy, N(rmunablerb) );
      } FC_LOG_AND_DROP()
   }

   // --------------- connection ---------------
   connection::connection(string endpoint)
      : socket(std::make_shared<tcp::socket>(std::ref(app().get_io_service()))),
        node_id(),
        last_handshake_recv(),
        last_handshake_sent(),
        sent_handshake_count(0),
        connecting(false),
        protocol_version(0),
        peer_addr(endpoint),
        response_expected(),
        no_retry(no_reason)
   {
      wlog("created connection to ${n}", ("n", endpoint));
      initialize();
   }

   connection::connection( socket_ptr s )
      : socket( s ),
        node_id(),
        last_handshake_recv(),
        last_handshake_sent(),
        sent_handshake_count(0),
        connecting(true),
        protocol_version(0),
        peer_addr(),
        response_expected(),
        no_retry(no_reason)
   {
      wlog( "accepted network connection" );
      initialize();
   }

   connection::~connection() {}


   void connection::initialize() {
      auto *rnd = node_id.data();
      rnd[0] = 0;
      response_expected.reset(new boost::asio::steady_timer(app().get_io_service()));
   }

   bool connection::connected() {
      return (socket && socket->is_open() && !connecting);
   }

   bool connection::current() {
      return connected();
   }

   void connection::flush_queues() {
      write_queue.clear();
   }

   void connection::close() {
      if(socket) {
         socket->close();
      }
      else {
         wlog("no socket to close!");
      }
      flush_queues();
      connecting = false;

      reset();
      sent_handshake_count = 0;
      last_handshake_recv = handshake_message();
      last_handshake_sent = handshake_message();
      fc_dlog(logger, "canceling wait on ${p}", ("p",peer_name()));
      cancel_wait();
      pending_message_buffer.reset();
   }

   void connection::send_handshake( ) {
      handshake_initializer::populate(last_handshake_sent);
      last_handshake_sent.generation = ++sent_handshake_count;
      fc_dlog(logger, "Sending handshake generation ${g} to ${ep}",
              ("g",last_handshake_sent.generation)("ep", peer_name()));
      enqueue(last_handshake_sent);
   }

   char* connection::convert_tstamp(const tstamp& t)
   {
      const long long NsecPerSec{1000000000};
      time_t seconds = t / NsecPerSec;
      strftime(ts, ts_buffer_size, "%F %T", localtime(&seconds));
      snprintf(ts+19, ts_buffer_size-19, ".%lld", t % NsecPerSec);
      return ts;
   }

   void connection::send_time() {
      time_message xpkt;
      xpkt.org = rec;
      xpkt.rec = dst;
      xpkt.xmt = get_time();
      org = xpkt.xmt;
      enqueue(xpkt);
   }

   void connection::send_time(const time_message& msg) {
      time_message xpkt;
      xpkt.org = msg.xmt;
      xpkt.rec = msg.dst;
      xpkt.xmt = get_time();
      enqueue(xpkt);
   }

   void connection::queue_write(std::shared_ptr<vector<char>> buff,
                                bool trigger_send,
                                std::function<void(boost::system::error_code, std::size_t)> callback) {
      write_queue.push_back({buff, callback});
      if(out_queue.empty() && trigger_send)
         do_queue_write();
   }

   void connection::do_queue_write() {
      if(write_queue.empty() || !out_queue.empty())
         return;
      connection_wptr c(shared_from_this());
      if(!socket->is_open()) {
         fc_elog(logger,"socket not open to ${p}",("p",peer_name()));
         my_impl->close(c.lock());
         return;
      }
      std::vector<boost::asio::const_buffer> bufs;
      while (write_queue.size() > 0) {
         auto& m = write_queue.front();
         bufs.push_back(boost::asio::buffer(*m.buff));
         out_queue.push_back(m);
         write_queue.pop_front();
      }
      boost::asio::async_write(*socket, bufs, [c](boost::system::error_code ec, std::size_t w) {
         try {
            auto conn = c.lock();
            if(!conn)
               return;

            for (auto& m: conn->out_queue) {
               m.callback(ec, w);
            }

            if(ec) {
               string pname = conn ? conn->peer_name() : "no connection name";
               if( ec.value() != boost::asio::error::eof) {
                  elog("Error sending to peer ${p}: ${i}", ("p",pname)("i", ec.message()));
               }
               else {
                  ilog("connection closure detected on write to ${p}",("p",pname));
               }
               my_impl->close(conn);
               return;
            }
            while (conn->out_queue.size() > 0) {
               conn->out_queue.pop_front();
            }
            conn->do_queue_write();
         }
         catch(const std::exception &ex) {
            auto conn = c.lock();
            string pname = conn ? conn->peer_name() : "no connection name";
            elog("Exception in do_queue_write to ${p} ${s}", ("p",pname)("s",ex.what()));
         }
         catch(const fc::exception &ex) {
            auto conn = c.lock();
            string pname = conn ? conn->peer_name() : "no connection name";
            elog("Exception in do_queue_write to ${p} ${s}", ("p",pname)("s",ex.to_string()));
         }
         catch(...) {
            auto conn = c.lock();
            string pname = conn ? conn->peer_name() : "no connection name";
            elog("Exception in do_queue_write to ${p}", ("p",pname) );
         }
      });
   }

   void connection::enqueue( const ibc_message &m, bool trigger_send ) {
      go_away_reason close_after_send = no_reason;
      if (m.contains<go_away_message>()) {
         close_after_send = m.get<go_away_message>().reason;
      }

      uint32_t payload_size = fc::raw::pack_size( m );
      char * header = reinterpret_cast<char*>(&payload_size);
      size_t header_size = sizeof(payload_size);

      size_t buffer_size = header_size + payload_size;

      auto send_buffer = std::make_shared<vector<char>>(buffer_size);
      fc::datastream<char*> ds( send_buffer->data(), buffer_size);
      ds.write( header, header_size );
      fc::raw::pack( ds, m );
      connection_wptr weak_this = shared_from_this();
      queue_write(send_buffer,trigger_send,
                  [weak_this, close_after_send](boost::system::error_code ec, std::size_t ) {
                     connection_ptr conn = weak_this.lock();
                     if (conn) {
                        if (close_after_send != no_reason) {
                           elog ("sent a go away message: ${r}, closing connection to ${p}",("r", reason_str(close_after_send))("p", conn->peer_name()));
                           my_impl->close(conn);
                           return;
                        }
                     } else {
                        fc_wlog(logger, "connection expired before enqueued ibc_message called callback!");
                     }
                  });
   }

   void connection::cancel_wait() {
      if (response_expected)
         response_expected->cancel();
   }

   const string connection::peer_name() {
      if( !last_handshake_recv.p2p_address.empty() ) {
         return last_handshake_recv.p2p_address;
      }
      if( !peer_addr.empty() ) {
         return peer_addr;
      }
      return "connecting client";
   }

   bool connection::process_next_message(ibc_plugin_impl& impl, uint32_t message_length) {
      try {
         auto index = pending_message_buffer.read_index();
         uint64_t which = 0; char b = 0; uint8_t by = 0;
         do {
            pending_message_buffer.peek(&b, 1, index);
            which |= uint32_t(uint8_t(b) & 0x7f) << by;
            by += 7;
         } while( uint8_t(b) & 0x80 && by < 32);

         auto ds = pending_message_buffer.create_datastream();
         ibc_message msg;
         fc::raw::unpack(ds, msg);
         msgHandler m(impl, shared_from_this() );
         msg.visit(m);
      } catch(  const fc::exception& e ) {
         edump((e.to_detail_string() ));
         impl.close( shared_from_this() );
         return false;
      }
      return true;
   }


   // --------------- ibc_plugin_impl ---------------
   void ibc_plugin_impl::connect( connection_ptr c ) {
      if( c->no_retry != go_away_reason::no_reason) {
         fc_dlog( logger, "Skipping connect due to go_away reason ${r}",("r", reason_str( c->no_retry )));
         return;
      }

      auto colon = c->peer_addr.find(':');

      if (colon == std::string::npos || colon == 0) {
         elog ("Invalid peer address. must be \"host:port\": ${p}", ("p",c->peer_addr));
         for ( auto itr : connections ) {
            if((*itr).peer_addr == c->peer_addr) {
               (*itr).reset();
               close(itr);
               connections.erase(itr);
               break;
            }
         }
         return;
      }

      auto host = c->peer_addr.substr( 0, colon );
      auto port = c->peer_addr.substr( colon + 1);
      idump((host)(port));
      tcp::resolver::query query( tcp::v4(), host.c_str(), port.c_str() );
      connection_wptr weak_conn = c;
      // Note: need to add support for IPv6 too

      resolver->async_resolve( query,
                               [weak_conn, this]( const boost::system::error_code& err,
                                                  tcp::resolver::iterator endpoint_itr ){
                                  auto c = weak_conn.lock();
                                  if (!c) return;
                                  if( !err ) {
                                     connect( c, endpoint_itr );
                                  } else {
                                     elog( "Unable to resolve ${peer_addr}: ${error}",
                                           (  "peer_addr", c->peer_name() )("error", err.message() ) );
                                  }
                               });
   }

   void ibc_plugin_impl::connect( connection_ptr c, tcp::resolver::iterator endpoint_itr ) {
      if( c->no_retry != go_away_reason::no_reason) {
         string rsn = reason_str(c->no_retry);
         return;
      }
      auto current_endpoint = *endpoint_itr;
      ++endpoint_itr;
      c->connecting = true;
      connection_wptr weak_conn = c;
      c->socket->async_connect( current_endpoint, [weak_conn, endpoint_itr, this] ( const boost::system::error_code& err ) {
         auto c = weak_conn.lock();
         if (!c) return;
         if( !err && c->socket->is_open() ) {
            if (start_session( c )) {
               c->send_handshake ();
            }
         } else {
            if( endpoint_itr != tcp::resolver::iterator() ) {
               close(c);
               connect( c, endpoint_itr );
            }
            else {
               elog( "connection failed to ${peer}: ${error}",
                     ( "peer", c->peer_name())("error",err.message()));
               c->connecting = false;
               my_impl->close(c);
            }
         }
      } );
   }

   bool ibc_plugin_impl::start_session( connection_ptr con ) {
      boost::asio::ip::tcp::no_delay nodelay( true );
      boost::system::error_code ec;
      con->socket->set_option( nodelay, ec );
      if (ec) {
         elog( "connection failed to ${peer}: ${error}",
               ( "peer", con->peer_name())("error",ec.message()));
         con->connecting = false;
         close(con);
         return false;
      }
      else {
         start_read_message( con );
         ++started_sessions;
         return true;
      }
   }

   void ibc_plugin_impl::start_listen_loop( ) {
      auto socket = std::make_shared<tcp::socket>( std::ref( app().get_io_service() ) );
      acceptor->async_accept( *socket, [socket,this]( boost::system::error_code ec ) {
         if( !ec ) {
            uint32_t visitors = 0;
            uint32_t from_addr = 0;
            auto paddr = socket->remote_endpoint(ec).address();
            if (ec) {
               fc_elog(logger,"Error getting remote endpoint: ${m}",("m", ec.message()));
            }
            else {
               for (auto &conn : connections) {
                  if(conn->socket->is_open()) {
                     if (conn->peer_addr.empty()) {
                        visitors++;
                        boost::system::error_code ec;
                        if (paddr == conn->socket->remote_endpoint(ec).address()) {
                           from_addr++;
                        }
                     }
                  }
               }
               if (num_clients != visitors) {
                  ilog ("checking max client, visitors = ${v} num clients ${n}",("v",visitors)("n",num_clients));
                  num_clients = visitors;
               }
               if( from_addr < max_nodes_per_host && (max_client_count == 0 || num_clients < max_client_count )) {
                  ++num_clients;
                  connection_ptr c = std::make_shared<connection>( socket );
                  connections.insert( c );
                  start_session( c );

               }
               else {
                  if (from_addr >= max_nodes_per_host) {
                     fc_elog(logger, "Number of connections (${n}) from ${ra} exceeds limit",
                             ("n", from_addr+1)("ra",paddr.to_string()));
                  }
                  else {
                     fc_elog(logger, "Error max_client_count ${m} exceeded",
                             ( "m", max_client_count) );
                  }
                  socket->close( );
               }
            }
         } else {
            elog( "Error accepting connection: ${m}",( "m", ec.message() ) );
            // For the listed error codes below, recall start_listen_loop()
            switch (ec.value()) {
               case ECONNABORTED:
               case EMFILE:
               case ENFILE:
               case ENOBUFS:
               case ENOMEM:
               case EPROTO:
                  break;
               default:
                  return;
            }
         }
         start_listen_loop();
      });
   }

   void ibc_plugin_impl::start_read_message( connection_ptr conn ) {
      try {
         if(!conn->socket) {
            return;
         }
         connection_wptr weak_conn = conn;

         std::size_t minimum_read = conn->outstanding_read_bytes ? *conn->outstanding_read_bytes : message_header_size;

         if (use_socket_read_watermark) {
            const size_t max_socket_read_watermark = 4096;
            std::size_t socket_read_watermark = std::min<std::size_t>(minimum_read, max_socket_read_watermark);
            boost::asio::socket_base::receive_low_watermark read_watermark_opt(socket_read_watermark);
            conn->socket->set_option(read_watermark_opt);
         }

         auto completion_handler = [minimum_read](boost::system::error_code ec, std::size_t bytes_transferred) -> std::size_t {
            if (ec || bytes_transferred >= minimum_read ) {
               return 0;
            } else {
               return minimum_read - bytes_transferred;
            }
         };

         boost::asio::async_read(*conn->socket,
                                 conn->pending_message_buffer.get_buffer_sequence_for_boost_async_read(), completion_handler,
                                 [this,weak_conn]( boost::system::error_code ec, std::size_t bytes_transferred ) {
                                    auto conn = weak_conn.lock();
                                    if (!conn) {
                                       return;
                                    }

                                    conn->outstanding_read_bytes.reset();

                                    try {
                                       if( !ec ) {
                                          if (bytes_transferred > conn->pending_message_buffer.bytes_to_write()) {
                                             elog("async_read_some callback: bytes_transfered = ${bt}, buffer.bytes_to_write = ${btw}",
                                                  ("bt",bytes_transferred)("btw",conn->pending_message_buffer.bytes_to_write()));
                                          }
                                          EOS_ASSERT(bytes_transferred <= conn->pending_message_buffer.bytes_to_write(), plugin_exception, "");
                                          conn->pending_message_buffer.advance_write_ptr(bytes_transferred);
                                          while (conn->pending_message_buffer.bytes_to_read() > 0) {
                                             uint32_t bytes_in_buffer = conn->pending_message_buffer.bytes_to_read();

                                             if (bytes_in_buffer < message_header_size) {
                                                conn->outstanding_read_bytes.emplace(message_header_size - bytes_in_buffer);
                                                break;
                                             } else {
                                                uint32_t message_length;
                                                auto index = conn->pending_message_buffer.read_index();
                                                conn->pending_message_buffer.peek(&message_length, sizeof(message_length), index);
                                                if(message_length > def_send_buffer_size*2 || message_length == 0) {
                                                   boost::system::error_code ec;
                                                   elog("incoming message length unexpected (${i}), from ${p}", ("i", message_length)("p",boost::lexical_cast<std::string>(conn->socket->remote_endpoint(ec))));
                                                   close(conn);
                                                   return;
                                                }

                                                auto total_message_bytes = message_length + message_header_size;

                                                if (bytes_in_buffer >= total_message_bytes) {
                                                   conn->pending_message_buffer.advance_read_ptr(message_header_size);
                                                   if (!conn->process_next_message(*this, message_length)) {
                                                      return;
                                                   }
                                                } else {
                                                   auto outstanding_message_bytes = total_message_bytes - bytes_in_buffer;
                                                   auto available_buffer_bytes = conn->pending_message_buffer.bytes_to_write();
                                                   if (outstanding_message_bytes > available_buffer_bytes) {
                                                      conn->pending_message_buffer.add_space( outstanding_message_bytes - available_buffer_bytes );
                                                   }

                                                   conn->outstanding_read_bytes.emplace(outstanding_message_bytes);
                                                   break;
                                                }
                                             }
                                          }
                                          start_read_message(conn);
                                       } else {
                                          auto pname = conn->peer_name();
                                          if (ec.value() != boost::asio::error::eof) {
                                             elog( "Error reading message from ${p}: ${m}",("p",pname)( "m", ec.message() ) );
                                          } else {
                                             ilog( "Peer ${p} closed connection",("p",pname) );
                                          }
                                          /* close( conn ); */
                                          conn->write_queue.clear();
                                          conn->out_queue.clear();
                                       }
                                    }
                                    catch(const std::exception &ex) {
                                       string pname = conn ? conn->peer_name() : "no connection name";
                                       elog("Exception in handling read data from ${p} ${s}",("p",pname)("s",ex.what()));
                                       close( conn );
                                    }
                                    catch(const fc::exception &ex) {
                                       string pname = conn ? conn->peer_name() : "no connection name";
                                       elog("Exception in handling read data ${s}", ("p",pname)("s",ex.to_string()));
                                       close( conn );
                                    }
                                    catch (...) {
                                       string pname = conn ? conn->peer_name() : "no connection name";
                                       elog( "Undefined exception hanlding the read data from connection ${p}",( "p",pname));
                                       close( conn );
                                    }
                                 } );
      } catch (...) {
         string pname = conn ? conn->peer_name() : "no connection name";
         elog( "Undefined exception handling reading ${p}",("p",pname) );
         close( conn );
      }
   }

   void ibc_plugin_impl::close( connection_ptr c ) {
      if( c->peer_addr.empty( ) && c->socket->is_open() ) {
         if (num_clients == 0) {
            fc_wlog( logger, "num_clients already at 0");
         }
         else {
            --num_clients;
         }
      }
      c->close();
   }

   size_t ibc_plugin_impl::count_open_sockets() const {
      size_t count = 0;
      for( auto &c : connections) {
         if(c->socket->is_open())
            ++count;
      }
      return count;
   }

   template<typename VerifierFunc>
   void ibc_plugin_impl::send_all( const ibc_message &msg, VerifierFunc verify) {
      for( auto &c : connections) {
         if( c->current() && verify( c)) {
            c->enqueue( msg );
         }
      }
   }

   void ibc_plugin_impl::send_all( const ibc_message& msg ) {
      for( auto &c : connections) {
         if( c->current() ) {
            c->enqueue( msg );
         }
      }
   }

   void ibc_plugin_impl::accepted_block_header(const block_state_ptr& block) {
      fc_dlog(logger,"signaled, block: ${n}, id: ${id}",("n", block->block_num)("id", block->id));
   }

   void ibc_plugin_impl::accepted_block(const block_state_ptr& block) {
      fc_dlog(logger,"signaled, block: ${n}, id: ${id}",("n", block->block_num)("id", block->id));
   }

   void ibc_plugin_impl::irreversible_block(const block_state_ptr& block) {
      /* fc_dlog(logger,"signaled, block: ${n}, id: ${id}",("n", block->block_num)("id", block->id)); */
      blockroot_merkle_type brtm;
      brtm.block_num = block->block_num;
      brtm.merkle = block->blockroot_merkle;

      blockroot_merkle_cache.push_back( brtm );
      if ( blockroot_merkle_cache.size() > 3600*BlocksPerSecond*24*7 ){ // one week
         blockroot_merkle_cache.erase( blockroot_merkle_cache.begin() );
      }

//      static constexpr uint32_t range = ( 1 << 10 ) * 4; // about 30 minutes
//      if ( block->block_num % range == 0 ){
//         ilog("push block ${n}'s block_merkle to chain contract",("n",block->block_num ));
//         blockroot_merkle_type par;
//         par.block_num = block->block_num;
//         par.merkle = block->blockroot_merkle;
//         chain_contract->blockmerkle( par );
//      }
   }

   void ibc_plugin_impl::accepted_confirmation(const header_confirmation& head) {
      fc_dlog(logger,"signaled, id = ${id}",("id", head.block_id));
   }

   bool ibc_plugin_impl::is_valid( const handshake_message &msg) {
      // Do some basic validation of an incoming handshake_message, so things
      // that really aren't handshake messages can be quickly discarded without
      // affecting state.
      bool valid = true;
      if (msg.last_irreversible_block_num > msg.head_num) {
         wlog("Handshake message validation: last irreversible block (${i}) is greater than head block (${h})",
              ("i", msg.last_irreversible_block_num)("h", msg.head_num));
         valid = false;
      }
      if (msg.p2p_address.empty()) {
         wlog("Handshake message validation: p2p_address is null string");
         valid = false;
      }
      if (msg.os.empty()) {
         wlog("Handshake message validation: os field is null string");
         valid = false;
      }
      if ((msg.sig != chain::signature_type() || msg.token != sha256()) && (msg.token != fc::sha256::hash(msg.time))) {
         wlog("Handshake message validation: token field invalid");
         valid = false;
      }
      return valid;
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const handshake_message &msg) {
      peer_ilog(c, "received handshake_message");
      if (!is_valid(msg)) {
         peer_elog( c, "bad handshake message");
         c->enqueue( go_away_message( fatal_other ));
         return;
      }

      if( c->connecting ) {
         c->connecting = false;
      }
      if (msg.generation == 1) {
         if( msg.node_id == node_id) {
            elog( "Self connection detected. Closing connection");
            c->enqueue( go_away_message( self ) );
            return;
         }

         if( c->peer_addr.empty() || c->last_handshake_recv.node_id == fc::sha256()) {
            fc_dlog(logger, "checking for duplicate" );
            for(const auto &check : connections) {
               if(check == c)
                  continue;
               if(check->connected() && check->peer_name() == msg.p2p_address) {
                  // It's possible that both peers could arrive here at relatively the same time, so
                  // we need to avoid the case where they would both tell a different connection to go away.
                  // Using the sum of the initial handshake times of the two connections, we will
                  // arbitrarily (but consistently between the two peers) keep one of them.
                  if (msg.time + c->last_handshake_sent.time <= check->last_handshake_sent.time + check->last_handshake_recv.time)
                     continue;

                  fc_dlog( logger, "sending go_away duplicate to ${ep}", ("ep",msg.p2p_address) );
                  go_away_message gam(duplicate);
                  gam.node_id = node_id;
                  c->enqueue(gam);
                  c->no_retry = duplicate;
                  return;
               }
            }
         }
         else {
            fc_dlog(logger, "skipping duplicate check, addr == ${pa}, id = ${ni}",("pa",c->peer_addr)("ni",c->last_handshake_recv.node_id));
         }

//#ifndef PLUGIN_TEST
//         if( msg.chain_id != sidechain_id) {
//            elog( "Peer chain id not correct. Closing connection");
//            c->enqueue( go_away_message(go_away_reason::wrong_chain) );
//            return;
//         }
//#endif
         c->protocol_version = msg.network_version;
         if(c->protocol_version != net_version) {
            if (network_version_match) {
               elog("Peer network version does not match expected ${nv} but got ${mnv}",
                    ("nv", net_version)("mnv", c->protocol_version));
               c->enqueue(go_away_message(wrong_version));
               return;
            } else {
               ilog("Local network version: ${nv} Remote version: ${mnv}",
                    ("nv", net_version)("mnv", c->protocol_version));
            }
         }

         if(  c->node_id != msg.node_id) {
            c->node_id = msg.node_id;
         }

         if(!authenticate_peer(msg)) {
            elog("Peer not authenticated.  Closing connection.");
            c->enqueue(go_away_message(authentication));
            return;
         }

         if (c->sent_handshake_count == 0) {
            c->send_handshake();
         }
      }

      c->last_handshake_recv = msg;
      c->_logger_variant.reset();
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const go_away_message &msg ) {
      string rsn = reason_str( msg.reason );
      peer_ilog(c, "received go_away_message");
      ilog( "received a go away message from ${p}, reason = ${r}",
            ("p", c->peer_name())("r",rsn));
      c->no_retry = msg.reason;
      if(msg.reason == duplicate ) {
         c->node_id = msg.node_id;
      }
      c->flush_queues();
      close (c);
   }

   void ibc_plugin_impl::handle_message(connection_ptr c, const time_message &msg) {
      peer_ilog(c, "received time_message");
      /* We've already lost however many microseconds it took to dispatch
       * the message, but it can't be helped.
       */
      msg.dst = c->get_time();

      // If the transmit timestamp is zero, the peer is horribly broken.
      if(msg.xmt == 0)
         return;                 /* invalid timestamp */

      if(msg.xmt == c->xmt)
         return;                 /* duplicate packet */

      c->xmt = msg.xmt;
      c->rec = msg.rec;
      c->dst = msg.dst;

      if(msg.org == 0)
      {
         c->send_time(msg);
         return;  // We don't have enough data to perform the calculation yet.
      }

      c->offset = (double(c->rec - c->org) + double(msg.xmt - c->dst)) / 2;
      double NsecPerUsec{1000};

      if(logger.is_enabled(fc::log_level::all))
         logger.log(FC_LOG_MESSAGE(all, "Clock offset is ${o}ns (${us}us)", ("o", c->offset)("us", c->offset/NsecPerUsec)));
      c->org = 0;
      c->rec = 0;
   }


   void ibc_plugin_impl::handle_message( connection_ptr c, const ibc_heartbeat_message &msg) {
      peer_ilog(c, "received ibc_heartbeat_message");

      ilog("received msg: origtrxs_table_id_range [${of},${ot}] cashtrxs_table_seq_num_range [${cf},${ct}] new_producers_block_num ${n}, lwcls_range [${lsf},${lst}]",
           ("of",msg.origtrxs_table_id_range.first)("ot",msg.origtrxs_table_id_range.second)
           ("cf",msg.cashtrxs_table_seq_num_range.first)("ct",msg.cashtrxs_table_seq_num_range.second)
           ("n",msg.new_producers_block_num)("lsf",msg.lwcls.first_num)("lst",msg.lwcls.last_num));

      // step one: check ibc_chain_state and lwcls
      if ( msg.ibc_chain_state == deployed ) {  // send lwc_init_message
         controller &cc = chain_plug->chain();
         uint32_t head_num = cc.fork_db_head_block_num();

#ifndef PLUGIN_TEST
         uint32_t depth = 200;
         block_state_ptr p;
         while ( p == block_state_ptr() && depth >= 25 ){
            uint32_t check_num = std::max( head_num - depth, uint32_t(1) );
            p = cc.fetch_block_state_by_number( check_num );
            if ( p == block_state_ptr() ){
               ilog("didn't get block_state_ptr of block num: ${n}", ("n", check_num ));
            }else{
               break;
            }
            depth /= 2;
         }

         if ( p == block_state_ptr() ){
            ilog("didn't get any block state finally, wait");
            return;
         }

#else
         block_state_ptr p = cc.fetch_block_state_by_number( head_num );
#endif

         if ( p->pending_schedule.version != p->active_schedule.version ){
            ilog("pending_schedule version not equal to active_schedule version, wait until equal");
            return;
         }

         lwc_init_message msg;
         msg.header = p->header;
         msg.active_schedule = p->active_schedule;
         msg.blockroot_merkle = p->blockroot_merkle;

         peer_ilog(c,"send lwc_init_message");
         c->enqueue( msg, true);
      } else if ( msg.ibc_chain_state == working ){ // validate and update local lwcls_info
         auto check_id = [=](uint32_t block_num, block_id_type id) -> bool {
            if ( block_num == 0 || block_num > chain_plug->chain().head_block_num() ){
               return false;
            }
            try {
               auto ret_id = my_impl->chain_plug->chain().get_block_id_for_num(block_num);
               return ret_id == id;
            } FC_LOG_AND_DROP()
            return false;
         };

         bool valid = false;
         if (check_id(msg.lwcls.first_num, msg.lwcls.first_id)) {
            if (msg.lwcls.valid && msg.lwcls.lib_num != 0 ) {
               if (check_id(msg.lwcls.lib_num, msg.lwcls.lib_id)) {
                  valid = true;
               } else {
                  valid = false;
               }
            }
            valid = true;
         }

         if ( valid ) {
            c->lwcls_info = msg.lwcls;
            c->lwcls_info_update_time = fc::time_point::now();
         } else {
            c->lwcls_info = lwc_section_type();
            c->lwcls_info_update_time = fc::time_point();
            peer_elog(c,"received invalid ibc_heartbeat_message::lwcls");
            idump((msg.lwcls));
         }
      }

      // step two: check origtrxs_table_id_range
      if ( msg.origtrxs_table_id_range != range_type() ){
         ibc_trxs_request_message request;
         request.table = N(origtrxs);
         if ( local_origtrxs.size() == 0 ){
            request.range = msg.origtrxs_table_id_range;
         } else if ( local_origtrxs.rbegin()->table_id < msg.origtrxs_table_id_range.second ) {
            request.range.first = local_origtrxs.rbegin()->table_id + 1;
            request.range.second = msg.origtrxs_table_id_range.second;
         }
         if ( request.range != range_type() ){
            for( auto &c : connections) {
               if( c->current() ) {
                  peer_ilog(c,"send ibc_trxs_request_message, origtrxs id range:[${f},${t}]", ("f",request.range.first)("t",request.range.second));
                  c->enqueue( request );
               }
            }
         }
      }

      // step three: check cashtrxs_table_id_range
      if ( msg.cashtrxs_table_seq_num_range != range_type() ) {
         ibc_trxs_request_message request;
         request.table = N(cashtrxs);
         if (local_cashtrxs.size() == 0) {

            auto gm_opt = token_contract->get_global_mutable_singleton();
            if ( !gm_opt.valid() ){
               elog("internal error, failed to get global_mutable_singleton");
               return;
            }

            request.range.first = gm_opt->cash_seq_num + 1;
            request.range.second = msg.cashtrxs_table_seq_num_range.second;
         } else if (local_cashtrxs.rbegin()->table_id < msg.cashtrxs_table_seq_num_range.second) {
            request.range.first = local_cashtrxs.rbegin()->table_id + 1;
            request.range.second = msg.cashtrxs_table_seq_num_range.second;
         }
         if ( request.range != range_type() ) {
            for( auto &c : connections) {
               if( c->current() ) {
                  peer_ilog(c,"send ibc_trxs_request_message, cashtrxs id range:[${f},${t}]", ("f", request.range.first)("t", request.range.second));
                  c->enqueue( request );
               }
            }
         }
      }

      // step four: check new_producers_block_num
      if ( msg.new_producers_block_num ){
         new_prod_blk_num = msg.new_producers_block_num;
      }
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const lwc_init_message &msg) {
      peer_ilog(c, "received lwc_init_message");

      chain_contract->get_contract_state();
      if ( chain_contract->state == deployed && chain_contract->lib_depth_valid() ){
         chain_contract->chain_init( msg );
      }
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const lwc_section_request_message &msg) {
      peer_ilog(c, "received lwc_section_request_message [${from},${to}]",("from",msg.start_block_num)("to",msg.end_block_num));

      uint32_t rq_length = msg.end_block_num - msg.start_block_num + 1;
      uint32_t head_blk_num = chain_plug->chain().head_block_num();
      uint32_t safe_blk_num = head_blk_num - MinDepth;

      if ( msg.start_block_num >= safe_blk_num || rq_length == 0 ){
         return;
      }
      if ( rq_length >= MaxSendSectionLength && safe_blk_num - msg.start_block_num < MaxSendSectionLength ){
         // ilog("have not enough data");
         return;
      }
      if  ( rq_length < MaxSendSectionLength && msg.end_block_num > safe_blk_num ) {
         // ilog("have not enough data");
         return;
      }

      uint32_t end_num = std::min( safe_blk_num, msg.end_block_num );

      if ( msg.end_block_num > safe_blk_num ){
         end_num = msg.start_block_num + ((end_num - msg.start_block_num ) / MaxSendSectionLength) * MaxSendSectionLength;
      }

      for ( uint32_t start_num = msg.start_block_num; start_num < end_num; start_num += MaxSendSectionLength ){
         lwc_section_data_message ret_msg;
         uint32_t check_num = start_num;

         auto start_bsp = chain_plug->chain().fetch_block_state_by_number( check_num );
         if ( start_bsp != block_state_ptr() ){
            ret_msg.blockroot_merkle = start_bsp->blockroot_merkle;
            ret_msg.headers.push_back( start_bsp->header );
         } else {
            auto sbp = chain_plug->chain().fetch_block_by_number(start_num);
            if ( sbp == signed_block_ptr() ){
               elog("block ${n} not exist", ("n", start_num));
               return;
            }

            // search form cache
            incremental_merkle mkl = get_brtm_from_cache( start_num );
            if ( mkl._node_count != 0 && mkl._active_nodes.size() > 0 ){
               ret_msg.blockroot_merkle = mkl;
               ret_msg.headers.push_back( *sbp );
            } else {    // when node restart
               ilog("didn't find blockroot_merkle of block ${n} in cache, calculate it by known blockroot_merkles",("n",check_num));

               blockroot_merkle_type walk_point;
               walk_point.block_num = start_num - ( start_num % 64 );
               auto sbp = chain_plug->chain().fetch_block_by_number(walk_point.block_num);
               if ( sbp == signed_block_ptr() ){
                  elog("block ${n} not exist", ("n", start_num));
                  return;
               }
               bool has_merkle_extension = false;
               for( auto& ext : sbp->block_extensions ){
                  if ( ext.first == 0xF && ext.second.size() > 0 ){
                     has_merkle_extension = true;
                     walk_point.merkle = fc::raw::unpack<incremental_merkle>( ext.second );
                     break;
                  }
               }

               if ( ! has_merkle_extension ){
                  elog("didn't find blockroot_merkle of block ${n} in block_log.dat, can't calculate block ${m}'s blockroot_merkle",("n",walk_point.block_num )("m",check_num));
                  return;
               } else {
                  dlog("calculate block ${n}'s blockroot_merkle from block ${m}",("n",check_num)("m",walk_point.block_num ));
               }

               uint32_t count = check_num - walk_point.block_num;
               for( uint32_t i = 0; i < count; ++i ){
                  walk_point.merkle.append( chain_plug->chain().get_block_id_for_num( walk_point.block_num ) );
                  walk_point.block_num++;
               }

               if (walk_point.block_num == check_num ){
                  ret_msg.blockroot_merkle = walk_point.merkle;
                  ret_msg.headers.push_back( *(chain_plug->chain().fetch_block_by_number(walk_point.block_num)) );
               } else {
                  elog("internal error, calculate blockroot_merkle of block ${n} failed", ("n",check_num));
                  return;
               }
            }
         }
         ++check_num;
         uint32_t tmp_end_num = std::min( start_num + MaxSendSectionLength - 1, end_num );
         while ( check_num <= tmp_end_num ){
            ret_msg.headers.push_back( *(chain_plug->chain().fetch_block_by_number( check_num )) );
            check_num += 1;
         }
         peer_ilog(c,"sending lwc_section_data_message, range [${from},${to}], merkle nodes ${nodes}", ("from",start_num)("to",tmp_end_num)("nodes",ret_msg.blockroot_merkle._active_nodes.size()));
         c->enqueue( ret_msg );

         return; // send only once
      }
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const lwc_section_data_message &msg) {
      peer_ilog(c, "received lwc_section_data_message [${from},${to}]",("from",msg.headers.front().block_num())("to",msg.headers.back().block_num()));

      auto p = chain_contract->get_sections_tb_reverse_nth_section();
      if ( !p.valid() ){
         elog("can not get section info from ibc.chain contract");
         return;
      }
      section_type ls = *p;

      uint32_t msg_first_num = msg.headers.begin()->block_num();
      uint32_t msg_last_num = msg.headers.rbegin()->block_num();

      if( msg_last_num <= ls.last && msg.headers.rbegin()->id() == chain_contract->get_chaindb_tb_block_id_by_block_num(msg_last_num) ){
         ilog("lwc_section_data_message has no new data");
         return;
      }

      if ( ls.valid && msg_last_num <= std::max(ls.first, ls.last > chain_contract->lwc_lib_depth ? ls.last - chain_contract->lwc_lib_depth : 0) ){
         ilog("nothing to do");
         return;
      }

      if ( msg_first_num == ls.last + 1 ){ // append directly
         chain_contract->pushsection( msg );
      }

      else if( msg_first_num <= ls.last ) { // find fit number then append directly // todo review
         // find the first block number, which id is same in msg and lwcls.
         uint32_t check_num_first = std::min( uint32_t(ls.last), msg.headers.rbegin()->block_num() );
         uint32_t check_num_last = std::max( uint32_t(ls.valid ? ls.last - chain_contract->lwc_lib_depth : ls.first), msg.headers.front().block_num() );
         uint32_t identical_num = 0;
         uint32_t check_num = check_num_first;
         while ( check_num >= check_num_last ){
            auto id_from_msg = msg.headers[ check_num - msg.headers.front().block_num()].id();
            auto id_from_lwc = chain_contract->get_chaindb_tb_block_id_by_block_num( check_num );
            if ( id_from_lwc != block_id_type() && id_from_msg == id_from_lwc ){
               identical_num = check_num;
               break;
            }
            --check_num;
         }

         idump((identical_num));

         if ( identical_num == 0 ){
            if ( check_num == ls.first ){
               // delete lwcls ?
            }
            elog("*****??");
            return;
         }

         // construct and push section data
         incremental_merkle merkle = msg.blockroot_merkle;
         for ( int i = 0; i < identical_num - msg.headers.front().block_num(); ++i ){
            merkle.append( msg.headers[i].id() );
         }

         lwc_section_data_message par;
         par.blockroot_merkle = merkle;
         auto first_itr = msg.headers.begin() + ( identical_num - msg.headers.front().block_num() );
         for ( auto it = first_itr; it != msg.headers.end(); ++it ){
            par.headers.push_back( *it );
         }
         chain_contract->pushsection( par );
      }

      else { // store in local_sections
         lwc_section_info  sctn;
         sctn.first = msg.headers.begin()->block_num();
         sctn.last = msg.headers.rbegin()->block_num();
         sctn.section_data = msg;

         auto it = local_sections.find( sctn.first );
         if ( it == local_sections.end() ){
            local_sections.insert( sctn );
         } else if ( msg.headers.rbegin()->block_num() < it->first ) {
            local_sections.erase( it );
            local_sections.insert( sctn );
         }

         // erase old local sections
         auto lwcls_opt = chain_contract->get_sections_tb_reverse_nth_section();
         if ( lwcls_opt.valid()){
            section_type lwcls = *lwcls_opt;
            int sum = 0;
            for ( auto it = local_sections.rbegin(); it != local_sections.rend(); ++it ){
               if ( it->first < lwcls.first ){
                  ++sum;
               }
               if ( sum >= MaxLocalOldSectionsCache ){
                  local_sections.erase( local_sections.iterator_to(*it) );
               }
            }
         }
      }
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const ibc_trxs_request_message &msg ) {
      peer_ilog(c, "received ibc_trxs_request_message, table ${tb}, id range [${f},${t}]",("tb",msg.table)("f",msg.range.first)("t",msg.range.second));

      uint32_t safe_tslot = my_impl->get_safe_head_tslot();
      ibc_trxs_data_message ret_msg;
      ret_msg.table = msg.table;

      static const uint32_t max_responses_per_time = 50;

      if ( msg.table == N(origtrxs) ){
         for( auto id = msg.range.first; id <= msg.range.second && id <= msg.range.first + max_responses_per_time; ++id ){
            auto p = token_contract->get_table_origtrxs_trx_info_by_id( id );
            if ( p.valid() ){
               original_trx_info trx_info = *p;
               if ( trx_info.block_time_slot >= safe_tslot ){ break; }
               auto info_opt = get_ibc_trx_rich_info( trx_info.block_time_slot, trx_info.trx_id, trx_info.id );
               if ( info_opt.valid() ){
                  ret_msg.trxs_rich_info.push_back( *info_opt );
               } else {
                  ilog("internal error, failed to get rich info of transaction: ${trx}, block time slot: ${tsl}",("trx",trx_info.trx_id)("tsl",trx_info.block_time_slot));
               }
            }
         }

      } else if ( msg.table == N(cashtrxs) ){
         for( auto id = msg.range.first; id <= msg.range.second && id <= msg.range.first + max_responses_per_time; ++id ){
            auto p = token_contract->get_table_cashtrxs_trx_info_by_seq_num( id );
            if ( p.valid() ){
               cash_trx_info trx_info = *p;
               if ( trx_info.block_time_slot >= safe_tslot ){ break; }
               auto info_opt = get_ibc_trx_rich_info( trx_info.block_time_slot, trx_info.trx_id, trx_info.seq_num );
               if ( info_opt.valid() ){
                  ret_msg.trxs_rich_info.push_back( *info_opt );
               } else {
                  ilog("internal error, failed to get rich info of transaction: ${trx}, block time slot: ${tsl}",("trx",trx_info.trx_id)("tsl",trx_info.block_time_slot));
               }
            }
         }
      }

      if ( ret_msg.trxs_rich_info.empty() ){
         return;
      }

      peer_ilog(c,"send ibc_trxs_data_message, size:${s}, id range:[${f},${t}]",("s",ret_msg.trxs_rich_info.size())("f",ret_msg.trxs_rich_info.begin()->table_id)("t",ret_msg.trxs_rich_info.rbegin()->table_id));
      c->enqueue( ret_msg );
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const ibc_trxs_data_message &msg ) {
      peer_ilog(c, "received ibc_trxs_data_message, table ${tb}, id range [${f},${t}]", ("tb",msg.table)("f",msg.trxs_rich_info.front().table_id)("t",msg.trxs_rich_info.back().table_id));

      if ( msg.table == N(origtrxs) ) {
         for( const auto& trx_info : msg.trxs_rich_info ){
            if ( local_origtrxs.size() == 0 ){
               local_origtrxs.insert(trx_info);
               break;
            }

            auto it =  local_origtrxs.find( trx_info.table_id );
            if ( it == local_origtrxs.end() ) { // link
               if ( trx_info.table_id == local_origtrxs.rbegin()->table_id + 1 ){
                  local_origtrxs.insert(trx_info);
               } else {
                  peer_elog(c,"received unlinkable trxs_rich_info table: origtrxs, table_id: ${tb_id}, trx_id: ${trx_id}",("tb_id",trx_info.table_id)("trx_id",trx_info.trx_id));
                  local_origtrxs.insert(trx_info); // add it still
               }
            } else {
               if ( it->trx_id == trx_info.trx_id ){ // duplicate
                  break;
               } else { // replace
                  local_origtrxs.erase( it );
                  local_origtrxs.insert(trx_info);
                  peer_elog(c,"received conflict trxs_rich_info table: origtrxs, table_id: ${tb_id}",("tb_id",trx_info.table_id));
               }
            }
         }

         while ( local_origtrxs.size() != 0 &&
              local_origtrxs.rbegin()->table_id - local_origtrxs.begin()->table_id > MaxLocalOrigtrxsCache ){
            local_origtrxs.erase( local_origtrxs.begin() );
         }
         return;
      }

      if ( msg.table == N(cashtrxs) ){
         for( const auto& trx_info : msg.trxs_rich_info ){
            if ( local_cashtrxs.size() == 0 ){
               local_cashtrxs.insert(trx_info);
               break;
            }

            auto it =  local_cashtrxs.find( trx_info.table_id );
            if ( it == local_cashtrxs.end() ) { // link
               if ( trx_info.table_id == local_cashtrxs.rbegin()->table_id + 1 ){
                  local_cashtrxs.insert(trx_info);
               } else {
                  peer_elog(c,"received unlinkable trxs_rich_info table: cashtrxs, table_id: ${tb_id}, trx_id: ${trx_id}",("tb_id",trx_info.table_id)("trx_id",trx_info.trx_id));
                  local_cashtrxs.insert(trx_info); // add it still
               }
            } else {
               if ( it->trx_id == trx_info.trx_id ){
                  break;
               } else { // replace
                  local_cashtrxs.erase( it );
                  local_cashtrxs.insert(trx_info);
                  peer_elog(c,"received conflict trxs_rich_info table: cashtrxs, table_id: ${tb_id}",("tb_id",trx_info.table_id));
               }
            }
         }

         while ( local_cashtrxs.size() != 0 &&
                 local_cashtrxs.rbegin()->table_id - local_cashtrxs.begin()->table_id > MaxLocalCashtrxsCache ){
            local_cashtrxs.erase( local_cashtrxs.begin() );
         }
         return;
      }
   }

   incremental_merkle ibc_plugin_impl::get_brtm_from_cache( uint32_t block_num ){
      if ( blockroot_merkle_cache.begin() != blockroot_merkle_cache.end() &&
      blockroot_merkle_cache.begin()->block_num <= block_num && block_num <= blockroot_merkle_cache.rbegin()->block_num ){
         return blockroot_merkle_cache[ block_num - blockroot_merkle_cache.begin()->block_num  ].merkle;
      }

      incremental_merkle mkl;
      mkl._node_count = 0;
      return mkl;
   }

   uint32_t ibc_plugin_impl::get_safe_head_tslot(){
      auto fdb_hbn = chain_plug->chain().fork_db_head_block_num();
      auto sbp = chain_plug->chain().fetch_block_by_number( fdb_hbn );
      auto head_tslot = sbp->timestamp.slot;
      return head_tslot - MinDepth;
   }

   lwc_section_type ibc_plugin_impl::sum_received_lwcls_info() {
      std::vector<lwc_section_type> sv;
      for (auto &c : connections ) {
         if ( c->lwcls_info_update_time != fc::time_point() &&
              c->lwcls_info != lwc_section_type() &&
              ( fc::time_point::now() - c->lwcls_info_update_time < fc::seconds(30)) ){
            sv.push_back( c->lwcls_info );
         }
      }

      if( sv.empty() ){
         return lwc_section_type();
      }
      std::sort( sv.begin(), sv.end(), []( lwc_section_type s1, lwc_section_type s2 ){
         return s1.first_num < s2.first_num ;
      } );

      return sv[ sv.size() / 2 ];
   }

   bool ibc_plugin_impl::is_head_catchup() {
      auto head_block_time_point = fc::time_point( chain_plug->chain().fork_db_head_block_time() );
      return head_block_time_point < fc::time_point::now() + fc::seconds(3) &&
             head_block_time_point > fc::time_point::now() - fc::seconds(5);
   }

   bool ibc_plugin_impl::should_send_ibc_heartbeat(){

      // check if local head catch up
      if ( !is_head_catchup() ){
         ilog("local chain head doesn't catch up current chain head, waiting...");
         return false;
      }

      // check ibc.chain contract
      if ( chain_contract->state != working ){
         chain_contract->get_contract_state();
      }
      if ( chain_contract->state == none ){
         ilog("ibc.chain contract not deployed");
         return false;
      }
      if (!chain_contract->lib_depth_valid() ){
         ilog("ibc.chain contract lib_depth validate failed");
         return false;
      }

      // check ibc.token contract
      if ( token_contract->state != working ){
         token_contract->get_contract_state();
         ilog("ibc.token contract not in working state, current state: ${s}", ("s", contract_state_str( token_contract->state )));
         return false;
      }

      return true;
   }

   // get  new producer schedule info for ibc_heartbeat_message to send, check if has new producer schedule since lwcls's last block
   void ibc_plugin_impl::chain_checker( ibc_heartbeat_message& msg ) {
      msg.new_producers_block_num = 0;

      auto lwcls = sum_received_lwcls_info();
      if ( lwcls == lwc_section_type() ){
         ilog("doesn't receive any lwcls infomation from connected peer chain relay nodes");
         return;
      }

      uint32_t local_safe_head_num = chain_plug->chain().head_block_num() - MinDepth;
      if ( lwcls.last_num >= local_safe_head_num ){
         return;
      }

      static uint32_t check_block_num = 0;

      if ( lwcls.last_num > check_block_num ){
         check_block_num = lwcls.last_num;
      }

      auto get_block_ptr = [=]( uint32_t num ) -> signed_block_ptr {
         return chain_plug->chain().fetch_block_by_number(num);
      };

      while ( check_block_num < local_safe_head_num ){
         auto np_opt = get_block_ptr(check_block_num)->new_producers;
         if ( np_opt.valid() && np_opt->producers.size() > 0 ){
            msg.new_producers_block_num = check_block_num - 1;
            ilog("find new_producers_block_num ${n} < ---- new producers ---- >",("n",msg.new_producers_block_num));
            return;
         }
         ++check_block_num;
      }
   }

   // get lwcls info for ibc_heartbeat_message to send
   void ibc_plugin_impl::ibc_chain_contract_checker( ibc_heartbeat_message& msg ) {

         auto p = my_impl->chain_contract->get_sections_tb_reverse_nth_section();
         if ( p.valid() ){
            auto obj = *p;
            lwc_section_type ls;
            ls.first_num = obj.first;
            ls.first_id = chain_contract->get_chaindb_tb_block_id_by_block_num( ls.first_num );
            ls.last_num = obj.last;
            ls.last_id = chain_contract->get_chaindb_tb_block_id_by_block_num( ls.last_num );
            if (  obj.last - chain_contract->lwc_lib_depth >= obj.first ){
               ls.lib_num = obj.last - chain_contract->lwc_lib_depth;
               ls.lib_id = chain_contract->get_chaindb_tb_block_id_by_block_num( ls.lib_num );
            } else {
               ls.lib_num = 0;
               ls.lib_id = block_id_type();
            }
            ls.valid = obj.valid;

            msg.lwcls = ls;
         }

         msg.ibc_chain_state = chain_contract->state;
   }

   // get origtrxs and cashtrxs tables info for ibc_heartbeat_message to send
   void ibc_plugin_impl::ibc_token_contract_checker( ibc_heartbeat_message& msg ){
      msg.ibc_token_state = token_contract->state;
      msg.origtrxs_table_id_range = token_contract->get_table_origtrxs_id_range();
      msg.cashtrxs_table_seq_num_range = token_contract->get_table_cashtrxs_seq_num_range();
   }

   void ibc_plugin_impl::start_ibc_heartbeat_timer() {

      if ( count_open_sockets() != 0 ){
         try{
            if ( should_send_ibc_heartbeat() ){
               ibc_heartbeat_message msg;
               chain_checker(msg);
               ibc_chain_contract_checker(msg);
               ibc_token_contract_checker(msg);

               if ( connections.size() == 0 ){
                  elog("connections.size() == 0");
               }

               for( auto &c : connections) {
                  if( c->current() ) {
                     peer_ilog(c,"sending ibc_heartbeat_message");

                     dlog("origtrxs_table_id_range [${of},${ot}] cashtrxs_table_seq_num_range [${cf},${ct}] new_producers_block_num ${n}, lwcls_range [${lsf},${lst},${v}]",
                          ("of",msg.origtrxs_table_id_range.first)("ot",msg.origtrxs_table_id_range.second)
                             ("cf",msg.cashtrxs_table_seq_num_range.first)("ct",msg.cashtrxs_table_seq_num_range.second)
                             ("n",msg.new_producers_block_num)("lsf",msg.lwcls.first_num)("lst",msg.lwcls.last_num)("v",msg.lwcls.valid));

                     c->enqueue( msg );
                  } else {
                     elog( "c->current() is faulse" );
                     ilog( "close connection" );
                     close(c);
                  }
               }
            }
         } FC_LOG_AND_DROP()
      } else {
         elog("count_open_sockets() == 0");
      }


      ibc_heartbeat_timer->expires_from_now (ibc_heartbeat_interval);
      ibc_heartbeat_timer->async_wait ([this](boost::system::error_code ec) {
         start_ibc_heartbeat_timer();
         if (ec) {
            wlog ("start_ibc_heartbeat_timer error: ${m}", ("m", ec.message()));
         }
      });
   }

   vector<digest_type>  get_merkle_path( vector<digest_type> ids, uint32_t num ) {
      if( 0 == ids.size() || num > ids.size() - 1 ) { return vector<digest_type>(); }

      vector<digest_type> result;

      if( ids.size() == 1 ){
         result.push_back( ids.front() );
         return result;
      }

      // add the first two elements to merkle path
      if ( num % 2 == 0 ){ // left side
         result.push_back(ids[num]);
         if ( num == ids.size() - 1 ){
            result.push_back(ids[num]);
         } else {
            result.push_back(ids[num+1]);
         }
      } else { // right side
         result.push_back(ids[num-1]);
         result.push_back(ids[num]);
      }

      // append middle path
      uint32_t idx_in_layer = num;
      while( ids.size() > 1 ) {
         if( ids.size() % 2 )
            ids.push_back(ids.back());

         for (int i = 0; i < ids.size() / 2; i++) {
            ids[i] = digest_type::hash(make_canonical_pair(ids[2 * i], ids[(2 * i) + 1]));
         }
         ids.resize(ids.size() / 2);

         if ( ids.size() > 1 ){ // not reach root yet
            idx_in_layer /= 2;
            if ( idx_in_layer % 2 == 0 ){ // left side
               if ( idx_in_layer == ids.size() - 1 ){
                  result.push_back( make_canonical_right(ids[idx_in_layer]) );
               } else {
                  result.push_back( make_canonical_right(ids[idx_in_layer+1]) );
               }
            } else { // right side
               result.push_back( make_canonical_left(ids[idx_in_layer-1]) );
            }
         }
      }

      // append merkle root
      result.push_back( ids.front() );
      return result;
   }


   optional<ibc_trx_rich_info> ibc_plugin_impl::get_ibc_trx_rich_info( uint32_t block_time_slot, transaction_id_type trx_id, uint64_t table_id ){
      auto head_num = chain_plug->chain().fork_db_head_block_num(); // .head_block_num(); to do
      auto head_slot = chain_plug->chain().fetch_block_by_number(head_num)->timestamp.slot;

      if ( head_slot < block_time_slot ){
         elog( "unknown block_time_slot" );
         return  optional<ibc_trx_rich_info>();
      }

      ibc_trx_rich_info trx_info;
      trx_info.table_id = table_id;
      trx_info.trx_id = trx_id;

      // get block number from block_time_slot
      uint32_t check_num = head_num - ( head_slot  - block_time_slot );
      uint32_t check_slot = chain_plug->chain().fetch_block_by_number(check_num)->timestamp.slot;
      while ( check_slot < block_time_slot ){
            check_num += 1;
            check_slot = chain_plug->chain().fetch_block_by_number(check_num)->timestamp.slot;
      }
      if ( check_slot != block_time_slot ){
         elog( "block of block_time_slot not found" );
         return  optional<ibc_trx_rich_info>();
      }
      trx_info.block_num = check_num;

      // get trx merkle path
      auto blk_ptr =  chain_plug->chain().fetch_block_by_number( trx_info.block_num );
      std::vector<digest_type>            trx_digests;
      std::vector<transaction_id_type>    trx_ids;
      std::vector<char>                   packed_trx_receipt;

      bool found = false;
      uint32_t found_num = 0;
      for ( auto const& trx : blk_ptr->transactions ){
         trx_digests.push_back( trx.digest() );

         transaction_id_type check_trx_id = transaction_id_type();
         try {
            check_trx_id = trx.trx.get<packed_transaction>().id();
         } catch (...) {}

         if ( check_trx_id == trx_id ){
            found = true;
            packed_trx_receipt = fc::raw::pack(trx);
         }
         if (!found){
            found_num += 1;
         }
      }

      if ( merkle(trx_digests) != blk_ptr->transaction_mroot ){
         elog("internal error");
         return optional<ibc_trx_rich_info>();
      }

      if ( !found ){
         elog("trx not found");
         return optional<ibc_trx_rich_info>();
      }

      auto mp = get_merkle_path( trx_digests, found_num );
      if ( mp.empty() ){
         elog("internal error");
         return optional<ibc_trx_rich_info>();
      }

      trx_info.merkle_path = mp;
      trx_info.packed_trx_receipt = packed_trx_receipt;

      return trx_info;
   }

   void ibc_plugin_impl::check_if_remove_old_data_in_ibc_contracts(){

      // ---- ibc.chain ----
      uint32_t size = chain_contract->get_sections_tb_size();
      if ( size >=3  ){
         chain_contract->rmfirstsctn();
      }

      // ---- ibc.token ----
      uint32_t last_finished_trx_block_time_slot = 0;
      auto gm_opt = token_contract->get_global_mutable_singleton();
      if ( gm_opt.valid() ){
         last_finished_trx_block_time_slot = gm_opt->last_finished_trx_block_time_slot;
      } else {
         elog("get_global_mutable_singleton failed");
         return;
      }

      if ( last_finished_trx_block_time_slot == 0 ){
         return;
      }

      uint32_t count = 0;
      range_type range = token_contract->get_table_origtrxs_id_range();
      if ( range == range_type() ){
         return;
      }

      std::vector<transaction_id_type> to_rmunablerb;
      std::vector<transaction_id_type> to_rollback;

      for ( uint64_t i = range.first; i <= range.second ; ++i ){
         auto trx_opt = token_contract->get_table_origtrxs_trx_info_by_id( i );
         if ( trx_opt.valid() ){
            if ( trx_opt->block_time_slot +  3600 * 24 * 2 < last_finished_trx_block_time_slot ){
               to_rmunablerb.push_back( trx_opt->trx_id );
               continue;
            }

            if ( trx_opt->block_time_slot + 25 < last_finished_trx_block_time_slot ){
               to_rollback.push_back( trx_opt->trx_id );
            } else {
               break;
            }
         }
      }

      static const uint32_t max_push_trxs_per_time = 30;

      if ( ! to_rollback.empty() ){
         token_contract->rollback( to_rollback );
      }

      if ( ! to_rmunablerb.empty() ){
         std::vector<transaction_id_type> to_push;
         if ( to_rmunablerb.size() > max_push_trxs_per_time ){
            to_push = std::vector<transaction_id_type>( to_rmunablerb.begin(), to_rmunablerb.begin() + max_push_trxs_per_time );
         } else {
            to_push = to_rmunablerb;
         }
         token_contract->rmunablerb( to_push );
      }
   }

   /**
    * This function implements the core ibc logic of the plugin
    */

   void ibc_plugin_impl::ibc_core_checker( ){

      if ( chain_contract->state != working || token_contract->state != working ){
         chain_contract->get_contract_state();
         token_contract->get_contract_state();
         return;
      }

      // dump debug info
      uint32_t orig_begin = 0, orig_end = 0, cash_begin = 0, cash_end = 0;
      if( local_origtrxs.begin() != local_origtrxs.end() ){
         orig_begin = local_origtrxs.begin()->table_id;
         orig_end = local_origtrxs.rbegin()->table_id;
      }
      if( local_cashtrxs.begin() != local_cashtrxs.end() ){
         cash_begin = local_cashtrxs.begin()->table_id;
         cash_end = local_cashtrxs.rbegin()->table_id;
      }
      ilog("local_origtrxs id range [${of},${ot}], local_cashtrxs id range [${cf},${ct}]",("of",orig_begin)("ot",orig_end)("cf",cash_begin)("ct",cash_end));

      ///< ---- step zero: remove side effect of unapplied trxs ---- >///
      chain_plug->chain().abort_block();
      chain_plug->chain().drop_all_unapplied_transactions();

      check_if_remove_old_data_in_ibc_contracts();

      ///< ---- step one: let lwcls in ibc.chain reach its minimum length ---- >///

      auto opt_sctn = chain_contract->get_sections_tb_reverse_nth_section();
      if ( !opt_sctn.valid() ){
         elog("internal error, can not get lwcls");
         return;
      }
      section_type lwcls = *opt_sctn;

      // calculation the minimun range of lwcls should reach through information of local_origtrxs, local_cashtrxs and new_prod_blk_num
      uint32_t min_last_num = lwcls.first + chain_contract->lwc_lib_depth ;

      if ( lwcls.np_num != 0 ){
         min_last_num = std::max( min_last_num, uint32_t( lwcls.np_num + BPScheduleReplaceMinLength + chain_contract->lwc_lib_depth) );
      }

      ///< --- local_origtrxs --- >///
      auto _it_orig = local_origtrxs.get<by_block_num>().lower_bound( lwcls.first );
      auto it_orig = local_origtrxs.project<0>(_it_orig);
      while ( it_orig != local_origtrxs.end() && it_orig->block_num < min_last_num ){
         min_last_num = std::max( min_last_num, it_orig->block_num + chain_contract->lwc_lib_depth );
         ++it_orig;
      }

      ///< --- local_cashtrxs --- >///
      auto _it_cash = local_cashtrxs.get<by_block_num>().lower_bound( lwcls.first );
      auto it_cash = local_cashtrxs.project<0>(_it_cash);
      while ( it_cash != local_cashtrxs.end() && it_cash->block_num < min_last_num ){
         min_last_num = std::max( min_last_num, it_cash->block_num + chain_contract->lwc_lib_depth );
         ++it_cash;
      }

      if ( lwcls.first <= new_prod_blk_num && new_prod_blk_num <= min_last_num ){
         min_last_num = std::max( min_last_num,  new_prod_blk_num + BPScheduleReplaceMinLength + chain_contract->lwc_lib_depth );
      }


      // check if lwcls reached the minimum range, if not, send lwc_section_request_message
      bool reached_min_length = true;
      if ( lwcls.last < min_last_num ){
         reached_min_length = false;
         lwc_section_request_message msg;
         msg.start_block_num = lwcls.last + 1;
         msg.end_block_num = min_last_num + 1;
         for( auto &c : connections) {
            if( c->current() ) {
               peer_ilog(c, "send lwc_section_request_message [${from},${to}]",("from",msg.start_block_num)("to",msg.end_block_num));
               c->enqueue( msg );
            }
         }
      }


      ///< ---- step two: push all transactions which should validate within this lwcls first to lib block ---- >///
      if ( lwcls.valid == false ){
         return;
      }

      static const uint32_t max_push_orig_trxs_per_time = 30;
      static const uint32_t max_push_cash_trxs_per_time = 30;

      std::vector<ibc_trx_rich_info> orig_trxs_to_push;
      std::vector<ibc_trx_rich_info> cash_trxs_to_push;

      uint32_t lib_num =  std::max( lwcls.first, lwcls.last > chain_contract->lwc_lib_depth ? lwcls.last - chain_contract->lwc_lib_depth : 1 );

      ///< --- local_origtrxs --- >///
      auto range = token_contract->get_table_cashtrxs_seq_num_range(true);
      if ( range.first == 0 ){   // range.first == 0 means cashtrxs is empty, range.second shoule alse be 0
         for( const auto& t : local_origtrxs.get<by_id>( ) ) {
            if ( lwcls.first <= t.block_num && t.block_num <= lib_num ){
               orig_trxs_to_push.push_back( t );
            }
         }
      } else {
         auto cash_opt = token_contract->get_table_cashtrxs_trx_info_by_seq_num( range.second );
         if ( cash_opt.valid() ){
            auto orig_trx_id = cash_opt->orig_trx_id;
            auto it_trx_id = local_origtrxs.get<by_trx_id>().find( orig_trx_id );
            auto it = local_origtrxs.project<0>(it_trx_id);
            if ( it != local_origtrxs.end() ){
               ++it;
               while ( it != local_origtrxs.end() ){
                  if ( lwcls.first <= it->block_num && it->block_num <= lib_num ){
                     orig_trxs_to_push.push_back( *it );
                  }
                  ++it;
               }
            } else { // maybe happen when restart ibc_plugin node
               wlog("can not find original transacton infomation form local_origtrxs, is nodeos restarted ?");
               auto it_blk_num = local_origtrxs.get<by_block_num>().lower_bound( cash_opt->orig_trx_block_num + 1 );
               it = local_origtrxs.project<0>(it_blk_num);
               while ( it != local_origtrxs.end() ){
                  if ( lwcls.first <= it->block_num && it->block_num <= lib_num ){
                     orig_trxs_to_push.push_back( *it );
                  }
                  ++it;
               }
            }
         } else { ilog("internal error, failed to get cash transaction information of seq_num ${n}",("n",range.second)); }
      }

      if ( ! orig_trxs_to_push.empty() ){
         std::vector<ibc_trx_rich_info> to_push;
         if ( orig_trxs_to_push.size() > max_push_orig_trxs_per_time ){
            to_push = std::vector<ibc_trx_rich_info>( orig_trxs_to_push.begin(), orig_trxs_to_push.begin() + max_push_orig_trxs_per_time );
         } else {
            to_push = orig_trxs_to_push;
         }

         static uint64_t highest_idx = 0;
         static uint32_t times = 0;

         if ( to_push.back().table_id != highest_idx ){
            highest_idx = to_push.back().table_id;
            times = 1;
         } else {
            times += 1;
         }
         if ( times <= 3 ){
            ilog("---------orig_trxs_to_push to push size ${n}, retry times ${try}",("n",to_push.size())("try",times));
            token_contract->push_cash_trxs( to_push, range.second + 1 );
         }
      }

      ///< --- local_cashtrxs --- >///
      auto gm_opt = token_contract->get_global_mutable_singleton();
      if ( !gm_opt.valid() ){
         elog("internal error, failed to get global_mutable_singleton");
         return;
      }
      uint32_t last_cash_seq_num = gm_opt->cash_seq_num;
      uint32_t next_cash_seq_num = last_cash_seq_num + 1;
      auto it = local_cashtrxs.get<by_id>().find( next_cash_seq_num );

      if ( it == local_cashtrxs.end() ){
         auto it_up = local_cashtrxs.get<by_id>().upper_bound( next_cash_seq_num );
         if ( it_up != local_cashtrxs.end() ){
            // cashconfirm action can't jump, must push according to the serial number
            // so, return directly here
            // this may be caused by start a new relay-relay channel when other relay-relay channel is working
            wlog("============= cashconfirm action can't jump, return directly =============");
            return;  // important!
         }
      }

      bool return_after_this_step = false;
      if ( it != local_cashtrxs.end() && it->block_num < lwcls.first ){
         // The contract can validate trx with the previous section, not only the lwcls, which may save such a serious error.
         // so don't return here, just print error.
         // this may be caused by start a new relay-relay channel when other relay-relay channel is working and
         // the new channel start a new section because no previous data was obtained
         elog("============== fatal error: it->block_num < lwcls.first ==============");
         edump((*it)( lwcls.first)( lwcls.last));
         return_after_this_step = true;
      }

      while ( it != local_cashtrxs.end() && it->block_num <= lib_num ){
         cash_trxs_to_push.push_back( *it );
         ++it;
      }

      if ( !cash_trxs_to_push.empty() ){
         std::vector<ibc_trx_rich_info> to_push;
         if ( cash_trxs_to_push.size() > max_push_cash_trxs_per_time ){
            to_push = std::vector<ibc_trx_rich_info>( cash_trxs_to_push.begin(), cash_trxs_to_push.begin() + max_push_cash_trxs_per_time );
         } else {
            to_push = cash_trxs_to_push;
         }
         ilog("---------cash_trxs_to_push to push size ${n}",("n",to_push.size()));
         token_contract->push_cashconfirm_trxs( to_push, last_cash_seq_num + 1 );
         return;
      }

      if ( return_after_this_step ){
         return;
      }


      ///< ---- step three: check if all related trxs about lwcls in local_origtrxs and local_cashtrxs have handled ---- >///

      bool orig_b = false, cash_b = false;

      // --- check local_origtrxs ---
      if ( orig_trxs_to_push.empty() || orig_trxs_to_push.back().trx_id == token_contract->last_origtrx_pushed ){
         orig_b = true;
      }

      // --- check local_cashtrxs ---
      if ( cash_trxs_to_push.empty() ){
         cash_b = true;
      } else {
         auto actn_params_opt = token_contract->get_cash_action_params( cash_trxs_to_push.back().packed_trx_receipt );
         if ( ! actn_params_opt.valid() ){
            elog("internal error, failed to get_cash_action_params");
            return;
         }
         if ( gm_opt->cash_seq_num == actn_params_opt->seq_num ){
            cash_b = true;
         }
      }

      // --- summary ---
      if ( ! (reached_min_length && orig_b && cash_b ) ){
         return;
      }


      ///< ---- step four: if has new trxs, request the next section ---- >///
      {
         uint32_t start_blk_num = 0;

         // --- check local_origtrxs ---
         auto __it_orig = local_origtrxs.get<by_block_num>().lower_bound( lwcls.last + 1 );
         auto it_orig = local_origtrxs.project<0>(__it_orig);
         if (  it_orig != local_origtrxs.end() ){
            start_blk_num = it_orig->block_num;
            //ilog("origtrxs has new trxs, start block ${n}",("n",start_blk_num));
         }

         // --- check local_cashtrxs ---
         auto __it_cash = local_cashtrxs.get<by_block_num>().lower_bound( lwcls.last + 1 );
         auto it_cash = local_cashtrxs.project<0>(__it_cash);
         if (  it_cash != local_cashtrxs.end() ){
            if ( start_blk_num != 0 ){
               start_blk_num = std::min( start_blk_num, it_cash->block_num );
            } else {
               start_blk_num = it_cash->block_num;
            }
            //ilog("cashtrxs has new trxs, start block ${n}",("n",start_blk_num));
         }

         // --- check new_prod_blk_num ---
         if ( new_prod_blk_num >= lwcls.last ){
            if ( start_blk_num != 0 ){
               start_blk_num = std::min( start_blk_num, new_prod_blk_num );
            } else {
               start_blk_num = new_prod_blk_num;
            }
         }

         // --- summary ----
         if ( start_blk_num != 0 ){
            // check if has relate section in local store
            bool found = false;
            for( auto it = local_sections.rbegin(); it != local_sections.rend(); ++it ){
               if ( it->first <= start_blk_num && start_blk_num <= it->last ){
                  found = true;
                  chain_contract->pushsection( it->section_data );
                  break;
               }
            }

            // not fount, sent lwc_section_request_message
            if ( ! found ){
               lwc_section_request_message msg;
               msg.start_block_num = start_blk_num;
               msg.end_block_num = start_blk_num + chain_contract->lwc_lib_depth + 1;
               for( auto &c : connections) {
                  if( c->current() ) {
                     peer_ilog(c, "send lwc_section_request_message [${from},${to}]",("from",msg.start_block_num)("to",msg.end_block_num));
                     c->enqueue( msg );
                  }
               }
            }
         }
      }
   }

   void ibc_plugin_impl::start_ibc_core_timer( ){

      static int i = 0;
      if ( count_open_sockets() != 0 ){
         try {
            // this is used for let ibc_heartbeat_timer work and exchange basic infomation first.
            if ( i < 5 ){
               ++i;
            } else {
               ibc_core_checker();
            }
         } FC_LOG_AND_DROP()
      } else {
         // when reconnect with peer plugin node
         i = 0;
         elog("count_open_sockets() == 0");
      }

      ibc_core_timer->expires_from_now( ibc_core_interval );
      ibc_core_timer->async_wait( [this](boost::system::error_code ec) {
         start_ibc_core_timer();
         if( ec) {
            wlog ("start_ibc_core_timer error: ${m}", ("m", ec.message()));
         }
      });
   }

   void ibc_plugin_impl::connection_monitor(std::weak_ptr<connection> from_connection) {
      auto max_time = fc::time_point::now();
      max_time += fc::milliseconds(max_cleanup_time_ms);
      auto from = from_connection.lock();
      auto it = (from ? connections.find(from) : connections.begin());
      if (it == connections.end()) it = connections.begin();
      while (it != connections.end()) {
         if (fc::time_point::now() >= max_time) {
            start_conn_timer(std::chrono::milliseconds(1), *it); // avoid exhausting
            return;
         }
         if( !(*it)->socket->is_open() && !(*it)->connecting) {
            if( (*it)->peer_addr.length() > 0) {
               connect(*it);
            }
            else {
               it = connections.erase(it);
               continue;
            }
         }
         ++it;
      }
      start_conn_timer(connector_period, std::weak_ptr<connection>());
   }

   void ibc_plugin_impl::start_conn_timer(boost::asio::steady_timer::duration du, std::weak_ptr<connection> from_connection) {
      connector_check->expires_from_now( du);
      connector_check->async_wait( [this, from_connection](boost::system::error_code ec) {
         if( !ec) {
            connection_monitor(from_connection);
         }
         else {
            elog( "Error from connection check monitor: ${m}",( "m", ec.message()));
            start_conn_timer( connector_period, std::weak_ptr<connection>());
         }
      });
   }

   void ibc_plugin_impl::start_monitors() {
      connector_check.reset(new boost::asio::steady_timer( app().get_io_service()));
      start_conn_timer(connector_period, std::weak_ptr<connection>());

      ibc_heartbeat_timer.reset(new boost::asio::steady_timer( app().get_io_service()));
      start_ibc_heartbeat_timer();

      ibc_core_timer.reset(new boost::asio::steady_timer( app().get_io_service()));
      start_ibc_core_timer();
   }

   void ibc_plugin_impl::ticker() {
      keepalive_timer->expires_from_now (keepalive_interval);
      keepalive_timer->async_wait ([this](boost::system::error_code ec) {
         ticker ();
         if (ec) {
            wlog ("Peer keepalive ticked sooner than expected: ${m}", ("m", ec.message()));
         }
         for (auto &c : connections ) {
            if (c->socket->is_open()) {
               c->send_time();
            }
         }
      });
   }

   bool ibc_plugin_impl::authenticate_peer(const handshake_message& msg) const {
      if(allowed_connections == None)
         return false;

      if(allowed_connections == Any)
         return true;

      if(allowed_connections == Specified) {
         auto allowed_it = std::find(allowed_peers.begin(), allowed_peers.end(), msg.key);
         auto private_it = private_keys.find(msg.key);

         if( allowed_it == allowed_peers.end() && private_it == private_keys.end() ) {
            elog( "Peer ${peer} sent a handshake with an unauthorized key: ${key}.",
                  ("peer", msg.p2p_address)("key", msg.key));
            return false;
         }
      }

      namespace sc = std::chrono;
      sc::system_clock::duration msg_time(msg.time);
      auto time = sc::system_clock::now().time_since_epoch();
      if(time - msg_time > peer_authentication_interval) {
         elog( "Peer ${peer} sent a handshake with a timestamp skewed by more than ${time}.",
               ("peer", msg.p2p_address)("time", "1 second")); // TODO Add to_variant for std::chrono::system_clock::duration
         return false;
      }

      if(msg.sig != chain::signature_type() && msg.token != sha256()) {
         sha256 hash = fc::sha256::hash(msg.time);
         if(hash != msg.token) {
            elog( "Peer ${peer} sent a handshake with an invalid token.",
                  ("peer", msg.p2p_address));
            return false;
         }
         chain::public_key_type peer_key;
         try {
            peer_key = crypto::public_key(msg.sig, msg.token, true);
         }
         catch (fc::exception& /*e*/) {
            elog( "Peer ${peer} sent a handshake with an unrecoverable key.",
                  ("peer", msg.p2p_address));
            return false;
         }
         if((allowed_connections & Specified) && peer_key != msg.key) {
            elog( "Peer ${peer} sent a handshake with an unauthenticated key.",
                  ("peer", msg.p2p_address));
            return false;
         }
      }
      else if(allowed_connections & Specified) {
         dlog( "Peer sent a handshake with blank signature and token, but this node accepts only authenticated connections.");
         return false;
      }
      return true;
   }

   chain::public_key_type ibc_plugin_impl::get_authentication_key() const {
      if(!private_keys.empty())
         return private_keys.begin()->first;
      return chain::public_key_type();
   }

   chain::signature_type ibc_plugin_impl::sign_compact(const chain::public_key_type& signer, const fc::sha256& digest) const {
      auto private_key_itr = private_keys.find(signer);
      if(private_key_itr != private_keys.end())
         return private_key_itr->second.sign(digest);
      return chain::signature_type();
   }

   connection_ptr ibc_plugin_impl::find_connection( string host )const {
      for( const auto& c : connections )
         if( c->peer_addr == host ) return c;
      return connection_ptr();
   }
   
   //--------------- handshake_initializer ---------------
   void handshake_initializer::populate( handshake_message &hello) {
      hello.network_version = net_version;
      hello.chain_id = my_impl->chain_id;
      hello.node_id = my_impl->node_id;
      hello.key = my_impl->get_authentication_key();
      hello.time = std::chrono::system_clock::now().time_since_epoch().count();
      hello.token = fc::sha256::hash(hello.time);
      hello.sig = my_impl->sign_compact(hello.key, hello.token);
      // If we couldn't sign, don't send a token.
      if(hello.sig == chain::signature_type())
         hello.token = sha256();
      hello.p2p_address = my_impl->p2p_address + " - " + hello.node_id.str().substr(0,7);
#if defined( __APPLE__ )
      hello.os = "osx";
#elif defined( __linux__ )
      hello.os = "linux";
#elif defined( _MSC_VER )
      hello.os = "win32";
#else
      hello.os = "other";
#endif
      hello.agent = my_impl->user_agent_name;

      controller& cc = my_impl->chain_plug->chain();
      hello.head_id = fc::sha256();
      hello.last_irreversible_block_id = fc::sha256();
      hello.head_num = cc.fork_db_head_block_num();
      hello.last_irreversible_block_num = cc.last_irreversible_block_num();
      if( hello.last_irreversible_block_num ) {
         try {
            hello.last_irreversible_block_id = cc.get_block_id_for_num(hello.last_irreversible_block_num);
         }
         catch( const unknown_block_exception &ex) {
            ilog("caught unkown_block");
            hello.last_irreversible_block_num = 0;
         }
      }
      if( hello.head_num ) {
         try {
            hello.head_id = cc.get_block_id_for_num( hello.head_num );
         }
         catch( const unknown_block_exception &ex) {
            hello.head_num = 0;
         }
      }
   }


   //--------------- ibc_plugin ---------------
   ibc_plugin::ibc_plugin()
      :my( new ibc_plugin_impl ) {
      my_impl = my.get();
   }

   ibc_plugin::~ibc_plugin() {
   }

   void ibc_plugin::set_program_options( options_description& /*cli*/, options_description& cfg )
   {
      cfg.add_options()
         ( "ibc-chain-contract", bpo::value<string>(), "Name of this chain's ibc chain contract")
         ( "ibc-token-contract", bpo::value<string>(), "Name of this chain's ibc token contract")
         ( "ibc-relay-name", bpo::value<string>(), "ID of relay controlled by this node (e.g. relayone)")
         ( "ibc-relay-private-key", bpo::value<string>(),
           "Key=Value pairs in the form <public-key>=KEY:<private-key>\n"
           "   <public-key>   \tis a string form of a vaild EOSIO public key\n\n"
           "   <private-key>  \tis a string form of a valid EOSIO private key which maps to the provided public key\n\n")

         ( "ibc-listen-endpoint", bpo::value<string>()->default_value( "0.0.0.0:5678" ), "The actual host:port used to listen for incoming ibc connections.")
         ( "ibc-server-address", bpo::value<string>(), "An externally accessible host:port for identifying this node. Defaults to ibc-listen-endpoint.")
         ( "ibc-sidechain-id", bpo::value<string>(), "The sidechain's chain id")
         ( "ibc-peer-address", bpo::value< vector<string> >()->composing(), "The public endpoint of a peer node to connect to. Use multiple ibc-peer-address options as needed to compose a network.")
         ( "ibc-max-nodes-per-host", bpo::value<int>()->default_value(def_max_nodes_per_host), "Maximum number of client nodes from any single IP address")
         ( "ibc-allowed-connection", bpo::value<vector<string>>()->multitoken()->default_value({"any"}, "any"), "Can be 'any' or 'specified' or 'none'. If 'specified', peer-key must be specified at least once.")
         ( "ibc-peer-key", bpo::value<vector<string>>()->composing()->multitoken(), "Optional public key of peer allowed to connect.  May be used multiple times.")
         ( "ibc-agent-name", bpo::value<string>()->default_value("\"EOSIO IBC Agent\""), "The name supplied to identify this node amongst the peers.")
         ( "ibc-peer-private-key", bpo::value<vector<string>>()->composing()->multitoken(),
           "Key=Value pairs in the form <public-key>=KEY:<private-key>\n"
           "   <public-key>   \tis a string form of a vaild EOSIO public key\n\n"
           "   <private-key>  \tis a string form of a valid EOSIO private key which maps to the provided public key\n\n")
         ( "ibc-max-clients", bpo::value<int>()->default_value(def_max_clients), "Maximum number of clients from which connections are accepted, use 0 for no limit")
         ( "ibc-connection-cleanup-period", bpo::value<int>()->default_value(def_conn_retry_wait), "Number of seconds to wait before cleaning up dead connections")
         ( "ibc-max-cleanup-time-msec", bpo::value<int>()->default_value(10), "Maximum connection cleanup time per cleanup call in millisec")
         ( "ibc-version-match", bpo::value<bool>()->default_value(false), "True to require exact match of ibc plugin version.")

         ( "ibc-log-format", bpo::value<string>()->default_value( "[\"${_name}\" ${_ip}:${_port}]" ),
           "The string used to format peers when logging messages about them.  Variables are escaped with ${<variable name>}.\n"
           "Available Variables:\n"
           "   _name  \tself-reported name\n\n"
           "   _id    \tself-reported ID (64 hex characters)\n\n"
           "   _sid   \tfirst 8 characters of _peer.id\n\n"
           "   _ip    \tremote IP address of peer\n\n"
           "   _port  \tremote port number of peer\n\n"
           "   _lip   \tlocal IP address connected to peer\n\n"
           "   _lport \tlocal port number connected to peer\n\n")
         ;
   }

   template<typename T>
   T dejsonify(const string& s) {
      return fc::json::from_string(s).as<T>();
   }

#define OPTION_ASSERT( option ) EOS_ASSERT( options.count( option ) && options.at( option ).as<string>() != string(), chain::plugin_config_exception, option " not specified" );

   void ibc_plugin::plugin_initialize( const variables_map& options ) {
      ilog("Initialize ibc plugin");
      try {
         peer_log_format = options.at( "ibc-log-format" ).as<string>();

         my->network_version_match = options.at( "ibc-version-match" ).as<bool>();

         OPTION_ASSERT( "ibc-sidechain-id" )
         my->sidechain_id = fc::sha256( options.at( "ibc-sidechain-id" ).as<string>() );
         ilog( "ibc sidechain id is ${id}", ("id",  my->sidechain_id.str()));

         OPTION_ASSERT( "ibc-chain-contract" )
         my->chain_contract.reset( new ibc_chain_contract( eosio::chain::name{ options.at("ibc-chain-contract").as<string>()}));
         ilog( "ibc chain contract account is ${name}", ("name",  options.at("ibc-chain-contract").as<string>()));

         OPTION_ASSERT( "ibc-token-contract" )
         my->token_contract.reset( new ibc_token_contract( eosio::chain::name{ options.at("ibc-token-contract").as<string>()}));
         ilog( "ibc token contract account is ${name}", ("name",  options.at("ibc-token-contract").as<string>()));

         OPTION_ASSERT( "ibc-relay-name" )
         my->relay = eosio::chain::name{ options.at("ibc-relay-name").as<string>() };
         ilog( "ibc relay account is ${name}", ("name",  options.at("ibc-relay-name").as<string>()));

         auto get_key = [=]( string key_spec_pair ) -> std::pair<public_key_type,private_key_type> {
            auto delim = key_spec_pair.find("=");
            EOS_ASSERT(delim != std::string::npos, plugin_config_exception, "Missing \"=\" in the key spec pair");
            auto pub_key_str = key_spec_pair.substr(0, delim);
            auto spec_str = key_spec_pair.substr(delim + 1);

            auto spec_delim = spec_str.find(":");
            EOS_ASSERT(spec_delim != std::string::npos, plugin_config_exception, "Missing \":\" in the key spec pair");
            auto spec_type_str = spec_str.substr(0, spec_delim);
            auto spec_data = spec_str.substr(spec_delim + 1);

            return std::make_pair( public_key_type(pub_key_str), private_key_type(spec_data) );
         };

         OPTION_ASSERT( "ibc-relay-private-key" )
         const auto& key_spec_pair = options.at("ibc-relay-private-key").as<string>();
         try {
            auto key = get_key( key_spec_pair );
            my->relay_private_key = key.second;
            ilog( "ibc relay public key is ${key}", ("key", key.first));
         } catch (...) {
            EOS_ASSERT( false, chain::plugin_config_exception, "Malformed ibc-relay-private-key: \"${val}\"", ("val", key_spec_pair));
         }

         my->connector_period = std::chrono::seconds( options.at( "ibc-connection-cleanup-period" ).as<int>());
         my->max_cleanup_time_ms = options.at("ibc-max-cleanup-time-msec").as<int>();
         my->max_client_count = options.at( "ibc-max-clients" ).as<int>();
         my->max_nodes_per_host = options.at( "ibc-max-nodes-per-host" ).as<int>();
         my->num_clients = 0;
         my->started_sessions = 0;

         my->resolver = std::make_shared<tcp::resolver>( std::ref( app().get_io_service()));

         if( options.count( "ibc-listen-endpoint" )) {
            my->p2p_address = options.at( "ibc-listen-endpoint" ).as<string>();
            auto host = my->p2p_address.substr( 0, my->p2p_address.find( ':' ));
            auto port = my->p2p_address.substr( host.size() + 1, my->p2p_address.size());
            ilog("ibc listen endpoint is ${h}:${p}",("h", host )("p", port));
            tcp::resolver::query query( tcp::v4(), host.c_str(), port.c_str());

            my->listen_endpoint = *my->resolver->resolve( query );
            my->acceptor.reset( new tcp::acceptor( app().get_io_service()));
         }

         if( options.count( "ibc-server-address" )) {
            my->p2p_address = options.at( "ibc-server-address" ).as<string>();
         } else {
            if( my->listen_endpoint.address().to_v4() == address_v4::any()) {
               boost::system::error_code ec;
               auto host = host_name( ec );
               if( ec.value() != boost::system::errc::success ) {
                  FC_THROW_EXCEPTION( fc::invalid_arg_exception, "Unable to retrieve host_name. ${msg}", ("msg", ec.message()));
               }
               auto port = my->p2p_address.substr( my->p2p_address.find( ':' ), my->p2p_address.size());
               my->p2p_address = host + port;
            }
         }

         if( options.count( "ibc-peer-address" )) {
            my->supplied_peers = options.at( "ibc-peer-address" ).as<vector<string> >();
         }

         if( options.count( "ibc-agent-name" )) {
            my->user_agent_name = options.at( "ibc-agent-name" ).as<string>();
         }

         if( options.count( "ibc-allowed-connection" )) {
            const std::vector<std::string> allowed_remotes = options["ibc-allowed-connection"].as<std::vector<std::string>>();
            for( const std::string& allowed_remote : allowed_remotes ) {
               if( allowed_remote == "any" )
                  my->allowed_connections |= ibc_plugin_impl::Any;
               else if( allowed_remote == "specified" )
                  my->allowed_connections |= ibc_plugin_impl::Specified;
               else if( allowed_remote == "none" )
                  my->allowed_connections = ibc_plugin_impl::None;
            }
         }

         if( my->allowed_connections & ibc_plugin_impl::Specified )
            EOS_ASSERT( options.count( "ibc-peer-key" ), plugin_config_exception,
                        "At least one ibc-peer-key must accompany 'ibc-allowed-connection=specified'" );

         if( options.count( "ibc-peer-key" )) {
            const std::vector<std::string> key_strings = options["ibc-peer-key"].as<std::vector<std::string>>();
            for( const std::string& key_string : key_strings ) {
               my->allowed_peers.push_back( dejsonify<chain::public_key_type>( key_string ));
            }
         }

         if( options.count("ibc-peer_private-key") ) {
            const std::vector<std::string> key_spec_pairs = options["ibc-peer-private-key"].as<std::vector<std::string>>();
            for (const auto& key_spec_pair : key_spec_pairs) {
               try {
                  auto key = get_key( key_spec_pair );
                  my->private_keys[key.first] = key.second;
               } catch (...) {
                  elog("Malformed ibc-peer-private-key: \"${val}\", ignoring!", ("val", key_spec_pair));
               }
            }
         }

         my->chain_plug = app().find_plugin<chain_plugin>();
         EOS_ASSERT( my->chain_plug, chain::missing_chain_plugin_exception, "" );
         my->chain_id = app().get_plugin<chain_plugin>().get_chain_id();

         fc::rand_pseudo_bytes( my->node_id.data(), my->node_id.data_size());

         my->keepalive_timer.reset( new boost::asio::steady_timer( app().get_io_service()));
         my->ticker();
      } FC_LOG_AND_RETHROW()
   }

   void ibc_plugin::plugin_startup() {
      if( my->acceptor ) {
         my->acceptor->open(my->listen_endpoint.protocol());
         my->acceptor->set_option(tcp::acceptor::reuse_address(true));
         try {
            my->acceptor->bind(my->listen_endpoint);
         } catch (const std::exception& e) {
            ilog("ibc_plugin::plugin_startup failed to bind to port ${port}", ("port", my->listen_endpoint.port()));
            throw e;
         }
         my->acceptor->listen();
         ilog("starting ibc plugin listener, max clients is ${mc}",("mc",my->max_client_count));
         my->start_listen_loop();
      }
      chain::controller&cc = my->chain_plug->chain();
      cc.irreversible_block.connect( boost::bind(&ibc_plugin_impl::irreversible_block, my.get(), _1));

      my->start_monitors();

      for( auto seed_node : my->supplied_peers ) {
         connect( seed_node );
      }

      if(fc::get_logger_map().find(logger_name) != fc::get_logger_map().end())
         logger = fc::get_logger_map()[logger_name];
   }

   void ibc_plugin::plugin_shutdown() {
      try {
         ilog( "shutdown.." );
         my->done = true;
         if( my->acceptor ) {
            ilog( "close acceptor" );
            my->acceptor->close();

            ilog( "close ${s} connections",( "s",my->connections.size()) );
            auto cons = my->connections;
            for( auto con : cons ) {
               my->close( con);
            }

            my->acceptor.reset(nullptr);
         }
         ilog( "exit shutdown" );
      }
      FC_CAPTURE_AND_RETHROW()
   }

   size_t ibc_plugin::num_peers() const {
      return my->count_open_sockets();
   }

   /**
    *  Used to trigger a new connection from RPC API
    */
   string ibc_plugin::connect( const string& host ) {
      if( my->find_connection( host ) )
         return "already connected";

      connection_ptr c = std::make_shared<connection>(host);
      fc_dlog(logger,"adding new connection to the list");
      my->connections.insert( c );
      fc_dlog(logger,"calling active connector");
      my->connect( c );
      return "added connection";
   }

   string ibc_plugin::disconnect( const string& host ) {
      for( auto itr = my->connections.begin(); itr != my->connections.end(); ++itr ) {
         if( (*itr)->peer_addr == host ) {
            (*itr)->reset();
            my->close(*itr);
            my->connections.erase(itr);
            return "connection removed";
         }
      }
      return "no known connection for host";
   }

   optional<connection_status> ibc_plugin::status( const string& host )const {
      auto con = my->find_connection( host );
      if( con )
         return con->get_status();
      return optional<connection_status>();
   }

   vector<connection_status> ibc_plugin::connections()const {
      vector<connection_status> result;
      result.reserve( my->connections.size() );
      for( const auto& c : my->connections ) {
         result.push_back( c->get_status() );
      }
      return result;
   }

}}
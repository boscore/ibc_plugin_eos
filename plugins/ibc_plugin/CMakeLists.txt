file(GLOB HEADERS "include/eosio/ibc_plugin/*.hpp" )
add_library( ibc_plugin
             ibc_plugin.cpp
             ${HEADERS} )

target_link_libraries( ibc_plugin chain_plugin producer_plugin appbase fc )
target_include_directories( ibc_plugin PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/../chain_interface/include  "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/appbase/include")

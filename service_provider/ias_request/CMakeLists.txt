
set(IAS_HTTP__IAS_REQUEST ias_request.h ias_request.cpp)
set(IAS_HTTP__AGENT agent.h agent_wget.h agent_wget.cpp)

include_directories(./httpparser)
add_library(ias_request ${IAS_HTTP__IAS_REQUEST} ${IAS_HTTP__AGENT} ${IAS_HTTP__HTTP_PARSER})
#target_link_libraries(ias_request)
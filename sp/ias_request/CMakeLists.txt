
set(IAS_HTTP__IAS_REQUEST ias_request.h ias_request.cpp)
set(IAS_HTTP__AGENT agent.h agent_wget.h agent_wget.cpp)
set(IAS_HTTP__HTTP_PARSER ./httpparser/response.h ./httpparser/httpresponseparser.h ../key_exchange_message/key_exchange_message.h)
include_directories(./httpparser)

add_library(ias_request ${IAS_HTTP__IAS_REQUEST} ${IAS_HTTP__AGENT} ${IAS_HTTP__HTTP_PARSER})

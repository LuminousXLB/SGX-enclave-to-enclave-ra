
add_library(ias_http app.h app.cpp)
target_link_libraries(ias_http PRIVATE curl)
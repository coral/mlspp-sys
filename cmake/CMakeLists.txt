cmake_minimum_required(VERSION 3.13)
project(mlspp-sys-build LANGUAGES CXX)

# Propagate options to mlspp
option(TESTING "Build tests" OFF)
option(DISABLE_GREASE "Disable GREASE values" OFF)

# Disable testing in nlohmann_json
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)
set(JSON_MultipleHeaders OFF CACHE BOOL "" FORCE)

# Add nlohmann_json first so its target is available
add_subdirectory(
  ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/json
  ${CMAKE_CURRENT_BINARY_DIR}/json
  EXCLUDE_FROM_ALL
)

# Mark nlohmann_json as found so that find_package() calls inside mlspp
# (in both the main CMakeLists.txt and lib/hpke/CMakeLists.txt) succeed
# without needing an installed package config file.
set(nlohmann_json_FOUND TRUE CACHE BOOL "" FORCE)

# Define a macro that overrides find_package for nlohmann_json only.
# This is needed because mlspp sub-projects call find_package(nlohmann_json REQUIRED)
# but the target already exists from add_subdirectory above.
macro(find_package)
  if("${ARGV0}" STREQUAL "nlohmann_json")
    # Already available via add_subdirectory - skip
  else()
    _find_package(${ARGV})
  endif()
endmacro()

# Add mlspp (which depends on nlohmann_json::nlohmann_json)
add_subdirectory(
  ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/mlspp
  ${CMAKE_CURRENT_BINARY_DIR}/mlspp
)

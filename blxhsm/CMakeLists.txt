# CMake 最低版本号要求
cmake_minimum_required (VERSION 2.8)

# 项目信息
project (blxhsm)

add_definitions(-DUNICODE -D_UNICODE)

# 查找当前目录下的所有源文件
# 并将名称保存到 src 变量
aux_source_directory(. src)

FILE(GLOB_RECURSE HeaderFiles "./*.h")

FILE(GLOB_RECURSE DefFile "./*.def")


#Win + VS环境下,会自动在设置的目录后面扩展一层 <CONFIG> 目录,所以最终生成的Debug版本库会在 ${PROJECT_SOURCE_DIR}/../lib/Debug 目录下,
#Release版本库会在 ${PROJECT_SOURCE_DIR}/../lib/Release 目录下
#Linux + GCC环境下,无论是Debug还是Release,生成的库文件会直接放在你所设置的目录下,不会有差异
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/../bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/../bin)

#设置Debug版本和Release版本可执行文件的输出目录,
#一旦设置上面的属性,在任何环境下生成的可执行文件都将直接放在你所设置的目录
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${PROJECT_SOURCE_DIR}/../bin)
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${PROJECT_SOURCE_DIR}/../bin)

#设置了Debug版本和Release版本库文件的输出目录
#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${PROJECT_SOURCE_DIR}/../lib)
#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${PROJECT_SOURCE_DIR}/../lib)

# 指定生成目标
add_library(blxhsm SHARED ${src} ${HeaderFiles} ${DefFile}) 
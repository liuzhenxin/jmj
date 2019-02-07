#声明要求的cmake最低版本
cmake_minimum_required( VERSION 2.8 )
 
#声明一个cmake工程
project( APITEST )

set(CMAKE_MFC_FLAG 2)

add_definitions(-D_AFXDLL)
# 查找当前目录下的所有源文件
# 并将名称保存到 src 变量
aux_source_directory(. src)

FILE(GLOB_RECURSE HeaderFiles "./*.h")

FILE(GLOB_RECURSE CommonHeaderFiles "../Common/*.h")

FILE(GLOB RC_FILES "./*.rc")

FILE(GLOB_RECURSE INIFile "../Common/IniFile.cpp")

include_directories(../Common)

#Win + VS环境下,会自动在设置的目录后面扩展一层 <CONFIG> 目录,所以最终生成的Debug版本库会在 ${PROJECT_SOURCE_DIR}/../lib/Debug 目录下,
#Release版本库会在 ${PROJECT_SOURCE_DIR}/../lib/Release 目录下
#Linux + GCC环境下,无论是Debug还是Release,生成的库文件会直接放在你所设置的目录下,不会有差异
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/../bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/../bin)


include_directories(../include)
link_directories(../../lib)

#添加一个可执行程序
#语法：add_executable( 程序名 源代码文件 ）
add_executable( APITEST ${src} ${HeaderFiles} ${CommonHeaderFiles} ${INIFile} ${RC_FILES})

set_target_properties(APITEST PROPERTIES LINK_FLAGS "/SUBSYSTEM:WINDOWS")

#将可执行程序链接到库
#语法：target_link_libraries ( 程序名 库名称 ）
target_link_libraries ( APITEST blxhsm )
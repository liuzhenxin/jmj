# CMake 最低版本号要求
cmake_minimum_required (VERSION 2.8)

# 项目信息
project (blxhsm)

# 查找当前目录下的所有源文件
# 并将名称保存到 src 变量
aux_source_directory(. src)

aux_header_directory(. header)

#add_subdirectory(../Common)

#aux_source_directory(../Common srcCommon)

# 指定生成目标
add_library(blxhsm SHARED ${src}) 
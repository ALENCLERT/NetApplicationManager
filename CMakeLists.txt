cmake_minimum_required(VERSION 3.5)

project(NetApplicationManager LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# QtCreator supports the following variables for Android, which are identical to qmake Android variables.
# Check http://doc.qt.io/qt-5/deployment-android.html for more information.
# They need to be set before the find_package(Qt5 ...) call.

#if(ANDROID)
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
#    if (ANDROID_ABI STREQUAL "armeabi-v7a")
#        set(ANDROID_EXTRA_LIBS
#            ${CMAKE_CURRENT_SOURCE_DIR}/path/to/libcrypto.so
#            ${CMAKE_CURRENT_SOURCE_DIR}/path/to/libssl.so)
#    endif()
#endif()

find_package(Qt5 COMPONENTS Widgets REQUIRED)

# 设置Qt资源文件
set(RESOURCES resource.qrc)

# 使用Qt的资源处理器将.qrc文件转换成对应的C++代码
qt5_add_resources(RESOURCES_CPP ${RESOURCES})


if(ANDROID)
  add_library(NetApplicationManager SHARED
    main.cpp
  )
else()
  add_executable(NetApplicationManager
    main.cpp
    ${RESOURCES_CPP}
  )
endif()

target_link_libraries(NetApplicationManager PRIVATE Psapi)
target_link_libraries(NetApplicationManager PRIVATE Qt5::Widgets)

cmake_minimum_required(VERSION 3.22)

project(AnomalyCameraBlurFix LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Camera Blur Fix targets Windows x64")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(AnomalySDK CONFIG REQUIRED)

anomaly_add_plugin(anomaly_camera_blur_fix
    SOURCES plugin.cpp
    MANIFEST manifest.json
    PACKAGE_NAME CameraBlurFix)

target_compile_definitions(anomaly_camera_blur_fix PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

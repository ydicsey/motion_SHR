add_executable(motiontest
        test_aesni.cpp
        test_aby_format.cpp
        test_agmw.cpp
        test_astra.cpp
        test_base_ot.cpp
        test_bgmw.cpp
        test_bitmatrix.cpp
        test_bitvector.cpp
        test_bmr.cpp
        test_boolean_algorithms.cpp
        test_communication_layer.cpp
        test_conversions.cpp
        test_dummy_transport.cpp
        test_float.cpp
        test_fromaby_primitive_performance.cpp
        test_garbled_circuit.cpp
        test_integer_operations.cpp
        test_kk13_ot.cpp
        test_kk13_ot_flavors.cpp
        test_low_depth_reduce.cpp
        test_misc.cpp
        test_party_lifecycle.cpp
        test_motion_main.cpp
        test_mt.cpp
        test_ot.cpp
        test_ot_flavors.cpp
        test_reusable_future.cpp
        test_rng.cpp
        test_sb.cpp
        test_simdify_gate.cpp
        test_sp.cpp
        test_statistics.cpp
        test_subset_gate.cpp
        test_tcp_transport.cpp
        test_thread_pool_configuration.cpp
        test_unsimdify_gate.cpp
        )

target_link_libraries(motiontest PRIVATE
        MOTION::motion
        OpenMP::OpenMP_CXX
        gtest dl
        )


if (MSVC)
    target_compile_options(motiontest PRIVATE /FI"${CMAKE_CURRENT_SOURCE_DIR}/test_gtest_extensions.h")
else ()
    target_compile_options(motiontest PRIVATE -include "${CMAKE_CURRENT_SOURCE_DIR}/test_gtest_extensions.h")
endif ()


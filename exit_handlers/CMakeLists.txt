
list(APPEND ARGN
)

do_test(test_vic
    SOURCES test_vmcall.cpp
    ${ARGN}
)

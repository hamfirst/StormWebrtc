#pragma once

#include <type_traits>

template <class M, class T>
struct match_ref
{
  using type = typename std::conditional_t<
    std::is_reference<M>::value,
    typename std::add_lvalue_reference_t<T>,
    typename std::remove_reference_t<T>
  >;
};

template <class M, class T>
using match_ref_t = typename match_ref<M, T>::type;
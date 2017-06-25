#pragma once

#include <type_traits>

#include "match_ref.h"

template <class M, class T>
struct match_const
{
  using type = typename std::conditional_t<
    std::is_const<typename std::remove_reference_t<M>>::value,
    match_ref_t<T, typename std::add_const_t<typename std::remove_reference_t<T>>>,
    match_ref_t<T, typename std::remove_const_t<typename std::remove_reference_t<T>>>
  >;
};

template <class M, class T>
using match_const_t = typename match_const<M, T>::type;
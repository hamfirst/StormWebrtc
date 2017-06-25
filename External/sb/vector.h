#pragma once

#include <vector>
#include <algorithm>

template <class T>
bool vremove_ordered(std::vector<T> & vec, const T & elem)
{
  auto itr = std::find(vec.begin(), vec.end(), elem);
  if (itr != vec.end())
  {
    vec.erase(itr);
    return true;
  }

  return false;
}

template <class T>
bool vremove_quick(std::vector<T> & vec, const T & elem)
{
  auto itr = std::find(vec.begin(), vec.end(), elem);
  if (itr != vec.end()) 
  {
    std::iter_swap(itr, vec.end() - 1);
    vec.erase(vec.end() - 1);
    return true;
  }

  return false;
}

template <class T>
bool vremove_index_quick(std::vector<T> & vec, std::size_t index)
{
  auto itr = vec.begin() + index;
  if (itr != vec.end())
  {
    std::iter_swap(itr, vec.end() - 1);
    vec.erase(vec.end() - 1);
    return true;
  }

  return false;
}

template <class T>
bool vfind(const std::vector<T> & vec, const T & elem)
{
  auto itr = std::find(vec.begin(), vec.end(), elem);
  return (itr != vec.end());
}

template <class T>
int vfind_index(const std::vector<T> & vec, const T & elem)
{
  for (std::size_t index = 0, end = vec.size(); index < end; ++index)
  {
    if (vec[index] == elem)
    {
      return (int)index;
    }
  }

  return -1;
}

template <class T>
void vrearrange(std::vector<T> & vec, int src_index, int target_index)
{
  T val = std::move(vec[src_index]);

  vec.erase(vec.begin() + src_index);
  vec.emplace(vec.begin() + target_index, std::move(val));
}


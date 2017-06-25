#pragma once

#include <cstdlib>
#include <cstdint>

#include <bitset>

template <typename Type, std::size_t MaxAllocs>
class FixedSizedArrayAlloc
{
public:

  static_assert(sizeof(Type) >= sizeof(void *), "Allocation type is too small to alias with a pointer");
  static_assert(MaxAllocs > 0, "Cannot have an allocator with 0 elements");

  FixedSizedArrayAlloc()
  {

  }

  ~FixedSizedArrayAlloc()
  {
    for (std::size_t index = 0; index < MaxAllocs; index++)
    {
      if (m_AllocMask[index])
      {
        GetAllocAt(index)->~Type();
      }
    }
  }

  FixedSizedArrayAlloc(const FixedSizedArrayAlloc & rhs) = delete;
  FixedSizedArrayAlloc(FixedSizedArrayAlloc && rhs) = delete;

  FixedSizedArrayAlloc & operator = (const FixedSizedArrayAlloc & rhs) = delete;
  FixedSizedArrayAlloc & operator = (FixedSizedArrayAlloc && rhs) = delete;

  template <typename ... InitArgs>
  Type * Allocate(std::size_t index, InitArgs && ... args)
  {
    void * ptr = AllocateRaw(index);

    try
    {
      Type * t = new (ptr) Type(std::forward<InitArgs>(args)...);
      return t;
    }
    catch (...)
    {
      FreeRaw(ptr);
      throw;
    }
  }

  void * AllocateRaw(std::size_t index)
  {
    if (index >= MaxAllocs)
    {
      throw false;
    }

    if (m_AllocMask[index])
    {
      throw false;
    }

    m_AllocMask.set(index);
    return GetPtrAt(index);
  }

  void Free(Type * type)
  {
    type->~Type();
    FreeRaw(type);
  }

  void FreeRaw(void * ptr)
  {
    std::size_t index = GetIndexAt(ptr);
    FreeRaw(index);
  }

  void FreeRaw(std::size_t index)
  {
    if (m_AllocMask[index] == false)
    {
      throw false;
    }

    m_AllocMask.set(index, false);
  }

  std::size_t GetAllocationId(Type * ptr)
  {
    return GetIndexAt(ptr);
  }

  Type * GetElementForId(std::size_t id)
  {
    if (id >= MaxAllocs)
    {
      return nullptr;
    }

    if (m_AllocMask[id] == false)
    {
      return nullptr;
    }

    return GetAllocAt(id);
  }

private:
  Type * GetAllocAt(std::size_t index)
  {
    if (index >= MaxAllocs)
    {
      throw false;
    }

    return reinterpret_cast<Type *>(&m_Memory[sizeof(Type) * index]);
  }

  void ** GetPtrAt(std::size_t index)
  {
    if (index >= MaxAllocs)
    {
      throw false;
    }

    return reinterpret_cast<void **>(&m_Memory[sizeof(Type) * index]);
  }

  std::size_t GetIndexAt(void * ptr)
  {
    Type * t = reinterpret_cast<Type *>(ptr);

    std::size_t index = static_cast<std::size_t>(t - GetAllocAt(0));
    if (index >= MaxAllocs)
    {
      throw false;
    }

    return index;
  }

private:
  std::bitset<MaxAllocs> m_AllocMask;
  uint8_t m_Memory[sizeof(Type) * MaxAllocs];
};

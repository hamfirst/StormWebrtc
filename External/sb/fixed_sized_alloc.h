#pragma once

#include <cstdlib>
#include <cstdint>

#include <bitset>

template <typename Type, std::size_t MaxAllocs>
class FixedSizedAlloc
{
public:

  static_assert(sizeof(Type) >= sizeof(void *), "Allocation type is too small to alias with a pointer");
  static_assert(MaxAllocs > 0, "Cannot have an allocator with 0 elements");

  FixedSizedAlloc()
  {
    for (std::size_t index = 0; index < MaxAllocs - 1; index++)
    {
      *GetPtrAt(index) = GetAllocAt(index + 1);
    }

    *GetPtrAt(MaxAllocs - 1) = nullptr;
    m_Head = GetPtrAt(0);
  }

  ~FixedSizedAlloc()
  {
    for (std::size_t index = 0; index < MaxAllocs; index++)
    {
      if (m_AllocMask[index])
      {
        GetAllocAt(index)->~Type();
      }
    }
  }

  FixedSizedAlloc(const FixedSizedAlloc & rhs) = delete;
  FixedSizedAlloc(FixedSizedAlloc && rhs) = delete;

  FixedSizedAlloc & operator = (const FixedSizedAlloc & rhs) = delete;
  FixedSizedAlloc & operator = (FixedSizedAlloc && rhs) = delete;

  template <typename ... InitArgs>
  Type * Allocate(InitArgs && ... args)
  {
    void * ptr = AllocateRaw();

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

  void * AllocateRaw()
  {
    if (m_Head == nullptr)
    {
      throw false;
    }

    std::size_t index = GetIndexAt(m_Head);

    if (m_AllocMask[index])
    {
      throw false;
    }

    void * t = m_Head;

    void ** head_ptr = reinterpret_cast<void **>(m_Head);
    void * new_head = *head_ptr;

    m_AllocMask.set(index);
    m_Head = new_head;

    return t;
  }

  void Free(Type * type)
  {
    type->~Type();
    FreeRaw(type);
  }

  void FreeRaw(void * ptr)
  {
    std::size_t index = GetIndexAt(ptr);
    if (m_AllocMask[index] == false)
    {
      throw false;
    }

    m_AllocMask.set(index, false);

    void ** head_ptr = reinterpret_cast<void **>(ptr);
    *head_ptr = m_Head;

    m_Head = ptr;
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
  void * m_Head;
  std::bitset<MaxAllocs> m_AllocMask;
  uint8_t m_Memory[sizeof(Type) * MaxAllocs];
};

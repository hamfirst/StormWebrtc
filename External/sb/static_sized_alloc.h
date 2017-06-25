#pragma once

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <utility>

template <typename Type>
class StaticSizedAlloc
{
public:
  StaticSizedAlloc(std::size_t max_allocs) :
    m_MaxAllocs(max_allocs)
  {
    if (max_allocs == 0)
    {
      throw false;
    }

    m_Memory = static_cast<uint8_t *>(malloc(sizeof(Type) * m_MaxAllocs));

    std::size_t alloc_mask_size = (m_MaxAllocs + 7) / 8;
    m_AllocMask = static_cast<uint8_t *>(malloc(alloc_mask_size));

    memset(m_AllocMask, 0, alloc_mask_size);

    for (std::size_t index = 0; index < m_MaxAllocs - 1; index++)
    {
      *GetPtrAt(index) = GetAllocAt(index + 1);
    }

    *GetPtrAt(m_MaxAllocs - 1) = nullptr;
    m_Head = GetPtrAt(0);
  }

  StaticSizedAlloc(std::size_t max_allocs, const StaticSizedAlloc<Type> & to_copy) :
  {
    if (max_allocs == 0)
    {
      throw false;
    }

    m_Memory = static_cast<uint8_t *>(malloc(sizeof(Type) * m_MaxAllocs));

    std::size_t alloc_mask_size = (m_MaxAllocs + 7) / 8;
    m_AllocMask = static_cast<uint8_t *>(malloc(alloc_mask_size));

    m_AllocMask[0] = to_copy.m_AllocMask[0];

    for (std::size_t index = 0, byte = 0, bit = 0; index < to_copy.m_MaxAllocs; ++index, ++bit)
    {
      if (bit == 8)
      {
        bit = 0;
        byte++;

        m_AllocMask[byte] = to_copy.m_AllocMask[byte];
      }

      if ((to_copy.m_AllocMask[byte] & (1 << bit)) != 0)
      {
        new (GetAllocAt(index)) Type(*to_copy.GetAllocAt());
      }
    }

    int my_bytes = (m_MaxAllocs + 7) / 8;
    int to_copy_bytes = (to_copy.m_MaxAllocs + 7) / 8;
    if (my_bytes > to_copy_bytes)
    {
      memset(&m_AllocMask[to_copy_bytes], 0, my_bytes - to_copy_bytes);
    }

    m_Head = nullptr;
    for (int index = m_MaxAllocs - 1, byte = (m_MaxAllocs - 1) / 8, bit = (m_MaxAllocs - 1) % 8; index >= 0; --index, --bit)
    {
      if (bit < 0)
      {
        bit = 7;
        byte--;
      }

      if ((m_AllocMask[byte] & (1 << bit)) == 0)
      {
        auto ptr = GetPtrAt(index);
        *ptr = m_Head;
        m_Head = ptr;
      }
    }
  }

  ~StaticSizedAlloc()
  {
    for (std::size_t index = 0; index < m_MaxAllocs; index++)
    {
      if (GetAllocMask(index))
      {
        GetAllocAt(index)->~Type();
      }
    }

    free(m_Memory);
    free(m_AllocMask);
  }

  StaticSizedAlloc(const StaticSizedAlloc & rhs) = delete;
  StaticSizedAlloc(StaticSizedAlloc && rhs) = delete;

  StaticSizedAlloc & operator = (const StaticSizedAlloc & rhs) = delete;
  StaticSizedAlloc & operator = (StaticSizedAlloc && rhs) = delete;

  void Swap(StaticSizedAlloc<Type> & rhs)
  {
    std::swap(m_MaxAllocs, rhs.m_MaxAllocs);
    std::swap(m_Head, rhs.m_Head);
    std::swap(m_Memory, rhs.m_Memory);
    std::swap(m_AllocMask, rhs.m_AllocMask);
  }

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
    static_assert(sizeof(Type) >= sizeof(void *), "Allocation type is too small to alias with a pointer");

    if (m_Head == nullptr)
    {
      throw false;
    }

    std::size_t index = GetIndexAt(m_Head);

    if (GetAllocMask(index))
    {
      throw false;
    }

    void * t = m_Head;

    void ** head_ptr = reinterpret_cast<void **>(m_Head);
    void * new_head = *head_ptr;

    SetAllocMask(index);
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
    if (GetAllocMask(index) == false)
    {
      throw false;
    }

    UnsetAllocMask(index);

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
    if (id >= m_MaxAllocs)
    {
      return nullptr;
    }

    if (GetAllocMask(id) == false)
    {
      return nullptr;
    }

    return GetAllocAt(id);
  }

  std::size_t GetMaxAllocs()
  {
    return m_MaxAllocs;
  }

private:
  Type * GetAllocAt(std::size_t index)
  {
    if (index >= m_MaxAllocs)
    {
      throw false;
    }

    return reinterpret_cast<Type *>(&m_Memory[sizeof(Type) * index]);
  }

  const Type * GetAllocAt(std::size_t index) const
  {
    if (index >= m_MaxAllocs)
    {
      throw false;
    }

    return reinterpret_cast<Type *>(&m_Memory[sizeof(Type) * index]);
  }

  void ** GetPtrAt(std::size_t index)
  {
    if (index >= m_MaxAllocs)
    {
      throw false;
    }

    return reinterpret_cast<void **>(&m_Memory[sizeof(Type) * index]);
  }

  std::size_t GetIndexAt(void * ptr)
  {
    Type * t = reinterpret_cast<Type *>(ptr);

    std::size_t index = static_cast<std::size_t>(t - GetAllocAt(0));
    if (index >= m_MaxAllocs)
    {
      throw false;
    }

    return index;
  }

  bool GetAllocMask(std::size_t index)
  {
    std::size_t bit = index & 0x7;
    std::size_t byte = index >> 3;

    return (m_AllocMask[byte] & static_cast<uint8_t>(1 << bit)) != 0;
  }

  void SetAllocMask(std::size_t index)
  {
    std::size_t bit = index & 0x7;
    std::size_t byte = index >> 3;

    m_AllocMask[byte] |= static_cast<uint8_t>(1 << bit);
  }

  void UnsetAllocMask(std::size_t index)
  {
    std::size_t bit = index & 0x7;
    std::size_t byte = index >> 3;

    m_AllocMask[byte] &= ~static_cast<uint8_t>(1 << bit);
  }

private:
  std::size_t m_MaxAllocs;
  void * m_Head;
  uint8_t * m_Memory;
  uint8_t * m_AllocMask;
};

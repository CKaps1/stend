#pragma once
#include "secure_alloc.h"
#include <string>

namespace stend
{

	template <typename T> class __Secure_Allocator
	{
	public:
		// Type definitions
		using value_type = T;
		using pointer = T*;
		using const_pointer = const T*;
		using reference = T&;
		using const_reference = const T&;
		using size_type = std::size_t;
		using difference_type = std::ptrdiff_t;

		/**
		 * Allocate memory for N items using the standard allocator.
		 */
		pointer allocate(size_type n)
		{
			return static_cast<pointer>(secure_alloc(n * sizeof(T)));
		}

		/**
		 * Release memory which was allocated for N items at pointer P.
		 *
		 * The memory block is filled with zeroes before being released.
		 * The pointer argument is tagged as "volatile" to prevent the
		 * compiler optimizing out this critical step.
		 */
		void deallocate(volatile pointer p, size_type n)
		{
			secure_free(p);
		}

		/**
		* Construct an item in-place at pointer P.
		*/
		template <typename... Args> void construct(pointer p, Args&&... args)
		{
			// construct using "placement new" and "perfect forwarding"
			::new (static_cast<void*>(p)) T(std::forward<Args>(args)...);
		}

		size_type max_size() const { return size_t(-1) / sizeof(T); }

		pointer address(reference x) const { return std::addressof(x); }

		const_pointer address(const_reference x) const { return std::addressof(x); }

		/**
		 * Destroy an item in-place at pointer P.
		 */
		void destroy(pointer p) {
			// destroy using "explicit destructor"
			p->~T();
		}

		// Boilerplate
		__Secure_Allocator() {}
		template<typename U> __Secure_Allocator(const __Secure_Allocator<U>&) {}
		template<typename U> struct rebind { using other = __Secure_Allocator<U>; };
	};

	typedef std::basic_string<char, std::char_traits<char>, __Secure_Allocator<char>> secure_string;
	typedef std::basic_string<wchar_t, std::char_traits<wchar_t>, __Secure_Allocator<wchar_t>> secure_wstring;
};
/* Policies for result and outcome
(C) 2017-2023 Niall Douglas <http://www.nedproductions.biz/> (13 commits)
File Created: Oct 2017


Boost Software License - Version 1.0 - August 17th, 2003

Permission is hereby granted, free of charge, to any person or organization
obtaining a copy of the software and accompanying documentation covered by
this license (the "Software") to use, reproduce, display, distribute,
execute, and transmit the Software, and to prepare derivative works of the
Software, and to permit third-parties to whom the Software is furnished to
do so, all subject to the following:

The copyright notices in the Software and this entire statement, including
the above license grant, this restriction and the following disclaimer,
must be included in all copies of the Software, in whole or in part, and
all derivative works of the Software, unless such copies or derivative
works are solely in the form of machine-executable object code generated by
a source language processor.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

#ifndef BOOST_OUTCOME_POLICY_THROW_BAD_RESULT_ACCESS_HPP
#define BOOST_OUTCOME_POLICY_THROW_BAD_RESULT_ACCESS_HPP

#include "../bad_access.hpp"
#include "base.hpp"

BOOST_OUTCOME_V2_NAMESPACE_EXPORT_BEGIN

namespace policy
{
  /*! AWAITING HUGO JSON CONVERSION TOOL 
type definition  throw_bad_result_access. Potential doc page: NOT FOUND
*/
  template <class EC, class EP> struct throw_bad_result_access : base
  {
    template <class Impl> static constexpr void wide_value_check(Impl &&self)
    {
      if(!base::_has_value(std::forward<Impl>(self)))
      {
        BOOST_OUTCOME_THROW_EXCEPTION(bad_outcome_access("no value"));  // NOLINT
      }
    }
    template <class Impl> static constexpr void wide_error_check(Impl &&self)
    {
      if(!base::_has_error(std::forward<Impl>(self)))
      {
        BOOST_OUTCOME_THROW_EXCEPTION(bad_outcome_access("no error"));  // NOLINT
      }
    }
    template <class Impl> static constexpr void wide_exception_check(Impl &&self)
    {
      if(!base::_has_exception(std::forward<Impl>(self)))
      {
        BOOST_OUTCOME_THROW_EXCEPTION(bad_outcome_access("no exception"));  // NOLINT
      }
    }
  };
  template <class EC> struct throw_bad_result_access<EC, void> : base
  {
    template <class Impl> static constexpr void wide_value_check(Impl &&self)
    {
      if(!base::_has_value(std::forward<Impl>(self)))
      {
        if(base::_has_error(std::forward<Impl>(self)))
        {
          BOOST_OUTCOME_THROW_EXCEPTION(bad_result_access_with<EC>(base::_error(std::forward<Impl>(self))));
        }
        BOOST_OUTCOME_THROW_EXCEPTION(bad_result_access("no value"));  // NOLINT
      }
    }
    template <class Impl> static constexpr void wide_error_check(Impl &&self)
    {
      if(!base::_has_error(std::forward<Impl>(self)))
      {
        BOOST_OUTCOME_THROW_EXCEPTION(bad_result_access("no error"));  // NOLINT
      }
    }
  };
}  // namespace policy

BOOST_OUTCOME_V2_NAMESPACE_END

#endif

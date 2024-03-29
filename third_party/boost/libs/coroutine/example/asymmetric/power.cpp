
//          Copyright Oliver Kowalke 2009.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <boost/coroutine/all.hpp>

#include <cstdlib>
#include <iostream>

#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <boost/range.hpp>

void power( boost::coroutines::asymmetric_coroutine< int >::push_type & sink, int number, int exponent)
{
    int counter = 0;
    int result = 1;
    while ( counter++ < exponent)
    {
            result = result * number;
            sink( result);
    }
}

int main()
{
    {
        std::cout << "using range functions" << std::endl;
        boost::coroutines::asymmetric_coroutine< int >::pull_type source( boost::bind( power, _1, 2, 8) );
        boost::coroutines::asymmetric_coroutine< int >::pull_type::iterator e( boost::end( source) );
        for ( boost::coroutines::asymmetric_coroutine< int >::pull_type::iterator i( boost::begin( source) );
              i != e; ++i)
            std::cout << * i <<  " ";
    }

    {
        std::cout << "\nusing BOOST_FOREACH" << std::endl;
        boost::coroutines::asymmetric_coroutine< int >::pull_type source( boost::bind( power, _1, 2, 8) );
        BOOST_FOREACH( int i, source)
        { std::cout << i <<  " "; }
    }

    std::cout << "\nDone" << std::endl;

    return EXIT_SUCCESS;
}

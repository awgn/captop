/*
 *  Copyright (c) 2014 Nicola Bonelli <nicola@pfq.io>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#pragma once 

#include <string>
#include <vector>

struct range_filter
{
    range_filter(const char *filt)
    {
        auto xs = split_one_of(",", filt);        
        for(auto & x : xs) {
            auto r = split_one_of("-", x);
            ranges_.emplace_back(
                std::stoi(r[0]),
                std::stoi(r[r.size() == 1 ? 0 : 1]));
        }
    }

    bool operator()(size_t n) const
    {
        for(auto & r : ranges_)
            if (r.first <= n && r.second >= n)
                return true;
        return false;
    }

    bool empty() const
    {
        return ranges_.empty();
    }

private:


    static std::vector<std::string>
    split_one_of(const char *sep, std::string s)
    {
        std::vector<std::string> ret;
        size_t pos = 0;

        while ((pos = s.find_first_of(sep)) != std::string::npos)
        {
            auto token = s.substr(0, pos);
            if (!token.empty())
                ret.push_back(std::move(token));
            s = s.substr(pos + 1);
        }

        if (!s.empty())
            ret.push_back(std::move(s));

        return ret;
    }

    std::vector<std::pair<size_t,size_t>> ranges_;
};


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

namespace vt100
{
    namespace
    {
        const char * const CLEAR = "\E[2J";
        const char * const EDOWN = "\E[J";
        const char * const DOWN  = "\E[1B";
        const char * const HOME  = "\E[H";
        const char * const ELINE = "\E[K";
        const char * const BOLD  = "\E[1m";
        const char * const RESET = "\E[0m";
        const char * const BLUE  = "\E[1;34m";
        const char * const RED   = "\E[31m";
    }
}


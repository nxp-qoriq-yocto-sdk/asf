#/* Copyright (C) 2009-2010 Freescale Semiconductor, Inc. All Rights Reserved.
# *
# * File:	Makefile
# *
# * This program is free software; you can redistribute it and/or modify it
# * under the terms of the GNU General Public License as published by the
# * Free Software Foundation; either version 2 of the  License, or (at your
# * option) any later version.
# *
# * This program is distributed in the hope that it will be useful, but
# * WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * General Public License for more details.
# *
# * You should have received a copy of the  GNU General Public License along
# * with this program; if not, write  to the Free Software Foundation, Inc.,
# * 675 Mass Ave, Cambridge, MA 02139, USA.
# *
# */

#------------------------------------------------------------------------------
#  Include Definitions
#------------------------------------------------------------------------------
.PHONY: all
all: build

build:
	make -w -C asfcmn -f makefile
	make -w -C asfffp -f makefile
	make -w -C asffwd -f makefile
	make -w -C asfipsec -f makefile
	make -w -C asfctrl -f makefile

#--------------------------------------------------------------
.PHONY: clean
clean:
	make -w -C asfcmn -f makefile clean
	make -w -C asfffp -f makefile clean
	make -w -C asffwd -f makefile clean
	make -w -C asfipsec -f makefile clean
	make -w -C asfctrl -f makefile clean


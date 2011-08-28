#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+ruby@gmail.com
#
module Haystack
  def openProc(pid)
    mapsfile = "/proc/#{pid}/maps"
    lines = File.new(mapsfile,'r').readlines
    return lines
  end

end

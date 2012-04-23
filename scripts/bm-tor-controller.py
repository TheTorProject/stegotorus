#! /usr/bin/python
# Copyright 2012 Zachary Weinberg
#
# Copying and distribution of this file, with or without modification, are
# permitted in any medium without royalty provided the copyright notice
# and this notice are preserved. This file is offered as-is, without any
# warranty.

from torctl import TorCtl, TorUtil, PathSupport
import sys
import time

#i = PathSupport.IdHexRestriction

#nodes_entry = PathSupport.OrNodeRestriction([
#   i('$580075B70F4CBA0C6819819CC3CB7F4D5D06F0FD') # torEFF
#  i('$0CE3CFB1E9CC47B63EA8869813BF6FAB7D4540C1'), # amunet4
#  i('$E0BD57A11F00041A9789577C53A1B784473669E4'), # amunet3
#  i('$E5E3E9A472EAF7BE9682B86E92305DB4C71048EF') # amunet2
#])

#nodes_mid = PathSupport.OrNodeRestriction([
#   i('$204C0D7C6E1D06D7645B07F9BEAC9971DBD7E5EC') # ITM
#  i('$3D0FAFB36EB9FC9D1EFD68758E2B0025117D3D1B'), # hazare2
#  i('$6586CEE14353DD1E6FAF3F172A23B00119A67C57'), # saeed
#  i('$6F383C2629471E1AE7DA053D04625AAED69844CC')  # hazare
#])

#nodes_exit = PathSupport.OrNodeRestriction([
#   i('$13A742728E5E0FC7FE363A07799F0FAD276DED43') # Goodnet01
#  i('$3A415473854F9F082F16EECDFE436218FE1169EA'), # noiseexit01c
#  i('$9C98B38FE270546C69205E16047B8D46BBBB0447'), # noiseexit01d
#  i('$F97F3B153FED6604230CD497A3D1E9815B007636')  # noiseexit01a
#])

def ensure_nrl(x):
    if not isinstance(x, PathSupport.NodeRestrictionList):
        x = PathSupport.NodeRestrictionList([x])
    return x

class ThisSequenceUniformly(PathSupport.BaseSelectionManager):
    def __init__(self, restrictions):
        PathSupport.BaseSelectionManager.__init__(self)
        self.restrictions = [ ensure_nrl(x) for x in restrictions ]
        self.generators = None

    def reconfigure(self, consensus):
        if self.generators is not None:
            try:
                for g in self.generators:
                    g.rebuild(consensus.sorted_r)
            except PathSupport.NoNodesRemain:
                pass # have to make new generators

        self.generators = [
            PathSupport.ExactUniformGenerator(consensus.sorted_r, restr)
            for restr in self.restrictions
        ]

    def new_consensus(self, consensus):
        self.reconfigure(consensus)

    def select_path(self):
        if self.generators is None: raise PathSupport.NoNodesRemain
        path = []
        for g in self.generators:
            g.rewind()
            r = g.generate().next()
            r.refcount += 1
            path.append(r)
        return path

class ThisBridgeAndNothingElse(PathSupport.BaseSelectionManager):
    def __init__(self, bridge):
        self.bridge = bridge

    def select_path(self):
        self.bridge.refcount += 1
        return [self.bridge]

TorUtil.loglevel = "WARN"

c  = TorCtl.connect(ConnClass=PathSupport.Connection)
bs = c.get_network_status("purpose/bridge")
while len(bs) == 0:
    bs = c.get_network_status("purpose/bridge")

s  = ThisBridgeAndNothingElse(c.get_router(bs[0]))

h = PathSupport.PathBuilder(c, s)
c.set_event_handler(h)
c.set_events([TorCtl.EVENT_TYPE.STREAM,
              TorCtl.EVENT_TYPE.BW,
              TorCtl.EVENT_TYPE.NEWCONSENSUS,
              TorCtl.EVENT_TYPE.NEWDESC,
              TorCtl.EVENT_TYPE.CIRC,
              TorCtl.EVENT_TYPE.STREAM_BW], True)

while True: time.sleep(120)

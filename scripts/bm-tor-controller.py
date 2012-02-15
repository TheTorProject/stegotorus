#! /usr/bin/python

from torctl import TorCtl, TorUtil, PathSupport

import time

i = PathSupport.IdHexRestriction

# in San Francisco
amunet = PathSupport.OrNodeRestriction([
  i('$0CE3CFB1E9CC47B63EA8869813BF6FAB7D4540C1'), # amunet4
  i('$E0BD57A11F00041A9789577C53A1B784473669E4'), # amunet3
  i('$E5E3E9A472EAF7BE9682B86E92305DB4C71048EF') # amunet2
])

# probably in L.A.
hazare = PathSupport.OrNodeRestriction([
  i('$3D0FAFB36EB9FC9D1EFD68758E2B0025117D3D1B'), # hazare2
  i('$6586CEE14353DD1E6FAF3F172A23B00119A67C57'), # saeed
  i('$6F383C2629471E1AE7DA053D04625AAED69844CC')  # hazare
])

# very likely in L.A.
noisebr = PathSupport.OrNodeRestriction([
  i('$3A415473854F9F082F16EECDFE436218FE1169EA'), # noiseexit01c
  i('$9C98B38FE270546C69205E16047B8D46BBBB0447'), # noiseexit01d
  i('$F97F3B153FED6604230CD497A3D1E9815B007636')  # noiseexit01a
])

# I shouldn't have to do this
class TheseUniformly(PathSupport.BaseSelectionManager):
    def __init__(self, res_entry, res_mid, res_exit):
        PathSupport.BaseSelectionManager.__init__(self)
        if not isinstance(res_entry, PathSupport.NodeRestrictionList):
            res_entry = PathSupport.NodeRestrictionList([res_entry])
        if not isinstance(res_mid, PathSupport.NodeRestrictionList):
            res_mid = PathSupport.NodeRestrictionList([res_mid])
        if not isinstance(res_exit, PathSupport.NodeRestrictionList):
            res_exit = PathSupport.NodeRestrictionList([res_exit])
        self.res_entry = res_entry
        self.res_mid   = res_mid
        self.res_exit  = res_exit
        self.path_selector = None

    def reconfigure(self, consensus):
        if self.path_selector is not None:
            try:
                self.path_selector.rebuild_gens(consensus.sorted_r)
            except NoNodesRemain:
                pass

        self.path_selector = PathSupport.PathSelector(
            PathSupport.ExactUniformGenerator(consensus.sorted_r, self.res_entry),
            PathSupport.ExactUniformGenerator(consensus.sorted_r, self.res_mid),
            PathSupport.ExactUniformGenerator(consensus.sorted_r, self.res_exit),
            PathSupport.PathRestrictionList([PathSupport.UniqueRestriction()]))

    def new_consensus(self, consensus):
        self.reconfigure(consensus)

    def set_exit(self, exit_name):
        pass

    def set_target(self, host, port):
        pass

    def select_path(self):
        return self.path_selector.select_path(3)

TorUtil.loglevel = "WARN"

s = TheseUniformly(amunet, hazare, noisebr)
c = TorCtl.connect(ConnClass=PathSupport.Connection)
h = PathSupport.PathBuilder(c, s)
c.set_event_handler(h)
c.set_events([TorCtl.EVENT_TYPE.STREAM,
              TorCtl.EVENT_TYPE.BW,
              TorCtl.EVENT_TYPE.NEWCONSENSUS,
              TorCtl.EVENT_TYPE.NEWDESC,
              TorCtl.EVENT_TYPE.CIRC,
              TorCtl.EVENT_TYPE.STREAM_BW], True)

while True: time.sleep(120)

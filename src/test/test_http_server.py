#!/usr/bin/python2

from twisted.internet import reactor, endpoints
from twisted.web.server import Site
from twisted.web.resource import Resource
import time
import pdb

TEST_PAGE_BODY  = "This is a test page\n"

class TestPage(Resource):
    isLeaf = True
    def render_GET(self, request):
        if "content" in request.args and request.args["content"][0] == "tl_snark":
            #pdb.set_trace()
            with open("tl_snark") as test_file:
                data = test_file.read()
                resource = ""
                for i in range(0,1000):
                    resource +=data
                return resource
        elif "content" in request.args:
            return request.args["content"][0]
        else:
            return TEST_PAGE_BODY

def TestHttpServer(port):
        return reactor.listenTCP(port, Site(TestPage()))

if __name__ == "__main__":
    my_http_server = TestHttpServer(5001)
    reactor.run()
